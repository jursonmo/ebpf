package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go tool bpf2go -tags linux dnsmarkxdp bpf/dns_mark_xdp.c -- -I./bpf -I../headers

type Rule struct {
	CIDRs   []string `json:"cidrs"`
	Domains []string `json:"domains"`
}

type Config struct {
	Interface string `json:"interface"`
	Rules     []Rule `json:"rules"`
}

const (
	maxDomainLen = 64
	reloadAddr   = "127.0.0.1:18081"
)

type domainKey struct {
	Name [maxDomainLen]byte
}

type lpmKey struct {
	PrefixLen uint32
	IP        [4]byte
}

type cidrEntry struct {
	ipNet   *net.IPNet
	key     lpmKey
	bitmask uint64
}

func loadConfig(cfgPath string) (Config, error) {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return Config{}, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("解析配置文件失败: %w", err)
	}

	if strings.TrimSpace(cfg.Interface) == "" {
		return Config{}, errors.New("interface 不能为空")
	}
	if len(cfg.Rules) == 0 {
		return Config{}, errors.New("至少需要一条规则")
	}
	if len(cfg.Rules) > 64 {
		return Config{}, errors.New("最多支持 64 条规则（bitmask 限制）")
	}

	return cfg, nil
}

func clearDomainRulesMap(objs *dnsmarkxdpObjects) error {
	var (
		key  domainKey
		val  uint64
		keys []domainKey
	)
	iter := objs.DomainRules.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 domain_rules 失败: %w", err)
	}
	for _, k := range keys {
		if err := objs.DomainRules.Delete(k); err != nil {
			return fmt.Errorf("删除 domain_rules 旧规则失败: %w", err)
		}
	}
	return nil
}

func clearCidrRulesMap(objs *dnsmarkxdpObjects) error {
	var (
		key  lpmKey
		val  uint64
		keys []lpmKey
	)
	iter := objs.CidrRules.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 cidr_rules 失败: %w", err)
	}
	for _, k := range keys {
		if err := objs.CidrRules.Delete(k); err != nil {
			return fmt.Errorf("删除 cidr_rules 旧规则失败: %w", err)
		}
	}
	return nil
}

func rebuildRules(cfg Config, objs *dnsmarkxdpObjects) (map[string]uint64, []*cidrEntry, error) {
	if err := clearDomainRulesMap(objs); err != nil {
		return nil, nil, err
	}
	if err := clearCidrRulesMap(objs); err != nil {
		return nil, nil, err
	}

	domainBitmasks := make(map[string]uint64)
	for i, rule := range cfg.Rules {
		mask := uint64(1) << uint(i)
		for _, d := range rule.Domains {
			domainBitmasks[strings.ToLower(d)] |= mask
		}
	}

	for domain, mask := range domainBitmasks {
		var key domainKey
		copy(key.Name[:], domain)
		if err := objs.DomainRules.Update(key, mask, 0); err != nil {
			return nil, nil, fmt.Errorf("写入域名规则 %q 失败: %w", domain, err)
		}
	}

	cidrMap := make(map[string]*cidrEntry)
	for i, rule := range cfg.Rules {
		mask := uint64(1) << uint(i)
		for _, cidr := range rule.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, nil, fmt.Errorf("解析 CIDR %s 失败: %w", cidr, err)
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				return nil, nil, fmt.Errorf("仅支持 IPv4: %s", cidr)
			}
			prefixLen, _ := ipnet.Mask.Size()
			cidrStr := ipnet.String()

			if e, ok := cidrMap[cidrStr]; ok {
				e.bitmask |= mask
			} else {
				var k lpmKey
				k.PrefixLen = uint32(prefixLen)
				copy(k.IP[:], ip4)
				cidrMap[cidrStr] = &cidrEntry{ipNet: ipnet, key: k, bitmask: mask}
			}
		}
	}

	entries := make([]*cidrEntry, 0, len(cidrMap))
	for _, e := range cidrMap {
		entries = append(entries, e)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key.PrefixLen < entries[j].key.PrefixLen
	})

	// 把短前缀规则传播到被其包含的长前缀，避免最长匹配导致规则交集丢失。
	for i := range entries {
		for j := 0; j < i; j++ {
			if entries[j].ipNet.Contains(entries[i].ipNet.IP) {
				entries[i].bitmask |= entries[j].bitmask
			}
		}
	}

	for _, e := range entries {
		if err := objs.CidrRules.Update(e.key, e.bitmask, 0); err != nil {
			return nil, nil, fmt.Errorf("写入 CIDR 规则 %s 失败: %w", e.ipNet, err)
		}
	}

	return domainBitmasks, entries, nil
}

func attachXDPProgram(prog *ebpf.Program, ifaceIndex int) (link.Link, string, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex,
	})
	if err == nil {
		return l, "auto(driver/generic)", nil
	}

	l2, err2 := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceIndex,
		Flags:     link.XDPGenericMode,
	})
	if err2 != nil {
		return nil, "", fmt.Errorf("附加 XDP 失败(auto=%v, generic=%w)", err, err2)
	}
	return l2, "generic(skb)", nil
}

func main() {
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	var objs dnsmarkxdpObjects
	if err := loadDnsmarkxdpObjects(&objs, nil); err != nil {
		log.Fatalf("加载 BPF 对象失败: %v", err)
	}

	var (
		l           link.Link
		server      *http.Server
		currentCfg  = cfg
		reloadMu    sync.Mutex
		cleanupOnce sync.Once
	)

	cleanup := func(reason string) {
		cleanupOnce.Do(func() {
			fmt.Printf("正在卸载... (%s)\n", reason)
			if server != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				if err := server.Shutdown(ctx); err != nil {
					log.Printf("关闭 reload HTTP 服务失败: %v", err)
				}
				cancel()
			}
			if l != nil {
				if err := l.Close(); err != nil {
					log.Printf("卸载 XDP 程序失败: %v", err)
				} else {
					log.Printf("卸载 XDP 程序成功")
				}
			}
			if err := objs.Close(); err != nil {
				log.Printf("关闭 BPF 对象失败: %v", err)
			} else {
				log.Printf("关闭 BPF 对象成功")
			}
		})
	}
	defer cleanup("程序退出")

	domainBitmasks, entries, err := rebuildRules(currentCfg, &objs)
	if err != nil {
		log.Fatalf("初始化规则失败: %v", err)
	}

	ingressIface, err := net.InterfaceByName(currentCfg.Interface)
	if err != nil {
		log.Fatalf("查找入口网卡 %s 失败: %v", currentCfg.Interface, err)
	}

	l, mode, err := attachXDPProgram(objs.DnsMarkXdp, ingressIface.Index)
	if err != nil {
		log.Fatalf("挂载 XDP 失败: %v", err)
	}
	log.Printf("XDP 挂载成功: if=%s index=%d mode=%s", ingressIface.Name, ingressIface.Index, mode)
	log.Printf("出口由 bpf_fib_lookup 动态决策")

	mux := http.NewServeMux()
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		reloadMu.Lock()
		defer reloadMu.Unlock()

		newCfg, err := loadConfig(cfgPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("reload失败: %v", err), http.StatusBadRequest)
			return
		}

		if newCfg.Interface != currentCfg.Interface {
			http.Error(
				w,
				fmt.Sprintf("reload失败: interface 不允许动态变更，当前=%s 新配置=%s", currentCfg.Interface, newCfg.Interface),
				http.StatusBadRequest,
			)
			return
		}

		newDomainBitmasks, newEntries, err := rebuildRules(newCfg, &objs)
		if err != nil {
			http.Error(w, fmt.Sprintf("reload失败: %v", err), http.StatusInternalServerError)
			return
		}

		currentCfg = newCfg
		domainBitmasks = newDomainBitmasks
		entries = newEntries

		log.Printf(
			"reload成功: rules=%d domains=%d cidrs=%d (egress=fib_lookup)",
			len(currentCfg.Rules), len(domainBitmasks), len(entries),
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"rules":   len(currentCfg.Rules),
			"domains": len(domainBitmasks),
			"cidrs":   len(entries),
		})
	})

	server = &http.Server{
		Addr:    reloadAddr,
		Handler: mux,
	}
	go func() {
		log.Printf("reload接口已启动: curl -X POST http://%s/reload", reloadAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("reload HTTP 服务异常退出: %v", err)
		}
	}()

	fmt.Printf("dns_mark_xdp 已挂载到 %s (XDP)\n", currentCfg.Interface)
	fmt.Println("出口路径: 由 bpf_fib_lookup 动态路由")
	fmt.Printf("共 %d 条规则, %d 个域名, %d 个 CIDR\n", len(currentCfg.Rules), len(domainBitmasks), len(entries))
	for i, rule := range currentCfg.Rules {
		fmt.Printf("  规则 %d: CIDRs=%v  Domains=%v\n", i, rule.CIDRs, rule.Domains)
	}
	fmt.Println("匹配规则的 DNS 查询会按 FIB 结果改写源IP/MAC 并 XDP redirect，按 Ctrl-C 退出并卸载")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	cleanup(fmt.Sprintf("收到信号 %s", s))
}
