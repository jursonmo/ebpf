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

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// //go:generate go tool bpf2go -tags linux dnsmark bpf/dns_mark.c -- -I./bpf -I../headers
// //go:generate go tool bpf2go -tags linux dnsmark bpf/dns_mark.c -- -I./bpf -I../headers -DVMLINUX_H
// Rule 每条规则包含多个 CIDR 和多个域名，匹配条件为：源IP命中任一CIDR 且 域名命中任一域名。

// 直接用bpf2go 命令生成，不需要go tool bpf2go 命令生成

//go:generate bpf2go -tags linux dnsmark bpf/dns_mark.c -- -I./bpf -I../headers
type Rule struct {
	CIDRs   []string `json:"cidrs"`
	Domains []string `json:"domains"`
}

type DomainMatchMode string

const (
	DomainMatchModeExact         DomainMatchMode = "exact"
	DomainMatchModeLongestSuffix DomainMatchMode = "longest_suffix"

	bpfDomainMatchExact uint32 = iota
	bpfDomainMatchLongestSuffix
)

type Config struct {
	Interface       string          `json:"interface"`
	DomainMatchMode DomainMatchMode `json:"domain_match_mode"`
	Rules           []Rule          `json:"rules"`
}

const maxDomainLen = 64

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

const reloadAddr = "127.0.0.1:18080"
const tcFilterName = "dns_mark"
const tcFilterHandle uint32 = 1

func deleteIngressBpfFilters(link netlink.Link, wantName string, wantHandle uint32) (int, error) {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return 0, err
	}

	deleted := 0
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		attrs := bpf.Attrs()
		matchName := wantName != "" && bpf.Name == wantName
		matchHandle := wantHandle != 0 && attrs.Handle == wantHandle
		if !matchName && !matchHandle {
			continue
		}
		if err := netlink.FilterDel(f); err != nil && !errors.Is(err, unix.ENOENT) {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
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
	if len(cfg.Rules) == 0 {
		return Config{}, errors.New("至少需要一条规则")
	}
	if len(cfg.Rules) > 64 {
		return Config{}, errors.New("最多支持 64 条规则（bitmask 限制）")
	}
	cfg.DomainMatchMode, err = normalizeDomainMatchMode(cfg.DomainMatchMode)
	if err != nil {
		return Config{}, err
	}
	for i := range cfg.Rules {
		for j, domain := range cfg.Rules[i].Domains {
			normalized, err := normalizeDomain(domain)
			if err != nil {
				return Config{}, fmt.Errorf("规则 %d 的域名非法: %w", i, err)
			}
			cfg.Rules[i].Domains[j] = normalized
		}
	}
	return cfg, nil
}

func normalizeDomainMatchMode(mode DomainMatchMode) (DomainMatchMode, error) {
	if mode == "" {
		return DomainMatchModeExact, nil
	}
	switch mode {
	case DomainMatchModeExact, DomainMatchModeLongestSuffix:
		return mode, nil
	default:
		return "", fmt.Errorf("不支持的 domain_match_mode=%q，可选值: %q, %q", mode, DomainMatchModeExact, DomainMatchModeLongestSuffix)
	}
}

func (m DomainMatchMode) bpfValue() uint32 {
	if m == DomainMatchModeLongestSuffix {
		return bpfDomainMatchLongestSuffix
	}
	return bpfDomainMatchExact
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", errors.New("域名不能为空")
	}
	if len(domain) >= maxDomainLen {
		return "", fmt.Errorf("域名 %q 过长，最大支持 %d 个字符", domain, maxDomainLen-1)
	}
	return domain, nil
}

func setLoadedDomainMatchMode(objs *dnsmarkObjects, mode DomainMatchMode) error {
	if objs.DomainMatchMode == nil {
		return errors.New("BPF 变量 domain_match_mode 不存在")
	}
	if err := objs.DomainMatchMode.Set(mode.bpfValue()); err != nil {
		return fmt.Errorf("写入 BPF 变量 domain_match_mode 失败: %w", err)
	}
	return nil
}

func clearDomainRulesMap(objs *dnsmarkObjects) error {
	var (
		key  dnsmarkDomainKey
		val  uint64
		keys []dnsmarkDomainKey
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

func clearCidrRulesMap(objs *dnsmarkObjects) error {
	var (
		key  dnsmarkLpmKey
		val  uint64
		keys []dnsmarkLpmKey
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

func rebuildRules(cfg Config, objs *dnsmarkObjects) (map[string]uint64, []*cidrEntry, error) {
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

	// 短前缀在前排序，将短前缀的 bitmask 传播到被包含的长前缀
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key.PrefixLen < entries[j].key.PrefixLen
	})

	//mo:因为正常的按照最长匹配的方式，长前缀匹配到后就跳出, 得到的mask只有一个bitmask, 如果这样去跟domin的mask对比，可能是匹配不对，但是可以匹配短前缀的网段的。
	//192.168.0.0/16-->baidu.com
	//192.168.1.0/24-->qq.com
	// src 192.168.1.100, dns query baidu.com, 业务上是应该匹配到的，如果单纯按最长匹配，找到第二条规则，第二条规则要求是qq.com才算匹配
	//这样就匹配不到了，所以需要把短前缀的bitmask传播到被包含的长前缀。第一条规则ipnet 包含了第二条规则ipnet
	// 所以第二条规则的mask 就是1<<1 | 1<<2 = 3, 然后更新到cidr_rules map中。
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

func main() {
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	// 1. 加载 BPF 程序
	spec, err := loadDnsmark()
	if err != nil {
		log.Fatalf("加载 BPF CollectionSpec 失败: %v", err)
	}
	if err := spec.Variables["domain_match_mode"].Set(cfg.DomainMatchMode.bpfValue()); err != nil {
		log.Fatalf("设置 domain_match_mode 失败: %v", err)
	}
	var objs dnsmarkObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("加载 BPF 对象失败: %v", err)
	}
	/*
		root@ubuntu:/home/mjw# bpftool map list
		   154: array  name .rodata  flags 0x480
		   	key 4B  value 171B  max_entries 1  memlock 4096B
		   	btf_id 321  frozen
		   155: hash  name domain_rules  flags 0x0
		   	key 64B  value 8B  max_entries 4096  memlock 294912B
		   	btf_id 322
		   156: lpm_trie  name cidr_rules  flags 0x1
		   	key 8B  value 8B  max_entries 1024  memlock 16384B
		   	btf_id 323

			//注意名称 domain_rules 和 cidr_rules, 跟bpf/dns_mark.c中的定义一致

		root@ubuntu:/home/mjw# bpftool prog list
			1194: sched_cls  name dns_mark  tag 1173f0d154792953  gpl
					loaded_at 2026-03-20T11:25:02+0000  uid 0
					xlated 1896B  jited 1218B  memlock 4096B  map_ids 160,161,162
					btf_id 331

		//注意 dns_mark 名称, 跟bpf/dns_mark.c中的定义一致,  并且可以看到关联的map_ids 160,161,162

	*/
	var (
		filter      *netlink.BpfFilter
		qdisc       *netlink.GenericQdisc
		lnk         netlink.Link
		server      *http.Server
		filterAdded bool
		qdiscAdded  bool
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
				} else {
					log.Printf("关闭 reload HTTP 服务成功\n")
				}
				cancel()
			}
			if filterAdded && filter != nil {
				if err := netlink.FilterDel(filter); err != nil {
					//莫：每次都失败，打印删除 TC filter 失败: no such file or directory, 所以增加下面这个兜底删除操作。
					// Some kernels/drivers don't find the object with the original
					// create attrs on delete; fall back to listing ingress filters.
					if errors.Is(err, unix.ENOENT) && lnk != nil {
						n, listErr := deleteIngressBpfFilters(lnk, filter.Name, filter.Attrs().Handle)
						if listErr != nil {
							log.Printf("删除 TC filter 失败(兜底删除也失败): %v (fallback: %v)", err, listErr)
						} else if n > 0 {
							log.Printf("删除 TC filter 成功(通过兜底扫描删除 %d 条)\n", n)
						} else {
							log.Printf("删除 TC filter: 未找到匹配项，可能已被提前删除")
						}
					} else {
						log.Printf("删除 TC filter 失败: %v", err)
					}
				} else {
					log.Printf("删除 TC filter 成功\n")
				}
			}
			if qdiscAdded && qdisc != nil {
				if err := netlink.QdiscDel(qdisc); err != nil {
					log.Printf("删除 clsact qdisc 失败: %v", err)
				} else {
					log.Printf("删除 clsact qdisc 成功\n")
				}
			}
			if err := objs.Close(); err != nil {
				log.Printf("关闭 BPF 对象失败: %v", err)
			} else {
				log.Printf("关闭 BPF 对象成功\n")
			}
		})
	}
	defer cleanup("程序退出")

	// 2. 初始化并填充 map
	domainBitmasks, entries, err := rebuildRules(cfg, &objs)
	if err != nil {
		log.Fatalf("初始化规则失败: %v", err)
	}

	// 4. 挂载到 TC ingress
	lnk, err = netlink.LinkByName(cfg.Interface)
	if err != nil {
		log.Fatalf("找不到网卡 %s: %v", cfg.Interface, err)
	}

	if n, delErr := deleteIngressBpfFilters(lnk, tcFilterName, tcFilterHandle); delErr != nil {
		log.Printf("启动预清理 ingress filter 失败(忽略继续): %v", delErr)
	} else if n > 0 {
		log.Printf("启动预清理: 删除历史 ingress filter %d 条", n)
	}

	qdisc = &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: lnk.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		// 兼容接口上已存在 clsact 的场景
		if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
			log.Fatalf("创建 clsact qdisc 失败: %v", err)
		}
		//log.Fatalf("创建 clsact qdisc 失败: %v", err)
	} else {
		qdiscAdded = true
	}

	filter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: lnk.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    tcFilterHandle,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.DnsMark.FD(),
		Name:         tcFilterName,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		if errors.Is(err, unix.EEXIST) || strings.Contains(strings.ToLower(err.Error()), "file exists") {
			n, delErr := deleteIngressBpfFilters(lnk, filter.Name, filter.Attrs().Handle)
			if delErr != nil {
				log.Fatalf("挂载 TC filter 失败(已存在，且删除旧filter失败): %v", delErr)
			}
			if n == 0 {
				log.Fatalf("挂载 TC filter 失败: 已存在且未找到可删除的历史 filter")
			}
			if err = netlink.FilterAdd(filter); err != nil {
				log.Fatalf("挂载 TC filter 失败(重试后): %v", err)
			}
			log.Printf("挂载前发现同名旧 filter，已删除并重试成功")
		} else {
			log.Fatalf("挂载 TC filter 失败: %v", err)
		}
	}
	filterAdded = true

	// 5. 启动 reload HTTP 接口
	currentIface := cfg.Interface
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
		if newCfg.Interface != currentIface {
			http.Error(
				w,
				fmt.Sprintf("reload失败: interface 不允许动态变更，当前=%s 新配置=%s", currentIface, newCfg.Interface),
				http.StatusBadRequest,
			)
			//TODO: 删除旧的tc filter 和qdisc，重新创建新的tc filter 和qdisc，重新挂载bpf程序。
			return
		}

		newDomainBitmasks, newEntries, err := rebuildRules(newCfg, &objs)
		if err != nil {
			http.Error(w, fmt.Sprintf("reload失败: %v", err), http.StatusInternalServerError)
			return
		}
		if newCfg.DomainMatchMode != cfg.DomainMatchMode {
			if err := setLoadedDomainMatchMode(&objs, newCfg.DomainMatchMode); err != nil {
				http.Error(w, fmt.Sprintf("reload失败: %v", err), http.StatusInternalServerError)
				return
			}
		}

		cfg = newCfg
		domainBitmasks = newDomainBitmasks
		entries = newEntries
		log.Printf("reload成功: 匹配模式=%s 规则=%d 域名=%d CIDR=%d", cfg.DomainMatchMode, len(cfg.Rules), len(domainBitmasks), len(entries))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"domain_match_mode": cfg.DomainMatchMode,
			"rules":             len(cfg.Rules),
			"domains":           len(domainBitmasks),
			"cidrs":             len(entries),
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
	//tc qdisc show dev ens2 clsact 查看 clsact qdisc 是否创建成功
	// tc qdisc del dev ens2 clsact 删除 clsact qdisc 这个能删除tc filter ingress以及的prog 和map
	//tc filter show dev ens2 ingress 查看 ingress filter 是否创建成功
	//tc filter del dev ens2 ingress 删除 ingress filter,  这个能删除对应的prog 和map
	/*
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# tc qdisc show dev ens2 clsact
			qdisc clsact ffff: parent ffff:fff1
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# tc filter show dev ens2 ingress
			filter protocol all pref 49152 bpf chain 0
			filter protocol all pref 49152 bpf chain 0 handle 0x1 dns_mark direct-action not_in_hw id 1208 tag b3454a0d871e8b3a jited

		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# bpftool prog show | grep -B 5 "map_ids.*173"
					1143: cgroup_skb  tag 6deef7357e7b4530  gpl
					   	loaded_at 2026-03-18T06:03:37+0000  uid 0
					   	xlated 64B  jited 58B  memlock 4096B
					1201: sched_cls  name dns_mark  tag b3454a0d871e8b3a  gpl
					   	loaded_at 2026-03-21T15:40:11+0000  uid 0
					   	xlated 1952B  jited 1249B  memlock 4096B  map_ids 172,173,174
				//注意 map_ids 172,173,174, 是被该prog引用的。
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# bpftool map list
				172: array  name .rodata  flags 0x480
					key 4B  value 332B  max_entries 1  memlock 4096B
					btf_id 342  frozen
				173: hash  name domain_rules  flags 0x0
					key 64B  value 8B  max_entries 4096  memlock 294912B
					btf_id 343
				174: lpm_trie  name cidr_rules  flags 0x1
					key 8B  value 8B  max_entries 1024  memlock 16384B
					btf_id 344

		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark#
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# tc filter del dev ens2 ingress
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark#
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# bpftool prog show | grep -B 5 "map_ids.*173"
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark#
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark# bpftool map list
		root@ubuntu2204:/home/mjw/ebpf/examples/dns_mark#
	*/
	// 6. 打印摘要
	fmt.Printf("dns_mark 已挂载到 %s (ingress)\n", cfg.Interface)
	fmt.Printf("域名匹配模式: %s\n", cfg.DomainMatchMode)
	fmt.Printf("共 %d 条规则, %d 个域名, %d 个 CIDR\n",
		len(cfg.Rules), len(domainBitmasks), len(entries))
	for i, rule := range cfg.Rules {
		fmt.Printf("  规则 %d: CIDRs=%v  Domains=%v\n", i, rule.CIDRs, rule.Domains)
	}
	fmt.Println("匹配的 DNS 请求将被打上 mark 54, 按 Ctrl-C 退出并卸载")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	cleanup(fmt.Sprintf("收到信号 %s", s))
}
