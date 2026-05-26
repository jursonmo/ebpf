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
	"strconv"
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
// 使用 -fno-builtin-memcpy 可以避免编译时把for循环优化成memcpy指令
//
// 内核5.17以上，使用bpf_loop 辅助函数，避免编译后程序体积过大，加载失败。
// //go:generate bpf2go -tags linux dnsmark bpf/dns_mark_bpf_loop.c -- -I./bpf -I../headers
//
//go:generate bpf2go -tags linux dnsmark bpf/dns_mark.c -- -I./bpf -I../headers
type Rule struct {
	CIDRs   []string `json:"cidrs"`
	Domains []string `json:"domains"`
}

type DomainMatchMode string

const (
	DomainMatchModeExact         DomainMatchMode = "exact"
	DomainMatchModeLongestSuffix DomainMatchMode = "longest_suffix"

	// bpfDomainMatchExact = iota
	// bpfDomainMatchLongestSuffix
	// 上面这段代码有bug，bpfDomainMatchLongestSuffix会变成3, 所以不能这样写
)

const (
	bpfDomainMatchExact         uint32 = 0
	bpfDomainMatchLongestSuffix uint32 = 1
)

type Config struct {
	Interfaces      []string        `json:"interfaces"`
	DomainMatchMode DomainMatchMode `json:"domain_match_mode"`
	Debug           bool            `json:"debug"`
	Rules           []Rule          `json:"rules"`
}

type debugRequest struct {
	Debug   *bool `json:"debug"`
	Enabled *bool `json:"enabled"`
}

const maxDomainLen = 64

type domainKey struct {
	Name [maxDomainLen]byte
}

type domainLpmKey struct {
	PrefixLen uint32
	Name      [maxDomainLen]byte
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

type tcAttachment struct {
	iface       string
	lnk         netlink.Link
	filter      *netlink.BpfFilter
	qdisc       *netlink.GenericQdisc
	filterAdded bool
	qdiscAdded  bool
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

func normalizeInterfaces(interfaceNames []string) ([]string, error) {
	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(interfaceNames))
	add := func(name string) error {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		if _, ok := seen[name]; ok {
			return nil
		}
		if strings.ContainsAny(name, "/\x00") {
			return fmt.Errorf("网卡名非法: %q", name)
		}
		seen[name] = struct{}{}
		normalized = append(normalized, name)
		return nil
	}

	for _, name := range interfaceNames {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	if len(normalized) == 0 {
		return nil, errors.New("至少需要配置一个 interfaces")
	}
	return normalized, nil
}

func sameInterfaces(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, name := range a {
		seen[name] = struct{}{}
	}
	for _, name := range b {
		if _, ok := seen[name]; !ok {
			return false
		}
	}
	return true
}

func attachTCIngress(iface string, progFD int) (*tcAttachment, error) {
	lnk, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("找不到网卡 %s: %w", iface, err)
	}

	if n, delErr := deleteIngressBpfFilters(lnk, tcFilterName, tcFilterHandle); delErr != nil {
		log.Printf("启动预清理 %s ingress filter 失败(忽略继续): %v", iface, delErr)
	} else if n > 0 {
		log.Printf("启动预清理 %s: 删除历史 ingress filter %d 条", iface, n)
	}

	attachment := &tcAttachment{iface: iface, lnk: lnk}
	attachment.qdisc = &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: lnk.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscAdd(attachment.qdisc); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
			return nil, fmt.Errorf("创建 %s clsact qdisc 失败: %w", iface, err)
		}
	} else {
		attachment.qdiscAdded = true
	}

	attachment.filter = &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: lnk.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    tcFilterHandle,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           progFD,
		Name:         tcFilterName,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(attachment.filter); err != nil {
		if errors.Is(err, unix.EEXIST) || strings.Contains(strings.ToLower(err.Error()), "file exists") {
			n, delErr := deleteIngressBpfFilters(lnk, attachment.filter.Name, attachment.filter.Attrs().Handle)
			if delErr != nil {
				detachTCIngress(attachment)
				return nil, fmt.Errorf("挂载 %s TC filter 失败(已存在，且删除旧filter失败): %w", iface, delErr)
			}
			if n == 0 {
				detachTCIngress(attachment)
				return nil, fmt.Errorf("挂载 %s TC filter 失败: 已存在且未找到可删除的历史 filter", iface)
			}
			if err = netlink.FilterAdd(attachment.filter); err != nil {
				detachTCIngress(attachment)
				return nil, fmt.Errorf("挂载 %s TC filter 失败(重试后): %w", iface, err)
			}
			log.Printf("挂载 %s 前发现同名旧 filter，已删除并重试成功", iface)
		} else {
			detachTCIngress(attachment)
			return nil, fmt.Errorf("挂载 %s TC filter 失败: %w", iface, err)
		}
	}
	attachment.filterAdded = true
	return attachment, nil
}

func detachTCIngress(attachment *tcAttachment) {
	if attachment == nil {
		return
	}
	if attachment.filterAdded && attachment.filter != nil {
		if err := netlink.FilterDel(attachment.filter); err != nil {
			// 莫：每次都失败，打印删除 TC filter 失败: no such file or directory, 所以增加下面这个兜底删除操作。
			// Some kernels/drivers don't find the object with the original
			// create attrs on delete; fall back to listing ingress filters.
			if errors.Is(err, unix.ENOENT) && attachment.lnk != nil {
				n, listErr := deleteIngressBpfFilters(attachment.lnk, attachment.filter.Name, attachment.filter.Attrs().Handle)
				if listErr != nil {
					log.Printf("删除 %s TC filter 失败(兜底删除也失败): %v (fallback: %v)", attachment.iface, err, listErr)
				} else if n > 0 {
					log.Printf("删除 %s TC filter 成功(通过兜底扫描删除 %d 条)\n", attachment.iface, n)
				} else {
					log.Printf("删除 %s TC filter: 未找到匹配项，可能已被提前删除", attachment.iface)
				}
			} else {
				log.Printf("删除 %s TC filter 失败: %v", attachment.iface, err)
			}
		} else {
			log.Printf("删除 %s TC filter 成功\n", attachment.iface)
		}
	}
	if attachment.qdiscAdded && attachment.qdisc != nil {
		if err := netlink.QdiscDel(attachment.qdisc); err != nil {
			log.Printf("删除 %s clsact qdisc 失败: %v", attachment.iface, err)
		} else {
			log.Printf("删除 %s clsact qdisc 成功\n", attachment.iface)
		}
	}
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
	cfg.Interfaces, err = normalizeInterfaces(cfg.Interfaces)
	if err != nil {
		return Config{}, err
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
	switch mode {
	case DomainMatchModeExact, DomainMatchModeLongestSuffix:
		return mode, nil
	default:
		return DomainMatchModeLongestSuffix, nil // 默认使用最长后缀匹配模式.
		//return "", fmt.Errorf("不支持的 domain_match_mode=%q，可选值: %q, %q", mode, DomainMatchModeExact, DomainMatchModeLongestSuffix)
	}
}

func (m DomainMatchMode) bpfValue() uint32 {
	if m == DomainMatchModeLongestSuffix {
		return bpfDomainMatchLongestSuffix
	}
	return bpfDomainMatchExact
}

func bpfDebugValue(enabled bool) uint32 {
	if enabled {
		return 1
	}
	return 0
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

func setLoadedDebugMode(objs *dnsmarkObjects, enabled bool) error {
	if objs.DebugConfig == nil {
		return errors.New("BPF map debug_config 不存在")
	}
	key := uint32(0)
	value := bpfDebugValue(enabled)
	if err := objs.DebugConfig.Update(key, value, 0); err != nil {
		return fmt.Errorf("写入 BPF debug_config 失败: %w", err)
	}
	return nil
}

func parseDebugEnabled(r *http.Request) (bool, error) {
	raw := r.URL.Query().Get("debug")
	if raw == "" {
		raw = r.URL.Query().Get("enabled")
	}
	if raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return false, fmt.Errorf("debug 参数必须是 true 或 false")
		}
		return enabled, nil
	}

	var req debugRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return false, fmt.Errorf("请求体需要是 JSON，例如 {\"debug\":true}: %w", err)
	}
	if req.Debug != nil {
		return *req.Debug, nil
	}
	if req.Enabled != nil {
		return *req.Enabled, nil
	}
	return false, errors.New("请求体缺少 debug 或 enabled 字段")
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

func clearDomainSuffixRulesMap(objs *dnsmarkObjects) error {
	var (
		key  dnsmarkDomainLpmKey
		val  uint64
		keys []dnsmarkDomainLpmKey
	)
	iter := objs.DomainSuffixRules.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("遍历 domain_suffix_rules 失败: %w", err)
	}
	for _, k := range keys {
		if err := objs.DomainSuffixRules.Delete(k); err != nil {
			return fmt.Errorf("删除 domain_suffix_rules 旧规则失败: %w", err)
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

func reverseDomainForSuffixMatch(domain string) string {
	buf := []byte(domain)
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	buf = append(buf, '.')
	return string(buf)
}

func domainSuffixLookupKey(domain string) domainLpmKey {
	reversedDomain := reverseDomainForSuffixMatch(domain)
	var key domainLpmKey
	key.PrefixLen = maxDomainLen * 8
	copy(key.Name[:], reversedDomain)
	return key
}

func checkDomainSuffixRules(cfg Config, objs *dnsmarkObjects) {
	if cfg.DomainMatchMode != DomainMatchModeLongestSuffix {
		return
	}

	for _, rule := range cfg.Rules {
		for _, domain := range rule.Domains {
			tests := []string{domain}
			if !strings.HasPrefix(domain, "www.") {
				tests = append(tests, "www."+domain)
			}

			for _, testDomain := range tests {
				key := domainSuffixLookupKey(testDomain)
				var mask uint64
				if err := objs.DomainSuffixRules.Lookup(key, &mask); err != nil {
					log.Printf("domain_suffix_rules 自检失败: query=%q reversed=%q prefixlen=%d err=%v",
						testDomain, reverseDomainForSuffixMatch(testDomain), key.PrefixLen, err)
					continue
				}
				log.Printf("domain_suffix_rules 自检命中: query=%q reversed=%q prefixlen=%d mask=%d",
					testDomain, reverseDomainForSuffixMatch(testDomain), key.PrefixLen, mask)
			}
		}
	}
}

func rebuildRules(cfg Config, objs *dnsmarkObjects) (map[string]uint64, []*cidrEntry, error) {
	if err := clearDomainRulesMap(objs); err != nil {
		return nil, nil, err
	}
	if err := clearDomainSuffixRulesMap(objs); err != nil {
		return nil, nil, err
	}
	if err := clearCidrRulesMap(objs); err != nil {
		return nil, nil, err
	}

	domainBitmasks := make(map[string]uint64)
	suffixBitmasks := make(map[string]uint64)
	for i, rule := range cfg.Rules {
		mask := uint64(1) << uint(i)
		for _, d := range rule.Domains {
			normalized := strings.ToLower(d)
			domainBitmasks[normalized] |= mask
			suffixBitmasks[reverseDomainForSuffixMatch(normalized)] |= mask
		}
	}
	for domain, mask := range domainBitmasks {
		var key domainKey
		copy(key.Name[:], domain)
		if err := objs.DomainRules.Update(key, mask, 0); err != nil {
			return nil, nil, fmt.Errorf("写入域名规则 %q 失败: %w", domain, err)
		}
	}
	for reversedDomain, mask := range suffixBitmasks {
		var key domainLpmKey
		key.PrefixLen = uint32(len(reversedDomain) * 8)
		copy(key.Name[:], reversedDomain)
		if err := objs.DomainSuffixRules.Update(key, mask, 0); err != nil {
			return nil, nil, fmt.Errorf("写入域名后缀规则 %q 失败: %w", reversedDomain, err)
		}
		log.Printf("写入域名后缀规则: reversed=%q prefixlen=%d mask=%d", reversedDomain, key.PrefixLen, mask)
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
	if err := setLoadedDebugMode(&objs, cfg.Debug); err != nil {
		log.Fatalf("设置 debug_config 失败: %v", err)
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
		attachments []*tcAttachment
		server      *http.Server
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
			for i := len(attachments) - 1; i >= 0; i-- {
				detachTCIngress(attachments[i])
			}
			if err := objs.Close(); err != nil {
				log.Printf("关闭 BPF 对象失败: %v", err)
			} else {
				log.Printf("关闭 BPF 对象成功\n")
			}
		})
	}
	//defer cleanup("程序退出")

	// 2. 初始化并填充 map
	domainBitmasks, entries, err := rebuildRules(cfg, &objs)
	if err != nil {
		log.Fatalf("初始化规则失败: %v", err)
	}
	checkDomainSuffixRules(cfg, &objs)

	// 4. 挂载到 TC ingress
	for _, iface := range cfg.Interfaces {
		attachment, err := attachTCIngress(iface, objs.DnsMark.FD())
		if err != nil {
			cleanup("挂载失败")
			log.Fatal(err)
		}
		attachments = append(attachments, attachment)
	}

	// 5. 启动 reload HTTP 接口
	currentInterfaces := append([]string(nil), cfg.Interfaces...)
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
		if !sameInterfaces(newCfg.Interfaces, currentInterfaces) {
			http.Error(
				w,
				fmt.Sprintf("reload失败: interfaces 不允许动态变更，当前=%v 新配置=%v", currentInterfaces, newCfg.Interfaces),
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
		checkDomainSuffixRules(newCfg, &objs)
		if newCfg.DomainMatchMode != cfg.DomainMatchMode {
			if err := setLoadedDomainMatchMode(&objs, newCfg.DomainMatchMode); err != nil {
				http.Error(w, fmt.Sprintf("reload失败: %v", err), http.StatusInternalServerError)
				return
			}
		}
		if newCfg.Debug != cfg.Debug {
			if err := setLoadedDebugMode(&objs, newCfg.Debug); err != nil {
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
			"interfaces":        cfg.Interfaces,
			"domain_match_mode": cfg.DomainMatchMode,
			"debug":             cfg.Debug,
			"rules":             len(cfg.Rules),
			"domains":           len(domainBitmasks),
			"cidrs":             len(entries),
		})
	})
	mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			reloadMu.Lock()
			debug := cfg.Debug
			reloadMu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    true,
				"debug": debug,
			})
		case http.MethodPost:
			enabled, err := parseDebugEnabled(r)
			if err != nil {
				http.Error(w, fmt.Sprintf("debug设置失败: %v", err), http.StatusBadRequest)
				return
			}

			reloadMu.Lock()
			defer reloadMu.Unlock()

			if err := setLoadedDebugMode(&objs, enabled); err != nil {
				http.Error(w, fmt.Sprintf("debug设置失败: %v", err), http.StatusInternalServerError)
				return
			}
			cfg.Debug = enabled
			log.Printf("debug日志已设置为: %v", cfg.Debug)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    true,
				"debug": cfg.Debug,
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	server = &http.Server{
		Addr:    reloadAddr,
		Handler: mux,
	}
	go func() {
		log.Printf("reload接口已启动: curl -X POST http://%s/reload", reloadAddr)
		log.Printf("debug接口: curl http://%s/debug 或 curl -X POST 'http://%s/debug?debug=true'", reloadAddr, reloadAddr)
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
	fmt.Printf("dns_mark 已挂载到 %s (ingress)\n", strings.Join(cfg.Interfaces, ", "))
	fmt.Printf("域名匹配模式: %s\n", cfg.DomainMatchMode)
	fmt.Printf("debug日志: %v\n", cfg.Debug)
	fmt.Printf("共 %d 条规则, %d 个域名, %d 个 CIDR\n",
		len(cfg.Rules), len(domainBitmasks), len(entries))
	for i, rule := range cfg.Rules {
		fmt.Printf("  规则 %d: CIDRs=%v  Domains=%v\n", i, rule.CIDRs, rule.Domains)
	}
	fmt.Println("匹配的 DNS 请求将被打上 mark 54, 按 Ctrl-C 退出并卸载")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Println("收到信号:", s)
	cleanup(fmt.Sprintf("收到信号 %s", s))
	os.Exit(0)
}
