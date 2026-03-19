package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go tool bpf2go -tags linux dnsmark bpf/dns_mark.c -- -I./bpf -I../headers 
////go:generate go tool bpf2go -tags linux dnsmark bpf/dns_mark.c -- -I./bpf -I../headers -DVMLINUX_H

// Rule 每条规则包含多个 CIDR 和多个域名，匹配条件为：源IP命中任一CIDR 且 域名命中任一域名。
type Rule struct {
	CIDRs   []string `json:"cidrs"`
	Domains []string `json:"domains"`
}

type Config struct {
	Interface string `json:"interface"`
	Rules     []Rule `json:"rules"`
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

func main() {
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}

	if len(cfg.Rules) == 0 {
		log.Fatal("至少需要一条规则")
	}
	if len(cfg.Rules) > 64 {
		log.Fatal("最多支持 64 条规则（bitmask 限制）")
	}

	// 1. 加载 BPF 程序
	var objs dnsmarkObjects
	if err := loadDnsmarkObjects(&objs, nil); err != nil {
		log.Fatalf("加载 BPF 对象失败: %v", err)
	}
	defer objs.Close()

	// 2. 填充 domain_rules map
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
			log.Fatalf("写入域名规则 %q 失败: %v", domain, err)
		}
	}

	// 3. 收集 CIDR 条目，处理前缀重叠
	cidrMap := make(map[string]*cidrEntry)
	for i, rule := range cfg.Rules {
		mask := uint64(1) << uint(i)
		for _, cidr := range rule.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Fatalf("解析 CIDR %s 失败: %v", cidr, err)
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				log.Fatalf("仅支持 IPv4: %s", cidr)
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
	for i := range entries {
		for j := 0; j < i; j++ {
			if entries[j].ipNet.Contains(entries[i].ipNet.IP) {
				entries[i].bitmask |= entries[j].bitmask
			}
		}
	}

	for _, e := range entries {
		if err := objs.CidrRules.Update(e.key, e.bitmask, 0); err != nil {
			log.Fatalf("写入 CIDR 规则 %s 失败: %v", e.ipNet, err)
		}
	}

	// 4. 挂载到 TC ingress
	lnk, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		log.Fatalf("找不到网卡 %s: %v", cfg.Interface, err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: lnk.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(qdisc)

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: lnk.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.DnsMark.FD(),
		Name:         "dns_mark",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("挂载 TC filter 失败: %v", err)
	}
	defer netlink.FilterDel(filter)

	// 5. 打印摘要
	fmt.Printf("dns_mark 已挂载到 %s (ingress)\n", cfg.Interface)
	fmt.Printf("共 %d 条规则, %d 个域名, %d 个 CIDR\n",
		len(cfg.Rules), len(domainBitmasks), len(entries))
	for i, rule := range cfg.Rules {
		fmt.Printf("  规则 %d: CIDRs=%v  Domains=%v\n", i, rule.CIDRs, rule.Domains)
	}
	fmt.Println("匹配的 DNS 请求将被打上 mark 53, 按 Ctrl-C 退出并卸载")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("正在卸载...")
}
