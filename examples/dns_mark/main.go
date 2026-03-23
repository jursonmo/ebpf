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
	"sync"
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
		filterAdded bool
		qdiscAdded  bool
		cleanupOnce sync.Once
	)
	cleanup := func(reason string) {
		cleanupOnce.Do(func() {
			fmt.Printf("正在卸载... (%s)\n", reason)
			if filterAdded && filter != nil {
				if err := netlink.FilterDel(filter); err != nil {
					log.Printf("删除 TC filter 失败: %v", err)
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
	} else {
		qdiscAdded = true
	}

	filter = &netlink.BpfFilter{
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
	filterAdded = true
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
	s := <-sig
	cleanup(fmt.Sprintf("收到信号 %s", s))
}
