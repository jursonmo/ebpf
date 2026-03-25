//go:build ignore

#include "dns_mark_xdp.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct domain_key);
	__type(value, __u64);
} domain_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u64);
} cidr_rules SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static __always_inline __u16 ipv4_hdr_csum(struct iphdr *ip)
{
	ip->check = 0;
	__u32 csum = 0;
	__u16 *next = (__u16 *)ip;

#pragma unroll
	for (int i = 0; i < (int)(sizeof(struct iphdr) >> 1); i++)
		csum += *next++;

	return csum_fold_helper(csum);
}

static __always_inline int update_l4_csum_ipv4_saddr(struct iphdr *ip, void *data_end,
						      __be32 old_saddr, __be32 new_saddr)
{
	if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void *)((char *)ip + sizeof(struct iphdr));
		if ((void *)(udp + 1) > data_end)
			return -1;

		/* IPv4 UDP checksum can be 0, which means "no checksum". */
		if (udp->check == 0)
			return 0;

		__u32 csum = (__u32)~udp->check;
		csum = bpf_csum_diff(&old_saddr, sizeof(old_saddr), &new_saddr, sizeof(new_saddr), csum);
		udp->check = csum_fold_helper(csum);
		if (udp->check == 0)
			udp->check = (__sum16)0xffff;
		return 0;
	}

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)((char *)ip + sizeof(struct iphdr));
		if ((void *)(tcp + 1) > data_end)
			return -1;

		__u32 csum = (__u32)~tcp->check;
		csum = bpf_csum_diff(&old_saddr, sizeof(old_saddr), &new_saddr, sizeof(new_saddr), csum);
		tcp->check = csum_fold_helper(csum);
		return 0;
	}

	return 0;
}

SEC("xdp")
int dns_mark_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	__u32 ip_hlen = ip->ihl << 2;
	if (ip_hlen != sizeof(struct iphdr))
		return XDP_PASS;

	struct udphdr *udp = (void *)((char *)ip + ip_hlen);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(DNS_PORT))
		return XDP_PASS;

	struct dnshdr *dns = (void *)(udp + 1);
	if ((void *)(dns + 1) > data_end)
		return XDP_PASS;
	if (bpf_ntohs(dns->flags) & 0x8000)
		return XDP_PASS;
	if (bpf_ntohs(dns->qdcount) < 1)
		return XDP_PASS;

	__u8 *name = (void *)(dns + 1);
	if ((void *)(name + 1) > data_end)
		return XDP_PASS;

	//bpf_printk("dns_mark_xdp: name = %p\n", name);
	struct domain_key dkey = {};
	__u32 out_pos = 0;
	__u8 label_rem = 0;
	__u8 ended = 0;
	__u8 seen_label = 0;

	for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
		__u8 *p = name + i;
		if ((void *)(p + 1) > data_end)
			return XDP_PASS;

		__u8 b = *p;
		if (label_rem == 0) {
			if (b == 0) {
				ended = 1;
				break;
			}
			/* Reject DNS compression pointers and invalid label length. */
			if ((b & 0xC0) || b > 63)
				return XDP_PASS;
			if (seen_label) {
				if (out_pos >= MAX_DOMAIN_LEN - 1)
					return XDP_PASS;
				dkey.name[out_pos++] = '.';
			}
			label_rem = b;
			seen_label = 1;
			continue;
		}

		if (out_pos >= MAX_DOMAIN_LEN - 1)
			return XDP_PASS;
		if (b >= 'A' && b <= 'Z')
			b += ('a' - 'A');
		dkey.name[out_pos++] = b;
		label_rem--;
	}

	if (!ended || !seen_label || label_rem != 0 || out_pos == 0)
		return XDP_PASS;

	bpf_printk("dns_mark_xdp: dkey = %s\n", dkey.name);
	__u64 *dmask = bpf_map_lookup_elem(&domain_rules, &dkey);
	if (!dmask || *dmask == 0)
	{
		bpf_printk("domain_rules miss: \n");
		return XDP_PASS;
	}

	struct lpm_key lpm = {
		.prefixlen = 32,
	};
	__builtin_memcpy(lpm.ip, &ip->saddr, sizeof(lpm.ip));

	__u64 *cmask = bpf_map_lookup_elem(&cidr_rules, &lpm);
	if (!cmask)
		return XDP_PASS;

	if ((*dmask & *cmask) == 0)
		return XDP_PASS;

	struct bpf_fib_lookup fib_params = {};
	fib_params.family = AF_INET;
	fib_params.ifindex = ctx->ingress_ifindex;
	fib_params.tos = ip->tos;
	fib_params.l4_protocol = ip->protocol;
	fib_params.tot_len = bpf_ntohs(ip->tot_len);
	fib_params.ipv4_src = ip->saddr;
	fib_params.ipv4_dst = ip->daddr;

	bpf_printk("before route fib_params: ifindex = %d\n", fib_params.ifindex);
	bpf_printk("before route fib_params: tos = %d\n", fib_params.tos);
	bpf_printk("before route fib_params: l4_protocol = %d\n", fib_params.l4_protocol);
	bpf_printk("before route fib_params: tot_len = %d\n", fib_params.tot_len);
	//分开打印ipv4_src和ipv4_dst，避免提示错：加载 BPF 对象失败: field DnsMarkXdp: program dns_mark_xdp: load program: invalid argument: invalid func unknown#177 (24524 line(s) omitted)
	bpf_printk("before route fib_params: ipv4_src A.B = %d.%d\n", fib_params.ipv4_src & 0xFF, (fib_params.ipv4_src >> 8) & 0xFF);
	bpf_printk("before route fib_params: ipv4_src C.D = %d.%d\n",(fib_params.ipv4_src >> 16) & 0xFF, (fib_params.ipv4_src >> 24) & 0xFF);
	bpf_printk("before route fib_params: ipv4_dst A.B = %d.%d\n", fib_params.ipv4_dst & 0xFF, (fib_params.ipv4_dst >> 8) & 0xFF);
	bpf_printk("before route fib_params: ipv4_dst C.D = %d.%d\n",(fib_params.ipv4_dst >> 16) & 0xFF, fib_params.ipv4_dst >> 24);

	// long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),
	// 			     BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_SRC);
	// 莫：带上 BPF_FIB_LOOKUP_SRC, 如果路由是8.8.8.8 via 172.17.0.2 dev br-x, 路由也会返回一个合适的跟br-x同网段的ip 作为fib_params.ipv4_src 。
	// 如果路由是8.8.8.8 via 172.17.0.2 dev br-x src 172.17.0.1 路由的结果里fib_params.ipv4_src 被改写为 172.17.0.1
	 
	long fib_rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_SRC);
	if (fib_rc != BPF_FIB_LKUP_RET_SUCCESS){
		bpf_printk("fib_lookup failed: %d\n", fib_rc);
		// * Returns
		// 	> 0 one of **BPF_FIB_LKUP_RET_** codes explaining why the
		//  * 	  packet is not forwarded or needs assist from full stack
		return XDP_PASS;
	}

	bpf_printk("after route fib_params: ifindex = %d\n", fib_params.ifindex);
	bpf_printk("after route fib_params: tos = %d\n", fib_params.tos);
	bpf_printk("after route fib_params: l4_protocol = %d\n", fib_params.l4_protocol);
	bpf_printk("after route fib_params: tot_len = %d\n", fib_params.tot_len);
	//分开打印ipv4_src和ipv4_dst，避免提示错：加载 BPF 对象失败: field DnsMarkXdp: program dns_mark_xdp: load program: invalid argument: invalid func unknown#177 (24524 line(s) omitted)
	bpf_printk("after route fib_params: ipv4_src A.B = %d.%d\n", fib_params.ipv4_src & 0xFF, (fib_params.ipv4_src >> 8) & 0xFF);
	bpf_printk("after route fib_params: ipv4_src C.D = %d.%d\n",(fib_params.ipv4_src >> 16) & 0xFF, (fib_params.ipv4_src >> 24) & 0xFF);

	// if (fib_params.ifindex == ctx->ingress_ifindex){
	// 	bpf_printk("dns_mark_xdp: ifindex = %d is the same as ingress_ifindex = %d, return XDP_TX\n", fib_params.ifindex, ctx->ingress_ifindex);
	// 	return XDP_TX;
	// }

	if (ip->saddr != fib_params.ipv4_src) {
		bpf_printk("fib_params: saddr changed\n");
		__be32 old_saddr = ip->saddr;
		ip->saddr = fib_params.ipv4_src;
		
		if (update_l4_csum_ipv4_saddr(ip, data_end, old_saddr, ip->saddr) < 0)
			return XDP_PASS;
		ip->check = ipv4_hdr_csum(ip);
	}

	// bpf_printk("fib_params src mac: %pM\n", fib_params.smac);
	// bpf_printk("fib_params dst mac: %pM\n", fib_params.dmac);
	/* 改写 L2 源/目的 MAC，匹配下一跳。 */
	__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	bpf_printk("dns_mark_xdp: redirect to ifindex = %d\n", fib_params.ifindex);
	long redirect_rc = bpf_redirect(fib_params.ifindex, 0); //莫:返回XDP_REDIRECT, ingerss网卡抓不到包，egress网卡能抓到包
	if (redirect_rc != XDP_REDIRECT){
		bpf_printk("redirect failed: %d\n", redirect_rc);
	}
	return redirect_rc;
}
