//go:build ignore

#include "dns_mark.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>
char LICENSE[] SEC("license") = "GPL";

enum domain_match_mode {
    DOMAIN_MATCH_EXACT = 0,
    DOMAIN_MATCH_LONGEST_SUFFIX = 1,
};

volatile const __u32 domain_match_mode = DOMAIN_MATCH_EXACT;

/* ---- maps ---- */

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

/* ---- main program ---- */
SEC("tc")
int dns_mark(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    //bpf_printk("dns_mark: skb->data = %p, skb->data_end = %p\n", skb->data, skb->data_end);
    /* --- ETH --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* --- IP --- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u32 ip_hlen = ip->ihl << 2;
    if (ip_hlen < sizeof(struct iphdr))
        return TC_ACT_OK;

    /* --- UDP --- */
    struct udphdr *udp = (void *)((char *)ip + ip_hlen);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (udp->dest != bpf_htons(DNS_PORT))
        return TC_ACT_OK;

    //cat /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("dns_mark: udp->dest = %d\n", bpf_ntohs(udp->dest));
    /* --- DNS header (read via helper for non-linear skb safety) --- */
    __u32 dns_off = sizeof(struct ethhdr) + ip_hlen + sizeof(struct udphdr);

    struct dnshdr dns;
    if (bpf_skb_load_bytes(skb, dns_off, &dns, sizeof(dns)) < 0){
        bpf_printk("dns_mark: bpf_skb_load_bytes failed\n");
        return TC_ACT_OK;
    }
    bpf_printk("dns_mark: dns.flags = %d\n", bpf_ntohs(dns.flags));
    if (bpf_ntohs(dns.flags) & 0x8000){
        bpf_printk("dns_mark: dns.flags = %d not a query, skip\n", bpf_ntohs(dns.flags));
        return TC_ACT_OK;
    }

    if (bpf_ntohs(dns.qdcount) < 1)
    {
        bpf_printk("dns_mark: dns.qdcount = %d < 1, skip\n", bpf_ntohs(dns.qdcount));
        return TC_ACT_OK;
    }

    /* --- Read and parse DNS QNAME into normalized dot-lowercase key --- */
    __u32 name_off = dns_off + sizeof(struct dnshdr);
    if (skb->len <= name_off)
        return TC_ACT_OK;

    bpf_printk("dns_mark: skb->len = %d, name_off = %d\n", skb->len, name_off);
    __u32 skb_len = skb->len;
    if (skb_len < name_off)
        return TC_ACT_OK;
    
    u32 domain_len = skb_len - name_off;
    //domain_len &= 0xFFFF;
    if (domain_len > MAX_DOMAIN_LEN)
        return TC_ACT_OK;
   // if (domain_len > MAX_DOMAIN_LEN) 
    //    domain_len = MAX_DOMAIN_LEN;

    __u8 raw[MAX_DOMAIN_LEN];
    __builtin_memset(raw, 0, sizeof(raw));
    if (domain_len == 0)
        return TC_ACT_OK;

        
    //asm volatile ("" : "+r"(domain_len));
    //if (domain_len == 0) domain_len = 1;
    // 4. 【核心黑科技】强制告诉验证器：domain_len 的范围是 [1, 64]
    // 即使我们知道它是对的，也要通过位运算再次锁定
    // 如果 MAX_DOMAIN_LEN 是 64，我们利用 (domain_len - 1) 进行位掩码
    // 这样即便 domain_len 是 0，运算后也会变成 63，而不会是 0   
    u32 final_len = (domain_len - 1) & (MAX_DOMAIN_LEN - 1);
    final_len += 1;
    //asm volatile ("" : "+r"(final_len));
    if (bpf_skb_load_bytes(skb, name_off, raw, /*MAX_DOMAIN_LEN*/ final_len) < 0){
        bpf_printk("dns_mark: bpf_skb_load_bytes failed\n");
        return TC_ACT_OK;
    }


    bpf_printk("dns_mark: get raw domain  = %s\n", raw);
    struct domain_key dkey;
    __builtin_memset(&dkey, 0, sizeof(dkey));

    __u32 out_pos = 0;
    __u8 label_rem = 0;
    __u8 ended = 0;
    __u8 seen_label = 0;
    __u8 dot_positions[MAX_SUFFIX_DEPTH];
    __u8 dot_count = 0;
    __builtin_memset(dot_positions, 0, sizeof(dot_positions));

    /*
    这段代码的作用是将 DNS Query Name（QNAME）从 wire 格式（如: 3www6google3com0）解码并标准化为小写点分（如: www.google.com）。
    具体步骤如下：

    - 遍历 raw 缓冲区里的 QNAME 数据，最多处理 MAX_DOMAIN_LEN 字节。
    - DNS QNAME 是以标签长度(1字节)+标签内容的方式递归编码，如【3 www 6 google 3 com 0】：
        - 如果 label_rem == 0，说明下一个字节表示新标签的长度（或者是结尾的 0，表示域名结束）。
            - 如果是 0，则设置 ended 标志，并 break。
            - 如果高两位为 1（即 b & 0xC0），说明遇到了 DNS 压缩指针，不支持直接 return。
            - 如果长度 > 63，非法，也直接 return。
            - 如果 seen_label==1，说明不是第一个标签，需要在输出 dkey.name 里补一个 '.'，并记录每段的起始 offset（用于后缀匹配）。
            - 其余情况下设置 label_rem = b（即当前标签剩余字符数），seen_label=1，并继续处理下一个字节。
        - 如果 label_rem > 0，说明现在应当按内容字节解析:
            - 如果 out_pos 超界，直接 return。
            - 若字符是大写字母，转成小写。
            - 写入 dkey.name，并label_rem--。
    - 最后得到的 dkey.name 就是 smallcase 并以 '.' 连接的域名字符串，比如 "www.google.com"。

    主要注意点：
    - 拒绝了 DNS 压缩格式（这在普通 DNS 报文里，QNAME 不会出现指针）。
    - label_rem 机制确保严格按照 RFC 的域名标签格式处理。
    - 只记录 MAX_SUFFIX_DEPTH 个 '.' 位置，便于后续 longest_suffix 匹配。
    */
    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        __u8 b = raw[i];

        // 开始一个新 label
        if (label_rem == 0) {
            if (b == 0) {
                ended = 1;  // 域名解析结束
                break;
            }

            // 拒绝 DNS 指针（压缩域名不允许，QNAME 只允许长度标签）
            if (b & 0xC0)
                return TC_ACT_OK;
            // 拒绝 label 长度非法
            if (b > 63)
                return TC_ACT_OK;

            // 不是第一个标签，需要在字符串中插入 '.'
            if (seen_label) {
                if (out_pos >= MAX_DOMAIN_LEN - 1)
                    return TC_ACT_OK;
                if (dot_count < MAX_SUFFIX_DEPTH)
                    dot_positions[dot_count++] = out_pos;
                dkey.name[out_pos++] = '.';
            }
            label_rem = b;
            seen_label = 1;
            continue;
        }

        // 处理标签内容字节
        if (out_pos >= MAX_DOMAIN_LEN - 1)
            return TC_ACT_OK;
        // 转为小写
        if (b >= 'A' && b <= 'Z')
            b += ('a' - 'A');
        dkey.name[out_pos++] = b;
        label_rem--;
    }

    bpf_printk("get domain key: %s\n", dkey.name);
    if (!ended || !seen_label || label_rem != 0 || out_pos == 0)
        return TC_ACT_OK;

    /* --- Match domain → rule bitmask --- */
    __u64 domain_mask = 0;
    __u64 *dmask = bpf_map_lookup_elem(&domain_rules, &dkey);
    if (dmask)
        domain_mask = *dmask;
    if (domain_mask == 0 && domain_match_mode == DOMAIN_MATCH_LONGEST_SUFFIX) {
#pragma unroll
        for (int suffix_idx = 0; suffix_idx < MAX_SUFFIX_DEPTH; suffix_idx++) {
            if (suffix_idx >= dot_count)
                break;

            __u32 start = (__u32)dot_positions[suffix_idx] + 1;
            if (start >= out_pos)
                break;
            __u32 copy_len = out_pos - start;

            struct domain_key suffix_key;
            __builtin_memset(&suffix_key, 0, sizeof(suffix_key));
#pragma unroll
            for (int j = 0; j < MAX_DOMAIN_LEN; j++) {
                if (j >= copy_len)
                    break;
                suffix_key.name[j] = dkey.name[start + j];
            }

            dmask = bpf_map_lookup_elem(&domain_rules, &suffix_key);
            if (dmask) {
                domain_mask = *dmask;
                break;
            }
        }
    }
    if (domain_mask == 0)
        return TC_ACT_OK;

    bpf_printk("get domain mask: %d\n", domain_mask);
    /* --- Match source IP via LPM trie → rule bitmask --- */
    struct lpm_key lpm;
    __builtin_memset(&lpm, 0, sizeof(lpm));
    lpm.prefixlen = 32;
    __builtin_memcpy(lpm.ip, &ip->saddr, 4);

    __u64 *cidr_mask = bpf_map_lookup_elem(&cidr_rules, &lpm);
    if (!cidr_mask)
    {
        bpf_printk("get cidr mask failed\n");
        return TC_ACT_OK;
    }
    bpf_printk("get cidr mask: %d\n", *cidr_mask);

    /* --- Both matched the same rule? Mark it. --- */
    if (domain_mask & *cidr_mask)
        skb->mark = MARK_NO_REDIRECT;

    return TC_ACT_OK;
}
