//go:build ignore

#include "dns_mark.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>
char LICENSE[] SEC("license") = "GPL";

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
    domain_len &= 0xFFFF;
    if (domain_len > MAX_DOMAIN_LEN)
        return TC_ACT_OK;

    __u8 raw[MAX_DOMAIN_LEN];
    __builtin_memset(raw, 0, sizeof(raw));
    if (bpf_skb_load_bytes(skb, name_off, raw, domain_len) < 0){
        bpf_printk("dns_mark: bpf_skb_load_bytes failed\n");
        return TC_ACT_OK;
    }
    bpf_printk("dns_mark: raw = %s\n", raw);
    struct domain_key dkey;
    __builtin_memset(&dkey, 0, sizeof(dkey));

    __u32 out_pos = 0;
    __u8 label_rem = 0;
    __u8 ended = 0;
    __u8 seen_label = 0;

    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        __u8 b = raw[i];

        if (label_rem == 0) {
            if (b == 0) {
                ended = 1;
                break;
            }

            /* Reject DNS compression pointers and invalid label length. */
            if (b & 0xC0)
                return TC_ACT_OK;
            if (b > 63)
                return TC_ACT_OK;

            if (seen_label) {
                if (out_pos >= MAX_DOMAIN_LEN - 1)
                    return TC_ACT_OK;
                dkey.name[out_pos++] = '.';
            }
            label_rem = b;
            seen_label = 1;
            continue;
        }

        if (out_pos >= MAX_DOMAIN_LEN - 1)
            return TC_ACT_OK;
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
        skb->mark = MARK_VALUE;

    return TC_ACT_OK;
}
