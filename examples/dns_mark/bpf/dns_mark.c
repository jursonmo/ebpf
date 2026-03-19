//go:build ignore

#include "dns_mark.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>
//char LICENSE[] SEC("license") = "GPL";

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

/* ---- helpers ---- */

/*
 * Parse DNS wire-format query name into a dot-separated lowercase string.
 * Returns the length of the resulting string, or -1 on error.
 */
static __always_inline int parse_dns_name(struct __sk_buff *skb, __u32 off,
                                          char *buf)
{
    int pos = 0;
    __u8 label_len;

    //#pragma unroll //关闭所有的unroll,可以让.o文件从38K减少到12K
    for (int i = 0; i < MAX_DNS_LABELS; i++) {
        if (bpf_skb_load_bytes(skb, off, &label_len, 1) < 0)
            return -1;
        off++;

        if (label_len == 0)
            break;

        if (label_len > 63)
            return -1;

        if (pos + (int)label_len + 1 >= MAX_DOMAIN_LEN)
            return -1;

        if (i > 0)
            buf[pos++] = '.';

        //#pragma unroll
        for (int j = 0; j < 63; j++) {
            if (j >= label_len)
                break;
            __u8 ch;
            if (bpf_skb_load_bytes(skb, off + j, &ch, 1) < 0)
                return -1;
            if (ch >= 'A' && ch <= 'Z')
                ch += 32;
            if (pos < MAX_DOMAIN_LEN - 1)
                buf[pos++] = ch;
        }
        off += label_len;
    }

    if (pos >= 0 && pos < MAX_DOMAIN_LEN)
        buf[pos] = '\0';
    return pos;
}

/*
 * Look up domain in the rules map, trying progressively shorter suffixes.
 * e.g. "www.google.com" → "google.com" → "com"
 * Returns a bitmask of matching rules, or 0 if no match.
 */
static __always_inline __u64 match_domain(char *name, int name_len)
{
    struct domain_key key;
    __u64 *val;
    int off = 0;

    //#pragma unroll
    for (int attempt = 0; attempt < MAX_SUFFIX_DEPTH; attempt++) {
        if (off >= name_len)
            return 0;

        __builtin_memset(&key, 0, sizeof(key));

        //#pragma unroll
        for (int j = 0; j < MAX_DOMAIN_LEN - 1; j++) {
            int idx = off + j;
            if (idx >= MAX_DOMAIN_LEN || idx >= name_len)
                break;
            key.name[j] = name[idx];
        }

        val = bpf_map_lookup_elem(&domain_rules, &key);
        if (val)
            return *val;

        int found = 0;
        //#pragma unroll
        for (int j = off; j < MAX_DOMAIN_LEN; j++) {
            if (j >= name_len)
                break;
            if (name[j] == '.') {
                off = j + 1;
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }

    return 0;
}

/* ---- main program ---- */

SEC("tc")
int dns_mark(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

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

    /* --- DNS header (use skb helper for non-linear data safety) --- */
    __u32 dns_off = sizeof(struct ethhdr) + ip_hlen + sizeof(struct udphdr);

    struct dnshdr dns;
    if (bpf_skb_load_bytes(skb, dns_off, &dns, sizeof(dns)) < 0)
        return TC_ACT_OK;

    if (bpf_ntohs(dns.flags) & 0x8000)
        return TC_ACT_OK;

    if (bpf_ntohs(dns.qdcount) < 1)
        return TC_ACT_OK;

    /* --- Parse query domain name --- */
    __u32 name_off = dns_off + sizeof(struct dnshdr);
    char domain[MAX_DOMAIN_LEN];
    __builtin_memset(domain, 0, sizeof(domain));

    int name_len = parse_dns_name(skb, name_off, domain);
    if (name_len <= 0)
        return TC_ACT_OK;

    /* --- Match domain → rule bitmask --- */
    __u64 domain_mask = match_domain(domain, name_len);
    if (domain_mask == 0)
        return TC_ACT_OK;

    /* --- Match source IP via LPM trie → rule bitmask --- */
    struct lpm_key lpm;
    lpm.prefixlen = 32;
    __builtin_memcpy(lpm.ip, &ip->saddr, 4);

    __u64 *cidr_mask = bpf_map_lookup_elem(&cidr_rules, &lpm);
    if (!cidr_mask)
        return TC_ACT_OK;

    /* --- Both matched the same rule? Mark it. --- */
    if (domain_mask & *cidr_mask)
        skb->mark = MARK_VALUE;

    return TC_ACT_OK;
}
