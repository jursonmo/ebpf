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
 * Parse DNS wire-format name from a pre-read stack buffer (raw)
 * into a dot-separated lowercase string (buf).
 * raw must be zero-padded so that bytes beyond actual data are 0.
 */
static __always_inline int parse_dns_name(char *raw, char *buf)
{
    int pos = 0;
    int roff = 0;

    for (int i = 0; i < MAX_DNS_LABELS; i++) {
        if (roff >= MAX_DOMAIN_LEN)
            return -1;

        __u8 label_len = (__u8)raw[roff];
        roff++;

        if (label_len == 0)
            break;
        if (label_len > 63)
            return -1;
        if (roff + label_len > MAX_DOMAIN_LEN)
            return -1;
        if (pos + (int)label_len + 1 >= MAX_DOMAIN_LEN)
            return -1;

        if (i > 0 && pos < MAX_DOMAIN_LEN - 1)
            buf[pos++] = '.';

        for (int j = 0; j < MAX_DOMAIN_LEN - 1; j++) {
            if (j >= label_len)
                break;
            int ridx = roff + j;
            if (ridx >= MAX_DOMAIN_LEN)
                break;
            char ch = raw[ridx];
            if (ch >= 'A' && ch <= 'Z')
                ch += 32;
            if (pos < MAX_DOMAIN_LEN - 1)
                buf[pos++] = ch;
        }
        roff += label_len;
    }

    if (pos < MAX_DOMAIN_LEN)
        buf[pos] = '\0';
    return pos;
}

/*
 * Look up domain in the rules map with exact match only.
 * Returns a bitmask of matching rules, or 0 if no match.
 */
static __always_inline __u64 match_domain(char *name, int name_len)
{
    struct domain_key key;
    __u64 *val;
    if (name_len <= 0)
        return 0;

    __builtin_memset(&key, 0, sizeof(key));
    for (int j = 0; j < MAX_DOMAIN_LEN - 1; j++) {
        if (j >= name_len)
            break;
        key.name[j] = name[j];
	asm volatile("");
    }

    val = bpf_map_lookup_elem(&domain_rules, &key);
    if (val)
        return *val;

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

    /* --- Bulk-read DNS query name into stack buffer --- */
    __u32 name_off = dns_off + sizeof(struct dnshdr);
    if (skb->len <= name_off)
        return TC_ACT_OK;

    __u32 avail = skb->len - name_off;
    if (avail > MAX_DOMAIN_LEN)
        avail = MAX_DOMAIN_LEN;

    char raw[MAX_DOMAIN_LEN];
    __builtin_memset(raw, 0, sizeof(raw));
    if (bpf_skb_load_bytes(skb, name_off, raw, avail) < 0)
        return TC_ACT_OK;

    /* --- Parse wire-format → dot-separated lowercase --- */
    char domain[MAX_DOMAIN_LEN];
    __builtin_memset(domain, 0, sizeof(domain));

    int name_len = parse_dns_name(raw, domain);
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
