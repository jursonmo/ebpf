#include "flow.h"

#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>
#include <bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
//#include <netinet/in.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct session_key);
    __type(value, struct session_val);
} sessions SEC(".maps");


static __always_inline int normalize_tuple(
        struct session_key *key,
        __u32 src_ip,
        __u32 dst_ip,
        __u16 src_port,
        __u16 dst_port,
        __u8 proto,
        int *dir)
{
    key->proto = proto;

    if (src_ip < dst_ip ||
        (src_ip == dst_ip && src_port < dst_port)) {

        key->ip1 = src_ip;
        key->ip2 = dst_ip;
        key->port1 = src_port;
        key->port2 = dst_port;

        *dir = 0;

    } else {

        key->ip1 = dst_ip;
        key->ip2 = src_ip;
        key->port1 = dst_port;
        key->port2 = src_port;

        *dir = 1;
    }

    return 0;
}


static __always_inline int parse_packet(struct __sk_buff *skb,
                                        struct session_key *key,
                                        int *dir)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end)
        return -1;

    __u16 sport = 0;
    __u16 dport = 0;

    if (ip->protocol == 6 /*IPPROTO_TCP*/) {

        struct tcphdr *tcp = (void *)ip + sizeof(*ip);

        if ((void *)(tcp + 1) > data_end)
            return -1;

        sport = tcp->source;
        dport = tcp->dest;

    } else if (ip->protocol == 17/*IPPROTO_UDP*/) {

        struct udphdr *udp = (void *)ip + sizeof(*ip);

        if ((void *)(udp + 1) > data_end)
            return -1;

        sport = udp->source;
        dport = udp->dest;

    } else {
        return -1;
    }

    normalize_tuple(
        key,
        ip->saddr,
        ip->daddr,
        sport,
        dport,
        ip->protocol,
        dir);

    return 0;
}


static __always_inline void update_session(struct session_key *key,
                                           int dir,
                                           __u64 bytes)
{
    struct session_val *val;
    __u64 now = bpf_ktime_get_ns();

    val = bpf_map_lookup_elem(&sessions, key);

    if (!val) {

        struct session_val new = {};
        new.last_seen = now;

        if (dir == 0)
            new.bytes_ab = bytes;
        else
            new.bytes_ba = bytes;

        bpf_map_update_elem(&sessions, key, &new, BPF_ANY);
        return;
    }

    if (dir == 0)
        __sync_fetch_and_add(&val->bytes_ab, bytes);
    else
        __sync_fetch_and_add(&val->bytes_ba, bytes);

    val->last_seen = now;
}


SEC("tc")
int flow_ingress(struct __sk_buff *skb)
{
    struct session_key key = {};
    int dir;

    if (parse_packet(skb, &key, &dir) < 0)
        return BPF_OK;

    update_session(&key, dir, skb->len);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";