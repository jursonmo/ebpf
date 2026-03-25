#ifndef __DNS_MARK_XDP_H
#define __DNS_MARK_XDP_H

#include "common.h"

#define MAX_DOMAIN_LEN 64
#define DNS_PORT 53
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define AF_INET 2
#define ETH_ALEN 6

#define BPF_FIB_LKUP_RET_SUCCESS 0
#define BPF_FIB_LOOKUP_OUTPUT 2
#define BPF_FIB_LOOKUP_SRC 16
#define BPF_F_NO_PREALLOC 1

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 doff_res_flags;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct domain_key {
	char name[MAX_DOMAIN_LEN];
};

struct lpm_key {
	__u32 prefixlen;
	__u8 ip[4];
};

struct dnshdr {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
};

struct bpf_fib_lookup {
	__u8 family;
	__u8 l4_protocol;
	__be16 sport;
	__be16 dport;
	__u16 tot_len;
	__u32 ifindex;
	union {
		__u8 tos;
		__be32 flowinfo;
		__u32 rt_metric;
	};
	union {
		__be32 ipv4_src;
		__u32 ipv6_src[4];
	};
	union {
		__be32 ipv4_dst;
		__u32 ipv6_dst[4];
	};
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__u8 smac[ETH_ALEN];
	__u8 dmac[ETH_ALEN];
};

#endif
