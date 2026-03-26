#ifndef __DNS_MARK_H
#define __DNS_MARK_H


#ifdef VMLINUX_H
#include "5.15.0.vmlinux.h"
#define ETH_P_IP 0x0800
enum tc_action_x {
	TC_ACT_UNSPEC 		= -1,
	TC_ACT_OK 			= 0,
	TC_ACT_RECLASSIFY 	= 1,
	TC_ACT_SHOT 		= 2,
	TC_ACT_PIPE 		= 3,
	TC_ACT_STOLEN 		= 4,
	TC_ACT_QUEUED 		= 5,
	TC_ACT_REPEAT 		= 6,
	TC_ACT_REDIRECT 	= 7,
	TC_ACT_JUMP 		= 0x10000000
};
#else
#include "common.h"
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    __u32 flow_keys;
    __u64 tstamp;
    __u32 wire_len;
    __u32 gso_segs;
    __u32 sk;
    __u32 gso_size;
};


#endif


#define MAX_DOMAIN_LEN   64
#define MAX_DNS_LABELS   8
#define MAX_SUFFIX_DEPTH (MAX_DNS_LABELS - 1)
#define DNS_PORT         53
#define MARK_NO_REDIRECT 54  //为了表明这个mark是绕过dns重定向的mark, 所以marK改成54;iptables -t mangle -I PREROUTING -p udp --dport 53 -m mark --set-mark 54 -j ACCEPT
#define IPPROTO_UDP      17
#define BPF_F_NO_PREALLOC 1


struct domain_key {
    char name[MAX_DOMAIN_LEN];
};

struct lpm_key {
    __u32 prefixlen;
    __u8  ip[4];
};

struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};


#endif
