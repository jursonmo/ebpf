#ifndef __FLOW_H
#define __FLOW_H

#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>
#include <bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
//#include <netinet/in.h>
#include <linux/types.h>

struct session_key {
    __u32 ip1;
    __u32 ip2;
    __u16 port1;
    __u16 port2;
    __u8 proto;
};

struct session_val {
    __u64 bytes_ab;
    __u64 bytes_ba;
    __u64 last_seen;
};

#endif