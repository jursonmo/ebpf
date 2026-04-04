// +build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

SEC("socket") // 表示这个函数是一个 BPF 程序，类型是 BPF_PROG_TYPE_SOCKET_FILTER
int count_icmp(struct __sk_buff *skb) {
    // 1. 解析以太网帧，判断是否是 IP 数据包
    // 偏移量：ETH_HLEN (14字节) 处是协议类型
    __u16 proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &proto, sizeof(proto));

    // 注意网络字节序转换 (0x0800 为 IPv4)
    if (proto != 0x0008) { // 实际上是 htons(ETH_P_IP)
        return 0; // 丢弃，不拷贝到用户态
    }

    // 2. 解析 IP 头，判断是否是 ICMP (协议号为 1)
    __u8 ip_proto;
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &ip_proto, sizeof(ip_proto));

    if (ip_proto != IPPROTO_ICMP) {
        return 0; // 不是 ICMP，不要
    }

    // 返回 -1 (或 skb->len) 表示将整个包拷贝到用户态
    // 返回 0 表示不拷贝
    return -1; 
}

char _license[] SEC("license") = "GPL";