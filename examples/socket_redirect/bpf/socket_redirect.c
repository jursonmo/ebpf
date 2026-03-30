#ifdef VMLINUX_H
    #include "../../vmlinux_headers/5.15.0.vmlinux.h"
#else
    #include "common.h"
    #ifndef SK_PASS
    enum sk_action {
        SK_DROP = 0,
        SK_PASS = 1,
    };
    #endif
#endif

//#include <linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

#ifndef BPF_F_INGRESS
#define BPF_F_INGRESS (1ULL)
#endif




// 定义一个 SockHash Map，用于存储 Socket 的映射关系
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, __u64);   // socket cookie
    __type(value, __u64); // Socket 的文件描述符
} sock_map SEC(".maps");

// 保存“当前 socket -> 对端 socket”的映射关系（都使用 socket cookie）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, __u64);
    __type(value, __u64);
} sock_pair_map SEC(".maps");

SEC("sk_msg")
int bpf_tcp_redir(struct sk_msg_md *msg) {
    __u64 src_cookie = bpf_get_socket_cookie(msg);
    __u64 *target_cookie;

    if (!src_cookie) {
        return SK_PASS;
    }

    // 先查“当前 socket 对应的目标 socket”
    target_cookie = bpf_map_lookup_elem(&sock_pair_map, &src_cookie);
    if (!target_cookie) {
        // 没有配对关系时不做重定向，交给常规路径
        return SK_PASS;
    }

    // 根据查到的目标 cookie 进行重定向
    long ret = bpf_msg_redirect_hash(msg, &sock_map, target_cookie, BPF_F_INGRESS);

    if (ret == SK_PASS) {
        // 重定向成功！数据已直接“瞬移”到 Socket B
        return SK_PASS; 
    }

    // --- 处理背压 (Backpressure) ---
    // 如果返回不是 SK_PASS（通常是 -EAGAIN，说明目标写缓冲区满了）
    // 我们返回 SK_PASS 但不执行 redirect，数据会留在原 Socket 的接收队列中
    // 这样原 Socket 就不再清空接收缓存，对端探测到窗口变小，自然就会减慢发送速度
    return SK_PASS; 
}

char _license[] SEC("license") = "GPL";