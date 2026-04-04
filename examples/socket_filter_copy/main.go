package main

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// 1. 解除内存限制 (eBPF 程序必备)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 2. 加载编译好的 BPF 对象
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// 3. 创建一个 Raw Socket (监听所有以太网帧)
	// 需要 root 权限
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("failed to open raw socket: %v", err)
	}
	defer syscall.Close(sock)

	// 4. 将 BPF 程序挂载到 Socket 上
	// 关键：使用 SO_ATTACH_BPF 选项
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_ATTACH_BPF, objs.CountIcmp.FD()); err != nil {
		log.Fatalf("failed to attach BPF to socket: %v", err)
	}

	fmt.Println("BPF 程序已挂载！正在监听 ICMP (Ping) 包... (请在另一个终端执行 ping 127.0.0.1)")

	// 5. 像读取普通文件一样从 Socket 读取被 BPF 过滤后的数据
	buf := make([]byte, 1500)
	for {
		n, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			log.Printf("recv error: %v", err)
			continue
		}

		// 解析捕获到的原始数据包 (简单处理)
		payload := buf[:n]
		if len(payload) > 34 {
			srcIP := net.IP(payload[26:30]) // IPv4 源地址在包中的固定偏移
			fmt.Printf("检测到 Ping 包！来自源 IP: %s，包大小: %d 字节\n", srcIP, n)
		}
	}
}

// 辅助函数：处理大端字节序
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
