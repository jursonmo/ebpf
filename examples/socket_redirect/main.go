package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go tool bpf2go -tags linux socketredirect bpf/socket_redirect.c -- -I./bpf -I../headers

// func loadSocketredirect() (*ebpf.CollectionSpec, error) {
// 	return ebpf.LoadCollectionSpec("socketredirect_bpfel.o")
// }

func main() {
	// 1. 加载编译好的 eBPF 程序
	spec, err := loadSocketredirect()
	if err != nil {
		log.Fatalf("加载失败: %v", err)
	}

	objs := struct {
		SockMap     *ebpf.Map     `ebpf:"sock_map"`
		SockPairMap *ebpf.Map     `ebpf:"sock_pair_map"`
		BpfTcpRedir *ebpf.Program `ebpf:"bpf_tcp_redir"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("创建集合失败: %v", err)
	}
	defer objs.SockMap.Close()
	defer objs.SockPairMap.Close()
	defer objs.BpfTcpRedir.Close()

	// 2. 将程序挂载到 SockHash Map 上
	// 这样每当 Map 中的 Socket 有消息产生，都会触发这个 eBPF 程序
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.BpfTcpRedir,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		log.Fatalf("挂载失败: %v", err)
	}

	// 3. 监听 8080，每次 accept 新连接就连到 127.0.0.1:9090
	lnA, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalf("监听 8080 失败: %v", err)
	}
	defer lnA.Close()

	// 仅用于保证连接对象在用户态保持引用，避免被 GC 提前关闭 FD。
	// 本示例聚焦配对重定向，不做连接生命周期清理。
	sessions := make(map[uint64]*sessionPair)
	var mu sync.Mutex

	log.Println("监听 127.0.0.1:8080，accept 后将自动连接 127.0.0.1:9090 并配置 sockmap 双向重定向")
	for {
		connA, err := lnA.Accept()
		if err != nil {
			log.Printf("Accept A 连接失败: %v", err)
			continue
		}

		tcpA, ok := connA.(*net.TCPConn)
		if !ok {
			log.Printf("连接不是 TCPConn，关闭: %T", connA)
			_ = connA.Close()
			continue
		}

		connB, err := net.Dial("tcp", "127.0.0.1:9090")
		if err != nil {
			log.Printf("建立 B 连接失败: %v", err)
			_ = tcpA.Close()
			continue
		}

		tcpB, ok := connB.(*net.TCPConn)
		if !ok {
			log.Printf("连接不是 TCPConn，关闭: %T", connB)
			_ = tcpA.Close()
			_ = connB.Close()
			continue
		}

		if err := addRedirectPair(objs.SockMap, objs.SockPairMap, tcpA, tcpB); err != nil {
			log.Printf("配置重定向失败: %v", err)
			_ = tcpA.Close()
			_ = tcpB.Close()
			continue
		}

		_, cookieA, err := getSocketFDAndCookie(tcpA)
		if err != nil {
			log.Printf("获取 A cookie 失败: %v", err)
			_ = tcpA.Close()
			_ = tcpB.Close()
			continue
		}

		mu.Lock()
		sessions[cookieA] = &sessionPair{a: tcpA, b: tcpB}
		mu.Unlock()

		log.Printf("已建立配对: client(%s) <-> backend(%s)", tcpA.RemoteAddr(), tcpB.RemoteAddr())
	}
}

type sessionPair struct {
	a *net.TCPConn
	b *net.TCPConn
}

func addRedirectPair(sockMap, pairMap *ebpf.Map, a, b *net.TCPConn) error {
	fdA, cookieA, err := getSocketFDAndCookie(a)
	if err != nil {
		return fmt.Errorf("获取 A fd/cookie 失败: %w", err)
	}
	fdB, cookieB, err := getSocketFDAndCookie(b)
	if err != nil {
		return fmt.Errorf("获取 B fd/cookie 失败: %w", err)
	}

	fdValA := uint64(fdA)
	fdValB := uint64(fdB)

	if err := sockMap.Update(&cookieA, &fdValA, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sock_map 写入 A 失败: %w", err)
	}
	if err := sockMap.Update(&cookieB, &fdValB, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sock_map 写入 B 失败: %w", err)
	}

	if err := pairMap.Update(&cookieA, &cookieB, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sock_pair_map 写入 A->B 失败: %w", err)
	}
	if err := pairMap.Update(&cookieB, &cookieA, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("sock_pair_map 写入 B->A 失败: %w", err)
	}

	log.Printf("配对完成: cookieA=%d fdA=%d <-> cookieB=%d fdB=%d", cookieA, fdA, cookieB, fdB)
	return nil
}

func getSocketFDAndCookie(conn *net.TCPConn) (fd int, cookie uint64, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var controlErr error
	if err := raw.Control(func(s uintptr) {
		fd = int(s)
		cookie, controlErr = unix.GetsockoptUint64(int(s), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		return 0, 0, err
	}
	if controlErr != nil {
		return 0, 0, controlErr
	}
	if cookie == 0 {
		return 0, 0, syscall.EINVAL
	}

	return fd, cookie, nil
}

/*
这个场景一个 sock_map 就能做，不一定要两个 map。

你说的设计：

key: src_cookie
value: dst_socket_fd
在 sk_msg 里直接用当前 src_cookie 调 bpf_msg_redirect_hash，就能把数据导到目标 socket。
如果要双向，就写两条：

A_cookie -> fdB
B_cookie -> fdA
*/
