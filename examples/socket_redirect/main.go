package main

import (
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
		BpfTcpRedir *ebpf.Program `ebpf:"bpf_tcp_redir"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("创建集合失败: %v", err)
	}
	defer objs.SockMap.Close()
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

	// 3. 模拟两个连接 A 和 B
	connA, _ := net.Dial("tcp", "127.0.0.1:8080")
	connB, _ := net.Dial("tcp", "127.0.0.1:9090")

	// 关键：获取底层文件描述符
	rawA, _ := connA.(*net.TCPConn).File()
	rawB, _ := connB.(*net.TCPConn).File()

	// 4. 注入 Map，建立关联
	// 把 Socket B 存入 key 1，这样 eBPF 就能找到它
	var key uint32 = 1
	val := uint64(rawB.Fd())
	objs.SockMap.Update(&key, &val, ebpf.UpdateAny)

	// 把 Socket A 也存入 Map（触发 sk_msg 挂钩）
	var keyA uint32 = 0
	valA := uint64(rawA.Fd())
	objs.SockMap.Update(&keyA, &valA, ebpf.UpdateAny)

	log.Println("eBPF 零拷贝转发已就绪，正在静默加速...")
	select {} // 阻塞运行
}
