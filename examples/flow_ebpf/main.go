package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	//"github.com/cilium/ebpf/link"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go flow bpf/flow.c -- -I./bpf
//go:generate go tool bpf2go  -tags linux flow bpf/flow.c -- -I./bpf -I../headers
// flow 决定了生成文件的名称，flow_bpfel.go 和 flow_bpfeb.go

type SessionKey struct {
	IP1   uint32
	IP2   uint32
	Port1 uint16
	Port2 uint16
	Proto uint8
	Pad   [3]byte
}

type SessionVal struct {
	BytesAB  uint64
	BytesBA  uint64
	LastSeen uint64
}

const idleTimeout = 5 * time.Minute

func ipToString(ip uint32) string {

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)

	return net.IP(b).String()
}

func main() {
	ifaceName := ""
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}
	if ifaceName == "" {
		log.Printf("请指定网卡名，如: %s ens2\n", os.Args[0])
		return
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal(err)
	}
	_ = iface

	var objs flowObjects

	if err := loadFlowObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}

	defer objs.Close()

	// l, err := link.AttachTC(link.TCOptions{
	// 	Program:   objs.FlowIngress,
	// 	Interface: iface.Index,
	// 	Attach:    ebpf.AttachTCIngress,
	// })
	// l, err := link.AttachTCX(link.TCXOptions{
	// 	Program:   objs.FlowIngress,
	// 	Interface: iface.Index,
	// 	Attach:    ebpf.AttachTCXIngress,
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// defer l.Close()

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get link: %v", err)
	}
	// 3. 添加 clsact qdisc (必须先有 clsact 才能挂载 ingress/egress)
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	// 忽略已存在的错误
	_ = netlink.QdiscAdd(qdisc)

	// 4. 创建 TC filter 并将 eBPF 程序 FD 注入
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS, // 如果是 egress 请用 HANDLE_MIN_EGRESS
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           objs.FlowIngress.FD(), // 这里传入 cilium/ebpf 提取出的 FD
		Name:         "my_tc_prog",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("failed to attach TC filter: %v", err)
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("failed to attach TC filter: %v", err)
	}

	fmt.Println("flow monitor started on", ifaceName)

	go gcSessions(objs.Sessions)
	go printSessions(objs.Sessions)

	select {}
}

func gcSessions(m *ebpf.Map) {

	ticker := time.NewTicker(time.Minute)

	for range ticker.C {

		iter := m.Iterate()

		var k SessionKey
		var v SessionVal

		now := uint64(time.Now().UnixNano())

		for iter.Next(&k, &v) {

			if now-v.LastSeen > uint64(idleTimeout) {

				m.Delete(&k)
			}
		}
	}
}

func printSessions(m *ebpf.Map) {

	ticker := time.NewTicker(5 * time.Second)

	for range ticker.C {

		fmt.Println("---- sessions ----")

		iter := m.Iterate()

		var k SessionKey
		var v SessionVal

		for iter.Next(&k, &v) {

			fmt.Printf("%s:%d <-> %s:%d proto=%d  tx=%d  rx=%d\n",
				ipToString(k.IP1),
				k.Port1,
				ipToString(k.IP2),
				k.Port2,
				k.Proto,
				v.BytesAB,
				v.BytesBA,
			)
		}
	}
}
