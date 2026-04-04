此例子未经过验证
只是说明 BPF_PROG_TYPE_SOCKET_FILTER 类型的作用，它的作用是觉得是否copy 内核的数据到关联的socket, 从而应用层可以看到这个数据副本


SEC("socket") // 表示这个函数是一个 BPF 程序，类型是 BPF_PROG_TYPE_SOCKET_FILTER

BPF_PROG_TYPE_SOCKET_FILTER类型的prog 会关联原始套接字， 原始套接字能接受到哪些数据，完全由这个prog 决定，也就是数据发生copy 就是发生在 ptype_all 中的套接字里，或者发生skb 离开协议栈后。

### 以从网卡接受报文来举例：
#### 路径：驱动程序 -> netif_receive_skb() -> __netif_receive_skb_core()

#### 关键点：在数据包进入具体的协议处理（如 IPv4 的 ip_rcv）之前，内核会遍历 ptype_all 链表。

#### 执行与拷贝：
1. 内核调用 deliver_skb()，进而调用 packet_rcv()（这是 af_packet 模块定义的函数）。
2. 在 packet_rcv() 内部，内核会调用 run_filter()（这里就是执行你编写的 eBPF 代码的地方）。

#### 根据返回值拷贝：
1. 如果 eBPF 返回 0，内核直接跳过。
2. 如果 eBPF 返回非 0，内核会调用 skb_clone()。注意，这通常是一个“克隆”操作，它只拷贝描述符（metadata），数据部分是共享的（只读），只有当你修改数据或缓冲区满时才会发生真正的物理拷贝。

#### 莫:以前要过滤数据，需要 ATTACH bpf 汇编代码， 但是不好写，也不灵活， 现在🈶了BPF_PROG_TYPE_SOCKET_FILTER类型的prog，可以在prog 程序里判断skb 的特性，通过返回值来决定skb 是否copy 到原始套接字里。


### 不仅可以挂载到 AF_PACKET（原始套接字），也可以挂载到普通的 AF_INET TCP 或 UDP 套接字上。

但这里有一个本质的区别：挂载到“正常 Socket”和“原始 Socket”上的行为逻辑完全不同。

1. 核心差异：镜像（Tap） vs 拦截（Filter）

1.1 关联到 Raw Socket (AF_PACKET)：
角色：它是“旁路监控”。

行为：内核把包发给协议栈的同时，额外复制一份给 Raw Socket。BPF 程序决定“要不要复制这笔数据”。它不会影响正常应用的通信。

1.2 关联到正常 TCP/UDP Socket (AF_INET)：

角色：它是“入场安检”。

行为：数据包已经在协议栈里走完了 TCP/UDP 处理逻辑。在数据被放入该 Socket 的**接收缓冲区（Receive Queue）**之前，内核会运行 eBPF 程序。

结果：如果 eBPF 程序返回 0，内核会直接丢弃这个包。这意味着你的应用程序（调用 read() 或 recv() 的那个进程）永远看不见这个包了。