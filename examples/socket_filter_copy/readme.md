此例子未经过验证
只是说明 BPF_PROG_TYPE_SOCKET_FILTER 类型的作用，它的作用是觉得是否copy 内核的数据到关联的socket, 从而应用层可以看到这个数据副本


SEC("socket") // 表示这个函数是一个 BPF 程序，类型是 BPF_PROG_TYPE_SOCKET_FILTER