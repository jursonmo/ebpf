### 加载bfp时，底层做了哪些事情，ebpf的Verifier现在就开始工作了？Verifier 会调用目标设备上的哪些库吗

我先快速看一下 loadDnsmarkObjects 在这个仓库里的实现链路（生成代码 -> ebpf 库加载器 -> 内核 bpf() 调用），然后给你一个“这 4 行代码到底触发了什么”的分层说明。

是的，在你这几行代码里 Verifier 就会开始工作，不是等到后面 tc 挂载时才开始。

loadDnsmarkObjects(&objs, nil) 的实际链路是：
```go
//dnsmark_bpfel.go
//Lines 47-53
func loadDnsmarkObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDnsmark()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}
```
LoadAndAssign 会触发 map/program 的内核加载：


collection.go
Lines 189-195
```go
case reflect.TypeOf((*Program)(nil)):
	assignedProgs[name] = true
	return loader.loadProgram(name)
case reflect.TypeOf((*Map)(nil)):
	assignedMaps[name] = true
	return loader.loadMap(name)
```
loadProgram 最终走到 BPF_PROG_LOAD：


collection.go
Lines 492-495
```go
prog, err := newProgramWithOptions(progSpec, cl.opts.Programs, cl.types)
if err != nil {
	return nil, fmt.Errorf("program %s: %w", progName, err)
}
```

prog.go
Lines 492-493
```go
fd, err = sys.ProgLoad(attr)
if err == nil {
```

types.go
Lines 1500-1502
```go
func ProgLoad(attr *ProgLoadAttr) (*FD, error) {
	fd, err := BPF(BPF_PROG_LOAD, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
```

```go
func BPF(cmd Cmd, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	// Prevent the Go profiler from repeatedly interrupting the verifier,
	// which could otherwise lead to a livelock due to receiving EAGAIN.
	if cmd == BPF_PROG_LOAD || cmd == BPF_PROG_RUN {
		maskProfilerSignal()
		defer unmaskProfilerSignal()
	}

	for {
		r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		runtime.KeepAlive(attr)

		// As of ~4.20 the verifier can be interrupted by a signal,
		// and returns EAGAIN in that case.
		if errNo == unix.EAGAIN && cmd == BPF_PROG_LOAD {
			continue
		}

		var err error
		if errNo != 0 {
			err = wrappedErrno{errNo}
		}

		return r1, err
	}
}
```
### 你这个问题的直接答案：

#### Verifier 什么时候开始？
1. 在 loadDnsmarkObjects 内部加载 program 时（BPF_PROG_LOAD syscall）就开始。

2. 它会调用目标设备上的库吗？
不会调用“设备上的用户态库”（比如 libc、你机器上的动态库、网卡上的某个库）。
Verifier 是内核里的静态分析器，在内核态检查字节码合法性（控制流、越界、helper 调用类型、上下文访问等）。

3. 那它依赖什么？
主要依赖内核里的 BPF 子系统元数据和能力（program type、helper 原型、BTF/kfunc 信息等）。
对 SEC("tc")（sched_cls）来说，是按该类型规则验证 __sk_buff 上下文访问和 helper 使用。

4. 和网卡设备本身有关系吗？
你这条普通 tc 路径下，验证主要是内核通用 verifier；不是去调用某个“目标设备库”。
（只有硬件 offload 等特殊模式，才可能涉及驱动/固件侧额外校验路径。）