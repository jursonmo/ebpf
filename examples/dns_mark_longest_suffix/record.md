
#### 我碰到一个问题，在5.15 内核的linux ,可以看到mark已经打上，且在iptables 可以匹配mark 54. 但是在5.4内核里linux 设备上测试，日志里看到  “<idle>-0     [000] .Ns. 2726413.185369: 0: domain:youtube.com, skb->mark=54”。 但是iptables 无法匹配54mark. 这可能是什么原因导致。

#### 在5.4 内核里，测试结果如下：
1. 测试规则
```
iptables -t mangle -I PREROUTING 1 -p udp --dport 53 -j LOG --log-prefix "pre-dns "
iptables -t mangle -I PREROUTING 1 -p udp --dport 53 -m mark --mark 54 -j LOG --log-prefix "pre-mark54 "

tc -s filter show dev <iface> ingress
```
2. 测试日志结果：pre-dns 有日志/计数，但 pre-mark54 没有.
```
root@ubuntu:~# tail -f /var/log/syslog
May 26 15:51:39 ubuntu kernel: [2727496.515458] pre-dns IN=lan OUT= PHYSIN=eth2 MAC=00:e2:69:1b:9a:54:00:e0:4c:68:02:c0:08:00 SRC=192.168.10.133 DST=192.168.10.1 LEN=57 TOS=0x00 PREC=0x00 TTL=64 ID=46983 PROTO=UDP SPT=60062 DPT=53 LEN=37

root@ubuntu:~# tc -s filter show dev lan ingress
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 dns_mark direct-action not_in_hw id 29 tag 5493ae5c3bdeffdd jited
```

### AI 分析原因
原因基本可以收敛到 **bridge 路径的 hook 顺序**。

你的 iptables 日志：

```text
pre-dns IN=lan OUT= PHYSIN=eth2 ...
```

说明这个包实际从桥成员口 `eth2` 进来，经过 bridge/br_netfilter 后，以 `IN=lan` 的形式进入 iptables。你现在 TC BPF 挂在：

```bash
tc -s filter show dev lan ingress
```

也就是挂在 **bridge master `lan` 的 ingress**，不是物理入口 `eth2`。

在 5.4 的 bridge/br_netfilter 路径里，`iptables mangle PREROUTING` 很可能已经在 `lan` 这个 master 设备的 TC ingress 之前处理过了。所以你后面在 TC 程序里看到：

```text
domain:youtube.com, skb->mark=54
```

只能证明 TC 程序执行时这个 skb 被写了 mark，但对前面已经执行过的 `mangle PREROUTING` 来说太晚了。因此出现：

- `pre-dns` 有日志/计数
- `pre-mark54` 没有
- BPF printk 里能看到 `skb->mark=54`

这三者并不矛盾。

建议直接把 BPF 挂到真正入口物理口，也就是 `eth2`：

```bash
tc qdisc add dev eth2 clsact 2>/dev/null
tc filter show dev eth2 ingress
```

你的 Go 配置里 `interface` 改成：

```json
"interface": "eth2"
```

如果 `lan` 下面有多个 bridge slave，就需要给每个 slave 都挂：

```bash
bridge link show master lan
```

然后对列出来的物理口分别挂 TC ingress。

再测：

```bash
iptables -t mangle -I PREROUTING 1 -p udp --dport 53 -m mark --mark 54 -j LOG --log-prefix "pre-mark54 "
iptables -t mangle -I PREROUTING 2 -p udp --dport 53 -j LOG --log-prefix "pre-dns "
```

如果挂到 `eth2` 后 `pre-mark54` 有日志/计数，就确认是 bridge master `lan` 的 TC ingress 太晚。

另外，如果你后面是用 `nat PREROUTING` 做 DNS redirect，记得排除 mark 要放在 nat 表里，mangle 表里的 `ACCEPT` 不会阻止 nat 表继续执行：

```bash
iptables -t nat -I PREROUTING 1 -p udp --dport 53 -m mark --mark 54 -j RETURN
```

结论：5.4 上优先不要把这个程序挂 bridge master `lan`，应该挂实际收包的 bridge slave，比如 `eth2`。


#### 结论： 如果开启br_netfilter, 则需要挂到实际收包的bridge slave 即物理口ethx, 而不是bridge master.  如果不开启br_netfilter, 则可以挂到bridge master. 内核5.15 之所以正常工作，是没有开启br_netfilter.