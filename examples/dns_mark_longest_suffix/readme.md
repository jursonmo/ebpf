TODO: 目前还没解决 加载 BPF 对象失败: field DnsMark: program dns_mark: load program: argument list too long: BPF program is too large. Processed 1000001 insn (38422 line(s) omitted)

莫：解决方法： bpf_loop  5.17 内核？  尾调用？
```
grep "CONFIG_DEBUG_INFO_BTF" /boot/config-$(uname -r)
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
```
make buildbpfloop 可以编译使用bpf_loop的dns_mark_bpf_loop.c
在dns_mark_bpf_loop.c 加上bpf_loop的定义，编译出来的.o还是有17K, 依然提示 BPF program is too large

2026.04.12 bpf_loop也不好解决BPF program is too large 和 verifier 检验的问题。我看到过 dae 项目里的bpf_helper._defs.h 里包含了bpf_loop的声明.
libbpf_1.4.7版本也包含了bpf_loop等相关声明，执行update.sh 可以下载libbpf_1.4.7的头部文件，已经下载到当前项目。

先修改成dns域名反转最长匹配的方式：
当前这版“整串反转后做前缀匹配”的实现，a.bb.com 会被 aa.bb.com 误命中。
因为我现在这版是把整串域名直接反转后放进 LPM trie：

规则 a.bb.com -> moc.bb.a
报文 aa.bb.com -> moc.bb.aa
而 moc.bb.a 确实是 moc.bb.aa 的前缀，所以会误匹配。

你这个担心是对的，根因是“字符前缀”不等于“DNS label 边界上的后缀匹配”。我们真正想要的是：
bb.com 能匹配 aa.bb.com
a.bb.com 不能匹配 aa.bb.com

解决方法：
最简单稳妥的办法是把反转 key 做成“带 label 边界终止符”的形式，比如：

规则 a.bb.com -> moc.bb.a.
报文 aa.bb.com -> moc.bb.aa.
规则 bb.com -> moc.bb.

这样：
moc.bb.a. 不是 moc.bb.aa. 的前缀，不会误匹配
moc.bb. 是 moc.bb.aa. 的前缀，仍然能正确命中后缀规则

这样后就不需要用到bfp_loop了。
------------------------------------
用 eBPF 实现对于某些源 IP 网段的某些指定域名 DNS请求打上 mark 54。

`config.json` 支持通过 `domain_match_mode` 配置域名匹配方式：

- `exact`: 精确匹配，`aa.bb.com` 只匹配 `aa.bb.com`
- `longest_suffix`: 最长后缀匹配，`aa.bb.com` 会依次尝试 `aa.bb.com`、`bb.com`、`com`

每条规则可以设置多个 IP 网段和多个域名；当 eBPF 接收到 DNS 请求后，只有在“源 IP 命中任一 CIDR”且“域名按配置模式命中任一规则域名”时，才会给该请求打上 mark 54，然后继续走协议栈。