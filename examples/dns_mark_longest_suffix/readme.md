TODO: 目前还没解决 加载 BPF 对象失败: field DnsMark: program dns_mark: load program: argument list too long: BPF program is too large. Processed 1000001 insn (38422 line(s) omitted)

用 eBPF 实现对于某些源 IP 网段的某些指定域名 DNS请求打上 mark 54。

`config.json` 支持通过 `domain_match_mode` 配置域名匹配方式：

- `exact`: 精确匹配，`aa.bb.com` 只匹配 `aa.bb.com`
- `longest_suffix`: 最长后缀匹配，`aa.bb.com` 会依次尝试 `aa.bb.com`、`bb.com`、`com`

每条规则可以设置多个 IP 网段和多个域名；当 eBPF 接收到 DNS 请求后，只有在“源 IP 命中任一 CIDR”且“域名按配置模式命中任一规则域名”时，才会给该请求打上 mark 54，然后继续走协议栈。