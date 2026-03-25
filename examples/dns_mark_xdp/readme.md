# dns_mark_xdp
其实是dns_xdp, 因为没有mark的操作，只是把dns_mark example 改过来的，所以带上mark. 

基于 XDP 的 DNS 规则匹配与快速转发示例：当 `源IP CIDR` 与 `DNS 域名` 同时命中同一条规则时，程序会通过 `bpf_fib_lookup` 动态查路由，改写源 IP 与二层 MAC，再 `bpf_redirect` 到查询出的出口网卡。这样绕过协议栈。

- 启动：`make build && sudo ./dns_mark_xdp config.json`
- 热更新规则：`curl -X POST http://127.0.0.1:18081/reload`
