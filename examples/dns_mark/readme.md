

帮我在当前目录下实现一个功能：用ebpf实现对于某些源ip网段 的某些指定域名的dns的请求打上mark 53, 即可以配置多条规则，每条规则可以设置多个ip网段，和多个域名，当ebpf 接受到dns 请求后，匹配每条规则，如果匹配中了，打上mark, 返回，让数据继续走协议栈。

---

## 实现说明（与当前代码一致）

### 行为概要

- 使用 **TC clsact + ingress**，在配置里指定的网卡上挂载 eBPF 程序 `dns_mark`（`sched_cls`）。只处理 **IPv4、UDP、目的端口 53** 的报文；解析 DNS 头后仅处理 **查询**（非响应），且要求 **qdcount ≥ 1**。
- 从 DNS 问题区读出 **QNAME**，转成 **小写、点分** 形式（例如 `www.google.com`），在 `domain_rules`（hash）里做 **整名精确匹配**（不是最长后缀匹配；若需要后缀匹配可参考同仓库 `dns_mark_longest_suffix` 示例）。
- 源地址在 `cidr_rules`（LPM trie）里做最长前缀匹配；用户态会把 **较短前缀规则的 bitmask 合并进被其包含的较长前缀**，这样「大网段一条规则 + 子网另一条规则」时，子网内主机仍可同时满足大网段规则上的域名条件（见 `main.go` 中 `rebuildRules` 的注释）。
- 当 **域名 bitmask 与 CIDR bitmask 按位与非 0**（即同属至少一条配置规则）时，设置 `skb->mark`。当前头文件里该值为 **`MARK_NO_REDIRECT` = 54**（用于与 DNS 重定向等场景配合，见 `bpf/dns_mark.h` 注释）；程序退出前会卸载 TC filter / 必要时删除 clsact。

### 配置 `config.json`

- `interface`：挂载 TC ingress 的网卡名（如 `ens2`）。
- `rules`：至少 1 条，最多 **64** 条（bitmask 限制）。每条：
  - `cidrs`：IPv4 CIDR 字符串列表（**仅 IPv4**）。
  - `domains`：域名列表，会转成小写写入 map；与报文里的 **完整 QNAME** 一致时才命中。

示例见仓库内 `config.json`。

### 编译与运行

- 依赖：Linux 内核、eBPF/TC、Clang/llvm、`bpf2go`（通过 `go generate`）、root 权限挂载 TC。
- 在本目录执行：`make generate` 生成 `dnsmark_bpfel.go` 等，再 `make build`（Makefile 中为 `GOOS=linux GOARCH=amd64 go build`）。
- 运行：`sudo ./dns_mark`（默认读当前目录 `config.json`），或 `sudo ./dns_mark /path/to/config.json`。

### 热加载规则

- 进程启动后在本机 **`127.0.0.1:18080`** 提供 HTTP 接口：`POST /reload` 会重新读取**启动时同一个配置文件路径**（若通过命令行指定则仍是该路径），更新 map。**不允许**在 reload 时修改 `interface`（需改网卡应退出程序后重新挂载）。

### 调试与卸载

- 可选：`bpf_printk` 日志可通过 `trace_pipe` 查看（见 `bpf/dns_mark.c` 注释）。
- 卸载：Ctrl-C 退出程序会尝试删除 filter 与 clsact；也可用手动 `tc filter del`、`tc qdisc del` 等（详见 `main.go` 内注释示例）。