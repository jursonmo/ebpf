generate:
	go generate

build: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dns_mark .

#CGO_ENABLED=0 明确关闭cgo, 避免编译机器引用了动态库,导致在宿主机上运行报错:/lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found

bpf_longest_generate:
	bpf2go -go-package main -tags linux dnsmark bpf/dns_mark_longest.c -- -I./bpf -I../headers

buildlongest: bpf_longest_generate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dns_mark_longest .

bpf_loop_generate:
	bpf2go -go-package main -tags linux dnsmark bpf/dns_mark_bpf_loop.c -- -I./bpf -I../headers

buildbpfloop: bpf_loop_generate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dns_mark_bpf_loop .

clean:
	rm -f dns_mark dns_mark_bpf_loop dnsmark_bpfel.go dnsmark_bpfeb.go dnsmark_bpfel.o dnsmark_bpfeb.o
