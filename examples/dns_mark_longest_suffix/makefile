generate:
	go generate

build: generate
	GOOS=linux GOARCH=amd64 go build -o dns_mark .

bpf_loop_generate:
	bpf2go -tags linux dnsmark bpf/dns_mark_bpf_loop.c -- -I./bpf -I../headers

buildbpfloop: bpf_loop_generate
	GOOS=linux GOARCH=amd64 go build -o dns_mark_bpf_loop .

clean:
	rm -f dns_mark dns_mark_bpf_loop dnsmark_bpfel.go dnsmark_bpfeb.go dnsmark_bpfel.o dnsmark_bpfeb.o
