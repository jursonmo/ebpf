generate:
	go generate

build: generate
	GOOS=linux GOARCH=amd64 go build -o dns_mark_xdp .

clean:
	rm -f dns_mark_xdp dnsmarkxdp_bpfel.go dnsmarkxdp_bpfeb.go dnsmarkxdp_bpfel.o dnsmarkxdp_bpfeb.o
