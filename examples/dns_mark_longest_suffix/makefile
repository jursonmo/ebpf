generate:
	go generate

build: generate
	GOOS=linux GOARCH=amd64 go build -o dns_mark .

clean:
	rm -f dns_mark dnsmark_bpfel.go dnsmark_bpfeb.go dnsmark_bpfel.o dnsmark_bpfeb.o
