generate:
	go generate

vmlinux:
	bpf2go -go-package=main -tags linux socketredirect bpf/socket_redirect.c -- -I./bpf -I../headers -DVMLINUX_H

buildvmlinux: vmlinux
	GOOS=linux GOARCH=amd64 go build -o socket_redirect .

build: generate
	GOOS=linux GOARCH=amd64 go build -o socket_redirect .

clean:
	rm -f socket_redirect socketredirect_bpfel.go socketredirect_bpfeb.go socketredirect_bpfel.o socketredirect_bpfeb.o
