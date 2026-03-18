BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -Wall -target bpf

generate:
	go generate
	# go generate main.go #如果go generate没生成flow_bpfel.go,就指定main.go

build: generate
	GOOS=linux GOARCH=amd64 go build -o flowmon main.go flow_bpfel.go

run:
	sudo ./flowmon

clean:
	rm -f flowmon flow_bpfel.go flow_bpfel.o
