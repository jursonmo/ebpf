BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -Wall -target bpf

generate:
	go generate
	# go generate main.go #如果go generate没生成flow_bpfel.go,就指定main.go

build: generate
	#GOOS=linux GOARCH=amd64 go build -o flowmon *.go #这样会明确编译flow_bpfel.go、flow_bpfeb.go文件, flow_bpfeb.go里的编译条件go:build就不起作用, 这样会编译错误
	#GOOS=linux GOARCH=amd64 go build -o flowmon main.go flow_bpfel.go
	GOOS=linux GOARCH=amd64 go build -o flowmon . # 这样会自动根据代码文件里的编译条件来决定要不要编译该文件。

run:
	sudo ./flowmon

clean:
	rm -f flowmon flow_bpfel.go flow_bpfel.o
