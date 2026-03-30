package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

func main() {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 3*time.Second)
	if err != nil {
		log.Fatalf("dial 8080 failed: %v", err)
	}
	defer conn.Close()

	log.Println("connected to 127.0.0.1:8080")

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		log.Fatalf("send hello failed: %v", err)
	}
	log.Println("sent: hello")

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatalf("read response failed: %v", err)
	}

	reply = strings.TrimSpace(reply)
	fmt.Printf("recv: %s\n", reply)
}
