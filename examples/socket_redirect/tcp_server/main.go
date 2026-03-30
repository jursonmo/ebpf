package main

import (
	"bufio"
	"log"
	"net"
	"strings"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		log.Fatalf("listen 9090 failed: %v", err)
	}
	defer ln.Close()

	log.Println("tcp_server listening on 127.0.0.1:9090")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept failed: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	msg, err := r.ReadString('\n')
	if err != nil {
		log.Printf("read failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	msg = strings.TrimSpace(msg)
	log.Printf("received from %s: %q", conn.RemoteAddr(), msg)

	if strings.EqualFold(msg, "hello") {
		if _, err := conn.Write([]byte("hell word\n")); err != nil {
			log.Printf("write response failed: %v", err)
			return
		}
		log.Printf("responded to %s with %q", conn.RemoteAddr(), "hell word")
		return
	}

	if _, err := conn.Write([]byte("unexpected message\n")); err != nil {
		log.Printf("write fallback failed: %v", err)
	}
}
