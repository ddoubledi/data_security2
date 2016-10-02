package main

import (
	"fmt"
	"net"
	"os"
	// "strings"
	"regexp"
	"github.com/monnand/dhkx"
)

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":7701")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		if conn, err := listener.Accept(); err == nil {
			go handleClient(conn)
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func handleClient(conn net.Conn) {
	hello, _ := regexp.Compile("^client hello")
	done, _ := regexp.Compile("^client done;")
	buf := make([]byte, 128)
	defer conn.Close()
	for {
		readLen, err := conn.Read(buf)
		if err != nil {
			fmt.Println(err)
		}
		if readLen != 0 {
			if hello.MatchString(string(buf)) {
				group, _ := dhkx.GetGroup(0)
				privateKey, _ := group.GeneratePrivateKey(nil)
				publicKey := privateKey.Bytes()
				responce := append([]byte("server hello;"), publicKey...)
				conn.Write([]byte(responce))
			} else if done.MatchString(string(buf)) {
				conn.Write([]byte("server done"))
			}
		}
		buf = make([]byte, 128)
	}
}
