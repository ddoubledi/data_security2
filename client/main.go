package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s host:port ", os.Args[0])
		os.Exit(1)
	}
	service := os.Args[1]

	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	checkError(err)
	request := make([]byte, 128)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		readLen, err := conn.Read(request)
		checkError(err)
		if readLen != 0 {
			// Pring menu
			fmt.Println(request)
			scanner.Scan()
			choice := scanner.Text()
			// Send choice to server
			conn.Write([]byte(choice))
		}
		_, err = conn.Write([]byte("Buy"))
		checkError(err)
		os.Exit(0)
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
