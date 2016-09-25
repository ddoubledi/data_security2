package main

import (
	"fmt"
	"net"
	"bufio"
)


func runServer() {
	fmt.Println("Launching server...")

	// listen on all interfaces
	ln, _ := net.Listen("tcp", ":7700")

	// accept connection on port
	conn, _ := ln.Accept()

	// run loop forever (or until ctrl-c)
	for {
		// will listen for message to process ending in newline (\n)
		message, _ := bufio.NewReader(conn).ReadString('\n')
		// output message received
		userMessage := int(message)
		fmt.Print("Message Received:", int(message))

		// handle received string, then run necessary command (execute function)
		// switch for console menu
		switch userMessage {
		case "1":

		}

		// send result of processing
		conn.Write([]byte(userMessage + "\n"))
	}
}
