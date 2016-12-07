package main

import (
	"net"

	"github.com/ddoubledi/data_security2/utils"
)

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7701")
	utils.CheckError(err)
	for {
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		utils.CheckError(err)
		conn.Write([]byte("sfsdghkgsadadfgsdfgsadfgfg"))
	}
}
