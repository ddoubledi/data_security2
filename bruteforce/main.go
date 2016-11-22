package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/ddoubledi/data_security2/utils"
)

func main() {
	workWithMainServer()
}

func workWithMainServer() {
	login := "user"
	password := ""
	bd := New(false, true, false, 3, 3)
	defer bd.Close()
MainFor:
	for {
		sessionKey, _ := utils.ConnectToKeyServer(login)
		if string(sessionKey) == "wtf" {
			continue MainFor
		}
		tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7700")
		utils.CheckError(err)
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		defer conn.Close()
		utils.CheckError(err)
		utils.Write([]byte(login), conn)
		buf := utils.Read(conn)
		res := strings.Split(string(buf), "\r\n")
		utils.WriteSecure([]byte("hi server"), conn, sessionKey)
		buf, _ = utils.ReadSecure(conn, sessionKey)
		res = strings.Split(string(buf), "\r\n")
		if string(res[0]) == "hi "+login {
			for i := 0; i < 3; i++ {
				buf, _ := utils.ReadSecure(conn, sessionKey)
				res := strings.Split(string(buf), "\r\n")
				fmt.Println(string(res[0]))
				if string(res[0][0]) == "H" {
					break MainFor
				}
				password = bd.Id()
				fmt.Println(password)
				if password == "" {
					break MainFor
				}
				utils.WriteSecure([]byte(password), conn, sessionKey)
			}
		}
		conn.Close()
	}

}
