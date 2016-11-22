package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/ddoubledi/data_security2/utils"

	"os"
)

func main() {
	fmt.Println("Enter your login")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	login := scanner.Text()
	fmt.Println("Start speak with key server")
	sessionKey, conn := utils.ConnectToKeyServer(login)
	conn.Close()
	fmt.Println("sessionKey:", string(sessionKey))
	workWithMainServer(sessionKey, login)
}

func workWithMainServer(sessionKey []byte, login string) {
	fmt.Println("Start speak with server")
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7700")
	utils.CheckError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	utils.CheckError(err)
	utils.Write([]byte(login), conn)
	buf := utils.Read(conn)
	res := strings.Split(string(buf), "\r\n")

	if string(res[0]) == "good" {
		fmt.Println("Nice")
		fmt.Println("My sessionKey:", string(sessionKey))
	}

	utils.WriteSecure([]byte("hi server"), conn, sessionKey)
	buf, _ = utils.ReadSecure(conn, sessionKey)
	res = strings.Split(string(buf), "\r\n")

	if string(res[0]) == "hi "+login {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			buf, _ := utils.ReadSecure(conn, sessionKey)
			res := strings.Split(string(buf), "\r\n")
			fmt.Println("buff:", res)
			fmt.Println(string(res[0]))
			if len(res) > 1 {
				fmt.Println("func:", res[1])
				switch res[1] {
				case "q":
					fmt.Print("Buy")
					return
				case "g":
					file := []byte(res[2])
					err := ioutil.WriteFile("./file", file, 0644)
					utils.CheckError(err)
				}
			}
			scanner.Scan()
			choice := scanner.Text()
			utils.WriteSecure([]byte(choice), conn, sessionKey)
		}
	}
}
