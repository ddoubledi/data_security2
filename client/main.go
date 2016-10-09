package main

import (
	"bufio"
	"fmt"
	"net"

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
	conn.Write([]byte(login))
	// response := make([]byte, 128)
	// for {
	// 	readLen, err := conn.Read(response)
	// 	utils.CheckError(err)
	// 	response, err = utils.Decrypt(sessionKey, response)
	// 	utils.CheckError(err)
	// 	if readLen != 0 {
	// 		fmt.Println(string(response))
	// 		scanner.Scan()
	// 		choice := scanner.Text()
	// 		encryptedChoice, err := utils.Encrypt(sessionKey, []byte(choice))
	// 		utils.CheckError(err)
	// 		conn.Write([]byte(encryptedChoice))
	// 		response = make([]byte, 128)
	// 	}
	// }
}
