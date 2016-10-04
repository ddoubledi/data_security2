package main

import (
	"bufio"
	"fmt"

	"github.com/ddoubledi/data_security2/utils"
	"github.com/monnand/dhkx"

	"net"
	"os"
	"strings"
)

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7701")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	checkError(err)
	// enter login
	fmt.Println("Enter your login")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	login := scanner.Text()
	// connect to key server and receive session key
	sessionKey := connectToKeyServer(conn, login)

	response := make([]byte, 32)
	readLen, err := conn.Read(response)
	checkError(err)

	var serverSessionKey []byte
	if readLen != 0 {
		response, err = utils.Decrypt([]byte(sessionKey), response)
		checkError(err)

		serverSessionKey = response
	}
	workWithMainServer(serverSessionKey)
}

func workWithMainServer(sessionKey []byte) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":7700")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	checkError(err)

	response := make([]byte, 128)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		readLen, err := conn.Read(response)
		checkError(err)
		response, err = utils.Decrypt(sessionKey, response)
		checkError(err)
		if readLen != 0 {
			fmt.Println(string(response))
			scanner.Scan()
			choice := scanner.Text()
			encryptedChoice, err := utils.Encrypt(sessionKey, []byte(choice))
			checkError(err)
			conn.Write([]byte(encryptedChoice))
			response = make([]byte, 128)
		}
	}
}

func connectToKeyServer(conn net.Conn, login string) []byte {
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	var largeKey []byte
	var sessionKey []byte

	utils.Write(append([]byte("client "), []byte(login)...), conn)

	buf := utils.Read(conn)

	res := strings.Split(string(buf), "\r\n")
	if res[0] == "server hello" {
		bobPubKey := dhkx.NewPublicKey([]byte(res[1]))
		k, _ := group.ComputeKey(bobPubKey, privateKey)
		largeKey = k.Bytes()
	}

	sessionKey = utils.GenerateAESKey(largeKey)

	doneMessage := []byte("client done")
	cipheredDone, err := utils.Encrypt(sessionKey, doneMessage)
	checkError(err)

	utils.Write(append(utils.AddDelimiter(cipheredDone), publicKey...), conn)

	buf = utils.Read(conn)

	res = strings.Split(string(buf), "\r\n")
	decrypted, _ := utils.Decrypt(sessionKey, []byte(res[0]))

	if string(decrypted) == "server done" {
		fmt.Println("Succesful received server done message")
		// everything is ok and return session key
		return sessionKey
	}
	return []byte("wtf")
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	}
}
