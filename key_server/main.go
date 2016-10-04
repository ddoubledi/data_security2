package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/ddoubledi/data_security2/utils"
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
	}
}

func handleClient(conn net.Conn) bool {
	hello, _ := regexp.Compile("^client hello")
	done, _ := regexp.Compile("^client done$")

	defer conn.Close()

	// TODO refactor this
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	for {
		buf := utils.Read(conn)
		res := strings.Split(string(buf), "\r\n")
		if hello.MatchString(string(res[0])) {
			utils.Write(append(utils.AddDelimiter([]byte("server hello")), publicKey...), conn)
		} else if len(res) > 2 {
			x := dhkx.NewPublicKey([]byte(res[1]))
			k, _ := group.ComputeKey(x, privateKey)

			sessionKey := utils.GenerateAESKey(k.Bytes()) // TODO
			fmt.Println("Session key: ", sessionKey)

			message, err := utils.Decrypt(sessionKey, []byte(res[0]))
			if err != nil {
				fmt.Println(err)
				break
			}

			if done.MatchString(string(message)) {
				serverDone := []byte("server done")

				encryptedDoneMessage, err := utils.Encrypt(sessionKey, serverDone)
				if err != nil {
					fmt.Println(err)
					break
				}

				utils.Write(encryptedDoneMessage, conn)
				conn.Close()
				break
			}
		}
		buf = make([]byte, 256)
	}
	return false
}
