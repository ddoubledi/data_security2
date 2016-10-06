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
	connServer, key := handleServer(listener)
	for {
		if conn, err := listener.Accept(); err == nil {
			go handleClient(conn, connServer, key)
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	}
}

func genSecure(conn net.Conn) (string, []byte) {
	hello, _ := regexp.Compile("^client .*")
	done, _ := regexp.Compile("^client done$")
	var login string
	var sessionKey []byte

	// TODO refactor this
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	for {
		buf := utils.Read(conn)
		res := strings.Split(string(buf), "\r\n")
		if hello.MatchString(string(res[0])) {
			utils.Write(append(utils.AddDelimiter([]byte("server hello")), publicKey...), conn)
			login = strings.Split(string(res[0]), " ")[1]
			fmt.Println("Login: ", login)
		} else if len(res) > 2 {
			x := dhkx.NewPublicKey([]byte(res[1]))
			k, _ := group.ComputeKey(x, privateKey)

			sessionKey = utils.GenerateAESKey(k.Bytes()) // TODO
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
				fmt.Println("end here")
				break
			}
		}
		buf = make([]byte, 256)
	}
	return login, sessionKey
}

// return *net.TCPListener
func handleServer(listener *net.TCPListener) (net.Conn, []byte) {
	fmt.Println("Connect to server")
	for {
		if conn, err := listener.Accept(); err == nil {
			_, key := genSecure(conn)
			// send to server about new client
			return conn, key
		}
	}
}

func handleClient(conn net.Conn, connServer net.Conn, key []byte) bool {
	login, sessionKey := genSecure(conn)
	// send to server about new client
	utils.WriteSecure(append(utils.AddDelimiter([]byte(login)), sessionKey...), connServer, key)
	conn.Close()
	return false
}
