package main

import (
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/ddoubledi/data_security2/utils"
	"github.com/monnand/dhkx"
)

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":7701")
	utils.CheckError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.CheckError(err)
	// connServer, key := handleServer(listener)
	// for {
	// 	if conn, err := listener.Accept(); err == nil {
	// 		go handleClient(conn, connServer, key)
	// 	}
	// }
	for {
		if conn, err := listener.Accept(); err == nil {
			go handleClient(conn, []byte("s"))
		}
	}
}

func GenerateRandomBytes(n int) string {
	rand.Seed(time.Now().UnixNano())
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func genSecure(conn net.Conn) (string, []byte) {
	hello, _ := regexp.Compile("^client .*")
	done, _ := regexp.Compile("^client good$")
	var login string
	var sessionKey []byte
	// var serverSessionKey []byte

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
				utils.WriteSecure([]byte("server good"), conn, sessionKey)

				// generate random key for client and server
				genString := GenerateRandomBytes(32)
				utils.WriteSecure([]byte(genString), conn, sessionKey)
				// encryptedMessage, err := utils.Encrypt(sessionKey, []byte(genString))
				// utils.CheckError(err)
				// utils.Write(encryptedMessage, conn)
				fmt.Println("genString:", genString)
				// fmt.Println("encryptedMessage:", encryptedMessage)
				// fmt.Println("serverSessionKey:", serverSessionKey)
				//
				// serverDone := []byte("server good")
				// fmt.Println("send fucking server good with key")
				// fmt.Println(string(append(utils.AddDelimiter(serverDone), serverSessionKey...)))
				// utils.WriteSecure(serverSessionKey, conn, sessionKey)
				//
				// endMessage := utils.ReadSecure(conn, sessionKey)
				// res = strings.Split(string(endMessage), "\r\n")
				// if res[0] == "client done" {
				// 	fmt.Println("end here")
				// 	break
				// }
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

// func handleClient(conn net.Conn, connServer net.Conn, key []byte) bool {
// 	login, sessionKey := genSecure(conn)
// 	// send to server about new client
// 	utils.WriteSecure(append(utils.AddDelimiter([]byte(login)), sessionKey...), connServer, key)
// 	conn.Close()
// 	return false
// }
func handleClient(conn net.Conn, key []byte) bool {
	genSecure(conn)
	// send to server about new client
	// utils.WriteSecure(append(utils.AddDelimiter([]byte(login)), sessionKey...), connServer, key)
	conn.Close()
	return false
}
