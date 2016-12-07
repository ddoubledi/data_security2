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
	connServer, serverKey := handleServer(listener)
	fmt.Println("MainServer Done.")
	connection_per_m := 0
	max_connections := 100
	go func() {
		for {
			connection_per_m = 0
			time.Sleep(time.Second * 60)
		}
	}()
	for {
		if conn, err := listener.Accept(); err == nil {
			go handleClient(conn, connServer, serverKey)
			connection_per_m += 1
		}
		if connection_per_m > max_connections {
			return
		}
	}

}

// GenerateRandomBytes gen random string with len(n)
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
				fmt.Println("serverSessionKey:", genString)
				// TODO: Client done?
				return login, []byte(genString)
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
