package main

import (
	"container/list"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/ddoubledi/data_security2/utils"
)

// User type
type User struct {
	name     string
	password string
	role     bool
	blocked  bool
}

func (u *User) String() string {
	return u.name + ";" + u.password + ";" + strconv.FormatBool(u.role) + ";" + strconv.FormatBool(u.blocked) + "\n"
}

var userList = list.New()
var userMap = map[string]string{}
var lock = sync.RWMutex{}

func handleClient(conn net.Conn) {
	buf := utils.Read(conn)
	login := strings.Split(string(buf), "\r\n")[0]

	// check if user exist
	if !userExist(login) {
		conn.Close()
	}

	// TODO: send good message with hash of info
	utils.Write([]byte("good"), conn)
	fmt.Println("Login:", string(login))
	lock.Lock()
	sessionKey := []byte(userMap[string(login)])
	lock.Unlock()
	fmt.Println(string(sessionKey))
	buf, _ = utils.ReadSecure(conn, sessionKey)
	res := strings.Split(string(buf), "\r\n")
	if string(res[0]) == "hi server" {
		user := new(User)
		utils.WriteSecure([]byte("hi "+login), conn, sessionKey)
		fmt.Println("good handshake")
		currentMenu := "password"
		utils.WriteSecure([]byte("Enter your password:"), conn, sessionKey)
		for {
			// get choice from user and than send currentMenu
			buf, err := utils.ReadSecure(conn, sessionKey)
			if err != nil {
				return
			}
			res = strings.Split(string(buf), "\r\n")
			choice := res[0]
			switch currentMenu {
			case "password":
				{
					if passwordChacker(user, conn, sessionKey, login, choice) {
						if user.role {
							currentMenu = "mainMenu"
							utils.WriteSecure([]byte("Hi user:c-change password\ng-get file\nq-exit"), conn, sessionKey)
						} else {
							currentMenu = "adminMenu"
							utils.WriteSecure([]byte("Hi admin:c-change password\ng-get file\nq-exit"), conn, sessionKey)
						}
					} else {
						conn.Close()
					}
				}
			case "mainMenu":
				{
					switch choice {
					case "c":
						currentMenu = "aChangePassword"
						utils.WriteSecure([]byte("Enter password:"), conn, sessionKey)
					case "q":
						currentMenu = "Exit"
						send := append(utils.AddDelimiter([]byte("Buy")), []byte("q")...)
						utils.WriteSecure(send, conn, sessionKey)
					case "g":
						currentMenu = "GetFile"
						send := append(utils.AddDelimiter([]byte("Get file")), []byte("g")...)
						dat, err := ioutil.ReadFile("./file")
						utils.CheckError(err)
						send = append(utils.AddDelimiter(send), []byte(dat)...)
						utils.WriteSecure(send, conn, sessionKey)
					}
				}
			case "adminMenu":
				{
					switch choice {
					case "c":
						currentMenu = "aChangePassword"
						utils.WriteSecure([]byte("Enter password:"), conn, sessionKey)
					case "q":
						currentMenu = "Exit"
						send := append(utils.AddDelimiter([]byte("Buy")), []byte("q")...)
						utils.WriteSecure(send, conn, sessionKey)
						conn.Close()
						return
					case "g":
						currentMenu = "GetFile"
						send := append(utils.AddDelimiter([]byte("Get file")), []byte("g")...)
						dat, err := ioutil.ReadFile("./file")
						utils.CheckError(err)
						send = append(utils.AddDelimiter(send), []byte(dat)...)
						utils.WriteSecure(send, conn, sessionKey)
					}
				}
			case "GetFile":
				{
					currentMenu = "adminMenu"
					utils.WriteSecure([]byte("Hi user:c-change password\ng-get file\nq-exit"), conn, sessionKey)
				}
			case "aChangePassword":
				{
					currentMenu = "adminMenu"
					changePassword(user, conn, sessionKey, choice)
					utils.WriteSecure([]byte("Hi user:c-change password\ng-get file\nq-exit"), conn, sessionKey)
				}
			default:
				utils.WriteSecure([]byte("Invalid choice"), conn, sessionKey)
			}
		}
	}
}

func listenKeyServer(serverSessionKey []byte, conn net.Conn) {
	for {
		message, _ := utils.ReadSecure(conn, serverSessionKey)
		res := strings.Split(string(message), "\r\n")
		lock.Lock()
		fmt.Println("new message: ", res[0], res[1])
		userMap[string(res[0])] = string(res[1])
		lock.Unlock()
	}
}

func main() {
	getUsersFromFile("./user_db.txt")
	service := ":7700"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	utils.CheckError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	utils.CheckError(err)
	sessionKey, conn := utils.ConnectToKeyServer("server")
	fmt.Println("Good, i got some key:")
	fmt.Println(string(sessionKey))
	go listenKeyServer(sessionKey, conn)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn)
	}

}
