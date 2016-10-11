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

func getUsersFromFile(filename string) {
	dat, err := ioutil.ReadFile(filename)
	utils.CheckError(err)
	userPass := strings.Split(string(dat), "\n")
	for i := 0; i < len(userPass) - 1; i++ {
		splitedUserPass := strings.Split(userPass[i], ";")
		fmt.Println(splitedUserPass)
		role, err := strconv.ParseBool(splitedUserPass[2])
		utils.CheckError(err)
		blocked, err := strconv.ParseBool(splitedUserPass[3])
		utils.CheckError(err)
		newUser := User{splitedUserPass[0], splitedUserPass[1], role, blocked}
		userList.PushBack(&newUser)
	}
}

func handleClient(conn net.Conn) {
	res := utils.Read(conn)
	login := strings.Split(string(res), "\r\n")[0]
	// TODO: send good message with hash of info
	utils.Write([]byte("good"), conn)
	fmt.Println("Login:", string(login))
	lock.Lock()
	sessionKey := []byte(userMap[string(login)])
	lock.Unlock()
	fmt.Println(string(sessionKey))
	var user User
	for attempts := 0; attempts < 3; attempts++ {
		utils.WriteSecureSave([]byte("Enter password:"), conn, sessionKey)
		fmt.Println("Enter password:")
		password := utils.ReadSecureSave(conn, sessionKey)
		user = checkUser(login, password)
		if user != nil {
			break
		}
		if attempts == 2 {
			conn.Close()
			return
		}
		utils.WriteSecureSave([]byte("Wrong password. Remain attempts - " + (3 - attempts)), conn, sessionKey)
	}

	// TODO: here is must be: getCurrentMenu() and then
	user = loginChoices()

	for {
		utils.WriteSecureSave([]byte("Hi " + user.name + "\nEnter choice:"), conn, sessionKey)
		choice := utils.ReadSecureSave(conn, sessionKey)
		if user.role {
			if choice == "r" {
				register()
			}
		}
	}
}


func listenKeyServer(serverSessionKey []byte, conn net.Conn) {
	for {
		message := utils.ReadSecure(conn, serverSessionKey)
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
