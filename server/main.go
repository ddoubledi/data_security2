package main

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"io/ioutil"
	"net"
	"os"
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
	for i := 0; i < len(userPass)-1; i++ {
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

func pushUsersToFile(filename string) {
	var buffer bytes.Buffer
	for e := userList.Front(); e != nil; e = e.Next() {
		userElement := e.Value.(*User)
		buffer.Write([]byte(userElement.String()))
	}
	err := ioutil.WriteFile(filename, []byte(buffer.String()), 0644)
	utils.CheckError(err)
}

func checkUser(login string, password string) *User {
	for e := userList.Front(); e != nil; e = e.Next() {
		userElement := e.Value.(*User)
		if (login == userElement.name) && (password == userElement.password) {
			return userElement
		}
	}
	return nil
}

func userExist(login string) bool {
	returnVal := false
	for e := userList.Front(); e != nil; e = e.Next() {
		userElement := e.Value.(*User)
		fmt.Println("login", login)
		fmt.Println("name", userElement.name)
		if login == userElement.name {
			returnVal = true
			break
		}
	}
	return returnVal
}

func login() *User {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter login:")
	scanner.Scan()
	login := scanner.Text()
	fmt.Println("Enter password:")
	scanner.Scan()
	password := scanner.Text()
	user := checkUser(login, password)
	return user
}

func loginChoices() *User {
	scanner := bufio.NewScanner(os.Stdin)

Choices:
	for {
		fmt.Println("Enter choice:")
		scanner.Scan()
		choice := scanner.Text()

		switch choice {
		case "l":
			user := login()
			if user != nil {
				return user
			} else {
				continue Choices
			}
		case "q":
			fmt.Println("quit")
			os.Exit(1)
		default:
			continue Choices
		}
	}
}

func register() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter login:")
	scanner.Scan()
	login := scanner.Text()
	fmt.Println("Enter password:")
	scanner.Scan()
	password := scanner.Text()
	fmt.Println("Enter role:")
	scanner.Scan()
	role, err := strconv.ParseBool(scanner.Text())
	utils.CheckError(err)
	user := User{login, password, role, false}
	userList.PushBack(&user)
}

func preMain() {
	userList.PushBack(&User{"admin", "admin", true, false})
	getUsersFromFile("./user_db.txt")
	pushUsersToFile("./user_dump.txt")
	scanner := bufio.NewScanner(os.Stdin)
	var user *User
	user = loginChoices()

	for {
		fmt.Println("Hi " + user.name)
		fmt.Println("Enter choice:")
		scanner.Scan()
		choice := scanner.Text()
		if user.role {
			if choice == "r" {
				register()
			}
		}
	}
}

func getCurrentMenu(currentMenu *string, choice string) string {
	var returnVal string
	menuValue := *currentMenu
	switch menuValue {
	case "hello":
		{
			*currentMenu = "login"
			returnVal = "Enter your login:"
			break
		}
	case "login":
		{
			if userExist(choice) {
				*currentMenu = "password"
				returnVal = "Enter your password:"
			} else {
				*currentMenu = "hello"
				returnVal = "Incorect login"
			}
			break
		}
	case "password":
		{

		}
	default:
		returnVal = "Invalid choice"
	}
	return returnVal
	// return ""
}

func handleClient(conn net.Conn) {
	login := utils.Read(conn)
	fmt.Println("Login:", string(login))
	lock.RLock()
	sessionKey := userMap[string(login)]
	fmt.Println(sessionKey)
	lock.RUnlock()
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
