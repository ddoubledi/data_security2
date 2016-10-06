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

	"github.com/ddoubledi/data_security2/utils"
	"github.com/monnand/dhkx"
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

func getUsersFromFile(filename string) {
	dat, err := ioutil.ReadFile(filename)
	checkError(err)
	userPass := strings.Split(string(dat), "\n")
	for i := 0; i < len(userPass)-1; i++ {
		splitedUserPass := strings.Split(userPass[i], ";")
		fmt.Println(splitedUserPass)
		role, err := strconv.ParseBool(splitedUserPass[2])
		checkError(err)
		blocked, err := strconv.ParseBool(splitedUserPass[3])
		checkError(err)
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
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
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
	checkError(err)
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

func handleClient(conn net.Conn, userMap map[string]string) {
	// request := make([]byte, 128) // set maximum request length to 128KB to prevent flood based attacks
	// currentMenu := "hello"
	// defer conn.Close() // close connection before exit
	// conn.Write([]byte(getCurrentMenu(&currentMenu, "")))
	// for {
	// 	readLen, err := conn.Read(request)
	// 	checkError(err)
	// 	conn.Write([]byte(getCurrentMenu(&currentMenu, string(request[:readLen]))))
	// 	request = make([]byte, 128)
	// }
	// Need new code Here
	login := utils.Read(conn)
	fmt.Println("Login:", login)
	fmt.Println("sessionKey:", userMap[string(login)])
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

func listenKeyServer(serverSessionKey []byte, conn net.Conn, usersMap map[string]string) {
	fmt.Println("Here")

	for {
		message := utils.ReadSecure(conn, serverSessionKey)
		res := strings.Split(string(message), "\r\n")
		fmt.Println(res)
		usersMap[res[0]] = res[1]
		fmt.Println(usersMap[res[0]])
	}
}

func serverConnectToKeyServer(usersMap map[string]string) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7701")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	checkError(err)
	login := "server"
	// connect to key server and receive session key
	sessionKey := connectToKeyServer(conn, login)

	response := make([]byte, 32)
	fmt.Println("response := make([]byte, 32)")
	readLen, err := conn.Read(response)
	checkError(err)
	fmt.Println("readLen, err := conn.Read(response)")
	var serverSessionKey []byte
	if readLen != 0 {
		fmt.Println("readLen != 0")
		response, err = utils.Decrypt([]byte(sessionKey), response)
		checkError(err)

		serverSessionKey = response
	}
	fmt.Println("Go")
	go listenKeyServer(serverSessionKey, conn, usersMap)
}

func main() {
	// map, that store map[login] = sessionKey
	var usersMap map[string]string
	usersMap = make(map[string]string)
	serverConnectToKeyServer(usersMap)
	getUsersFromFile("./user_db.txt")
	service := ":7700"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, usersMap)
	}

}
