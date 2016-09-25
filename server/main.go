package main

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
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
		newUser := User{splitedUserPass[0], splitedUserPass[1], false, false}
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

func main() {
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
