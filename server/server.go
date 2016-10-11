package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/ddoubledi/data_security2/utils"
)

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

func pushUsersToFile(filename string) {
	var buffer bytes.Buffer
	for e := userList.Front(); e != nil; e = e.Next() {
		userElement := e.Value.(*User)
		buffer.Write([]byte(userElement.String()))
	}
	err := ioutil.WriteFile(filename, []byte(buffer.String()), 0644)
	utils.CheckError(err)
}
