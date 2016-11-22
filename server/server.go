package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"

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

func register(login string, password string) {
	role := false
	user := User{login, password, role, false}
	userList.PushBack(&user)
}

func blockUser(login string) bool {
	for e := userList.Front(); e != nil; e = e.Next() {
		userElement := e.Value.(*User)
		if login == userElement.name {
			userElement.blocked = true
			return true
		}
	}
	return false

}

func passwordChacker(user *User, conn net.Conn, key []byte, login string, password string) bool {
	var err bool
	for attempts := 0; attempts < 3; attempts++ {
		if attempts != 0 {
			buf, err := utils.ReadSecure(conn, key)
			utils.CheckError(err)
			password = string(buf)
		}
		user = checkUser(login, password)
		if user != nil {
			err = true
			break
		}
		if attempts == 2 {
			conn.Close()
		}
		utils.WriteSecure([]byte("Wrong password. Remain attempts - "+string((3-attempts))), conn, key)
	}
	return err
}

func changePassword(user *User, conn net.Conn, key []byte, password string) bool {
	for attempts := 0; attempts < 3; attempts++ {
		var repassword string
		if attempts != 0 {
			buf, err := utils.ReadSecure(conn, key)
			utils.CheckError(err)
			password = string(buf)
		}
		utils.WriteSecure([]byte("Enter password again"), conn, key)
		buf, err := utils.ReadSecure(conn, key)
		utils.CheckError(err)
		repassword = string(buf)
		if password == repassword {
			user.password = password
			return true
		} else {
			continue
		}
	}
	return false
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
