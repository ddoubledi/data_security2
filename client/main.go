package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/monnand/dhkx"
	"io"
	"net"
	"os"
	"strings"
)

func main() {
	service := ":7701"

	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	checkError(err)
	// connect to key server and receive session key
	sessionKey := connectToKeyServer(conn)

	response := make([]byte, 32)
	readLen, err := conn.Read(response)
	checkError(err)

	var serverSessionKey []byte
	if readLen != 0 {
		response, err = decrypt([]byte(sessionKey), response)
		checkError(err)

		serverSessionKey = response
	}

	go workWithMainServer(serverSessionKey)
}

func workWithMainServer(sessionKey []byte) {
	service := "7700"

	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	checkError(err)

	response := make([]byte, 128)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		readLen, err := conn.Read(response)
		checkError(err)
		response, err = decrypt(sessionKey, response)
		checkError(err)
		if readLen != 0 {
			fmt.Println(string(response))
			scanner.Scan()
			choice := scanner.Text()
			encryptedChoice, err := encrypt(sessionKey, []byte(choice))
			checkError(err)
			conn.Write([]byte(encryptedChoice))
			response = make([]byte, 128)
		}
	}
}

func connectToKeyServer(conn net.Conn) []byte {
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	var sessionKey []byte

	conn.Write([]byte("client hello"))
	// must give "server hello" phrase + server public key, ';' delimiter

	for {
		var buf []byte
		readLen, _ := conn.Read(buf)
		if readLen != 0 {
			fmt.Println("I've got this: ", string(buf))

			var largeKey []byte
			// Print response
			fmt.Println(string(buf))
			responseParts := strings.Split(string(buf), ";")
			fmt.Println("Server greeding: ", responseParts[0])
			if responseParts[0] == "server hello" {
				bobPubKey := dhkx.NewPublicKey([]byte(responseParts[1]))
				k, _ := group.ComputeKey(bobPubKey, privateKey)
				largeKey = k.Bytes()
			}

			sessionKey = generateKey(largeKey)

			doneMessage := []byte("client done")
			fmt.Printf("%s\n", doneMessage)
			cipheredDone, err := encrypt(sessionKey, doneMessage)
			checkError(err)

			requestDoneClientMessage := append(append(cipheredDone, []byte(";")...), publicKey...)

			conn.Write([]byte(requestDoneClientMessage))
			break
		}
	}

	for {
		var buf []byte
		readLen, err := conn.Read(buf)
		checkError(err)
		if readLen != 0 {
			fmt.Println("I've got this: ", string(buf))

			decrypted, err := decrypt(sessionKey, buf)
			checkError(err)

			if readLen != 0 {
				fmt.Println(string(decrypted))

				if string(decrypted) == "server done" {
					// everything is ok and return session key
					return sessionKey
				}
			}
		}
	}
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func generateKey(largeKey []byte) []byte {
	key := make([]byte, 32)

	key = largeKey[78:110]
	for i := range key {
		key[i] += largeKey[i+10]
	}

	return key
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
