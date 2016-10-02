package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"github.com/monnand/dhkx"
	"strings"
	"crypto/aes"
	"encoding/base64"
	"crypto/rand"
	"io"
	"crypto/cipher"
	"errors"
)

func main() {
	service := "7701"

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
		response, err = decrypt(sessionKey, response)
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
			choice, err = encrypt(sessionKey, choice)
			checkError(err)
			conn.Write([]byte(choice))
			response = make([]byte, 128)
		}
	}
}

func connectToKeyServer(conn net.Conn) string {
	conn.Write([]byte("client hello"))
	var response string // must give "server hello" phrase + server public key, ';' delimiter

	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	readLen, err := conn.Read(response)
	checkError(err)

	var largeKey []byte;
	if readLen != 0 {
		// Print response
		fmt.Println(string(response))
		responseParts := strings.Split(response, ";")

		if (responseParts[0] == "server hello") {
			bobPubKey := dhkx.NewPublicKey(responseParts[1])
			k, _ := group.ComputeKey(bobPubKey, privateKey)
			largeKey = k.Bytes()
		}
	}

	sessionKey := generateKey(largeKey)

	doneMessage := []byte("client done")
	fmt.Printf("%s\n", doneMessage)
	cipheredDone, err := encrypt(sessionKey, doneMessage)
	checkError(err)

	requestDoneClientMessage := cipheredDone + ";" + publicKey

	conn.Write([]byte(requestDoneClientMessage))

	readLen, err = conn.Read(response)
	checkError(err)
	response, err = decrypt(sessionKey, response)
	checkError(err)

	if readLen != 0 {
		fmt.Println(string(response))

		if (string(response) == "server done") {
			// everything is ok and return session key
			return sessionKey
		}
	}

	return "wtf happend while connect to server"
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize + len(b))
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
		key[i] += largeKey[i + 10]
	}

	return key
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
