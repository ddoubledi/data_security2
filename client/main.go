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
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7701")
	checkError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	defer conn.Close()
	checkError(err)
	// connect to key server and receive session key
	fmt.Println("right after connected to socket")
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
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":7700")
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
	conn.Write([]byte("client hello\r\nend"))

	buf := make([]byte, 0, 4096) // big buffer
	tmp := make([]byte, 256)     // using small tmo buffer for demonstrating
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		//fmt.Println("got", n, "bytes.")
		buf = append(buf, tmp[:n]...)
		tmp = make([]byte, 256)
		end := buf[len(buf) - 3:]
		if (string(end) == "end") {
			break
		}
	}
	fmt.Println("I've got (server hello;key;end): ", string(buf))

	var largeKey []byte
	// Print response
	responseParts := strings.Split(string(buf), "\r\n")
	fmt.Println("Server greeding: ", responseParts[0])

	if responseParts[0] == "server hello" {
		fmt.Println("\nServer raw key: ", []byte(responseParts[1]))
		bobPubKey := dhkx.NewPublicKey([]byte(responseParts[1]))
		k, _ := group.ComputeKey(bobPubKey, privateKey)
		largeKey = k.Bytes()
	}

	sessionKey = generateKey(largeKey)

	doneMessage := []byte("client done")
	fmt.Println("\n\nSession key in decrypt: ", sessionKey)
	cipheredDone, err := encrypt(sessionKey, doneMessage)
	checkError(err)
	fmt.Println("\n\nSended raw key: ", publicKey)

	requestDoneClientMessage := append(append(append(cipheredDone, []byte("\r\n")...), publicKey...), []byte("\r\nend")...)
	fmt.Println("\n\n\nbefore writing client done\n\n\n")
	fmt.Println("Request done clien message: ", string(requestDoneClientMessage))
	conn.Write([]byte(requestDoneClientMessage))

	buf = make([]byte, 0, 4096) // big buffer
	tmp = make([]byte, 256)     // using small tmo buffer for demonstrating
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			fmt.Println("here", err)
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		buf = append(buf, tmp[:n]...)
		tmp = make([]byte, 256)
		end := buf[len(buf) - 3:]
		if (string(end) == "end") {
			break
		}
	}
	fmt.Println("I've got this (server done decrypted)")//, string(buf))

	fmt.Println("Session key in decrypt: ", sessionKey)
	decrypted, err := decrypt(sessionKey, buf)
	checkError(err)

	fmt.Println(string(decrypted))

	if string(decrypted) == "server done" {
		fmt.Println("Succesful received server done message")
		// everything is ok and return session key
		return sessionKey
	}
	return []byte("wtf")
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
