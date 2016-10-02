package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"regexp"
	"github.com/monnand/dhkx"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"encoding/base64"
	"io"
)

func main() {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", ":7701")
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		if conn, err := listener.Accept(); err == nil {
			go handleClient(conn)
		}
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func handleClient(conn net.Conn) {
	hello, _ := regexp.Compile("^client hello")
	done, _ := regexp.Compile("^client done$")

	buf := make([]byte, 128)
	defer conn.Close()

	// TODO refactor this
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	for {
		readLen, err := conn.Read(buf)
		if err != nil {
			fmt.Println(err)
		}
		if readLen != 0 {
			res := strings.Split(string(buf), ";")

			if hello.MatchString(string(res[0])) {
				responce := append([]byte(";"), publicKey...)
				conn.Write([]byte(responce))
			}

			k, _ := group.ComputeKey(dhkx.NewPublicKey([]byte(res[1])), privateKey)
			sessionKey := generateAESKey(k.Bytes())
			message, _ := decrypt(sessionKey, []byte(res[0]))

			if done.MatchString(string(message)) {
				conn.Write([]byte("server done"))
			}
		}
		buf = make([]byte, 128)
	}
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

func generateAESKey(largeKey []byte) []byte {
	key := make([]byte, 32)

	key = largeKey[78:110]
	for i := range key {
		key[i] += largeKey[i + 10]
	}

	return key
}
