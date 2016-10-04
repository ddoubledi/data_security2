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

const DELIMITER string = "\r\n"

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
	}
}

func handleClient(conn net.Conn) bool {
	hello, _ := regexp.Compile("^client hello")
	done, _ := regexp.Compile("^client done$")

	defer conn.Close()

	// TODO refactor this
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	for {
		buf := read(conn)
		res := strings.Split(string(buf), "\r\n")
		if hello.MatchString(string(res[0])) {
			write(append(addDelimiter([]byte("server hello")), publicKey...), conn)
		} else if len(res) > 2 {
			x := dhkx.NewPublicKey([]byte(res[1]))
			k, _ := group.ComputeKey(x, privateKey)

			sessionKey := generateAESKey(k.Bytes()) // TODO
			fmt.Println("Session key: ", sessionKey)

			message, err := decrypt(sessionKey, []byte(res[0]))
			if err != nil {
				fmt.Println(err)
				break
			}

			if done.MatchString(string(message)) {
				serverDone := []byte("server done")

				encryptedDoneMessage, err := encrypt(sessionKey, serverDone)
				if err != nil {
					fmt.Println(err)
					break
				}

				write(encryptedDoneMessage, conn)
				conn.Close()
				break
			}
		}
		buf = make([]byte, 256)
	}
	return false
}

// TODO: вынести это
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

// TODO: вынести это
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

// TODO: вынести это
func generateAESKey(largeKey []byte) []byte {
	key := make([]byte, 32)

	key = largeKey[78:110]
	for i := range key {
		key[i] += largeKey[i + 10]
	}

	return key
}

// TODO: вынести это
func write(message []byte, conn net.Conn) {
	conn.Write(addEnd(message))
}

// TODO: вынести это
func addEnd(message []byte) []byte {
	message = addDelimiter(message)
	return append(message, []byte("end")...)
}

// TODO: вынести это
func addDelimiter(message []byte) []byte {
	return append(message, []byte(DELIMITER)...)
}

// TODO: вынести это
func read(conn net.Conn) []byte {
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
		buf = append(buf, tmp[:n]...)
		tmp = make([]byte, 256)
		end := buf[len(buf) - 3:]
		if (string(end) == "end") {
			break
		}
	}
	return buf
}
