package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/monnand/dhkx"
)

// DELIMITER best
const DELIMITER string = "\r\n"

// GenerateAESKey boo
func GenerateAESKey(largeKey []byte) []byte {
	key := make([]byte, 32)

	key = largeKey[78:110]
	for i := range key {
		key[i] += largeKey[i+10]
	}

	return key
}

// AddEnd ga
func AddEnd(message []byte) []byte {
	message = AddDelimiter(message)
	return append(message, []byte("end")...)
}

// AddDelimiter na
func AddDelimiter(message []byte) []byte {
	return append(message, []byte(DELIMITER)...)
}

// Write ga
func Write(message []byte, conn net.Conn) {
	// set minimal message len(for better sync) to 256
	message = AddEnd(message)
	message_len := len(message)
	if message_len < 256 {
		tmp := make([]byte, 0, 256)
		message = append(tmp, message[:message_len]...)
	}
	conn.Write(message)
}

// WriteSecure encrypt message and send it.
func WriteSecure(message []byte, conn net.Conn, key []byte) {
	encMessage, err := Encrypt(key, message)
	CheckError(err)
	Write(encMessage, conn)
}

// ReadSecure encrypted message must be on the first position of split - [encMessage\r\nend]
// Than we can split it as usual string.
func ReadSecure(conn net.Conn, key []byte) ([]byte, error) {
	message := Read(conn)
	res := strings.Split(string(message), "\r\n")
	encMessage, err := Decrypt(key, []byte(res[0]))
	return encMessage, err
}

// Read na
func Read(conn net.Conn) []byte {
	buf := make([]byte, 0, 4096) // big buffer
	tmp := make([]byte, 256)     // using small buffer
For:
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break For
		}
		buf = append(buf, tmp[:n]...)
		tmp = make([]byte, 256)
		end := buf[len(buf)-5:]
		if string(end) == "\r\nend" {
			break For
		}

	}
	return buf
}

// Encrypt olo
func Encrypt(key, text []byte) ([]byte, error) {
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

// Decrypt lolo`
func Decrypt(key, text []byte) ([]byte, error) {
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

func ConnectToKeyServer(login string) ([]byte, net.Conn) {
	// connect to key server and scan login
	tcpAddr, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:7701")
	CheckError(err)
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	CheckError(err)

	//receive session key
	group, _ := dhkx.GetGroup(0)
	privateKey, _ := group.GeneratePrivateKey(nil)
	publicKey := privateKey.Bytes()

	var largeKey []byte
	var sessionKey []byte
	var serverSessionKey []byte
	serverSessionKey = make([]byte, 32)
	// write handshake phrase "client {{login}}"
	Write(append([]byte("client "), []byte(login)...), conn)

	buf := Read(conn)

	res := strings.Split(string(buf), "\r\n")
	if res[0] == "server hello" {
		bobPubKey := dhkx.NewPublicKey([]byte(res[1]))
		k, _ := group.ComputeKey(bobPubKey, privateKey)
		largeKey = k.Bytes()
	}

	sessionKey = GenerateAESKey(largeKey)

	doneMessage := []byte("client good")

	cipheredDone, _ := Encrypt(sessionKey, doneMessage)
	// CheckError(err)

	Write(append(AddDelimiter(cipheredDone), publicKey...), conn)

	result, _ := ReadSecure(conn, sessionKey)
	if string(result) == "server good" {
		result, _ := ReadSecure(conn, sessionKey)
		serverSessionKey = []byte(result)
		WriteSecure([]byte("client done"), conn, sessionKey)
		return serverSessionKey, conn
	}
	return []byte("wtf"), conn
}

func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
	}
}
