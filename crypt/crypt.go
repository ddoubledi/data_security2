package main

import (
	"github.com/monnand/dhkx"
	"fmt"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"encoding/base64"
	"log"
)

// Instruction:
// 1. Use getDHKey on both sides (client and server), this is for safe exchanging common key
// 2. generateKey, for generating key for AES crypt
// 3. Save key from generateKey, this is session key for user!
// 4. Use methods encrypt and decrypt with stored session key for cypher and decipher your messages

func main() {
	largeKey := getDHKey("7700")

	key := generateKey(largeKey)
	println("session key = ", key)

	//res := encrypt(key, "droch")
	//decrypt(key, res)

	//key := []byte("a very very very very secret key") // 32 bytes
	plaintext := []byte("some really really really long plaintext")
	fmt.Printf("%s\n", plaintext)
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%0x\n", ciphertext)
	result, err := decrypt(key, ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", result)
}

func generateKey(largeKey []byte) []byte {
	key := make([]byte, 32)

	key = largeKey[78:110]
	for i := range key {
		key[i] += largeKey[i + 10]
	}

	return key
}

// So to make everything works you need run this method at the beginning of communication
// between client and server for generating session key
func getDHKey(destination string) []byte {
	// Get a group. Use the default one would be enough.
	group, _ := dhkx.GetGroup(0)

	// Generate a private key from the group.
	// Use the default random number generator.
	privateKey, _ := group.GeneratePrivateKey(nil)

	// Get the public key from the private key.
	publicKey := privateKey.Bytes()

	// Send the public key to
	//Send(port, publicKey)
	fmt.Println("Public key = ", publicKey)

	// Receive a slice of bytes from Bob, which contains Bob's public key
	//b := Recv(port)
	b := publicKey // TODO: delete this bullshit, only for testing!

	// Recover Bob's public key
	bobPubKey := dhkx.NewPublicKey(b)

	// Compute the key
	k, _ := group.ComputeKey(bobPubKey, privateKey)

	// Get the key in the form of []byte
	key := k.Bytes()

	return key
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
