package main

import (
	"github.com/monnand/dhkx"
	"fmt"
)

func main()  {
	key := getDHKey("7700")

	println("session key = ", key)
}

// So to make everything works you need run this method at the beginning of communication
// between client and server for generating session key
func getDHKey(port string) []byte {
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


