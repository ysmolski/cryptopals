package main

import (
	"crypto/aes"
	"cryptopals/util"
	"encoding/base64"
	"fmt"
	"log"
)

var (
	key   = util.RandAes128()
	nonce = make([]byte, 16)
)

func edit(ct []byte, offset int, text []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	t := make([]byte, len(ct))
	util.CTREncrypt(block, nonce, t, ct)
	for i := offset; i < offset+len(text) && i < len(t); i++ {
		t[i] = text[i-offset]
	}
	util.CTREncrypt(block, nonce, ct, t)
}

func main() {
	encoded := util.ReadFile("25.txt")
	bytes, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		log.Fatal(err)
	}
	oldAes, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		log.Fatal(err)
	}
	util.ECBDecrypt(oldAes, bytes, bytes)
	// we have plaintext in bytes

	// encrypt it in CTR mode
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	util.CTREncrypt(block, nonce, bytes, bytes)

	// save the copy
	ct := make([]byte, len(bytes))
	copy(ct, bytes)

	// let's prepare sequence of 0 bytes and replace the text with it
	zeroes := make([]byte, len(bytes))
	edit(bytes, 0, zeroes)
	// result in bytes contains the key
	// let's recover the original plain text:
	for i := 0; i < len(ct); i++ {
		bytes[i] = ct[i] ^ bytes[i]
	}
	fmt.Println(string(bytes))
}
