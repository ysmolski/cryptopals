package main

import (
	"crypto/aes"
	"cryptopals/util"
	"encoding/base64"
	"fmt"
)

func main() {
	key := []byte("YELLOW SUBMARINE")

	encoded := util.ReadFile("7.txt")
	bytes, _ := base64.StdEncoding.DecodeString(string(encoded))

	fmt.Println(len(bytes))
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	// dst := make([]byte, 16)
	for i := 0; i < len(bytes); i += 16 {
		block.Decrypt(bytes[i:i+16], bytes[i:i+16])
	}
	fmt.Println(string(bytes))
}
