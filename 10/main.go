package main

import (
	"crypto/aes"
	"cryptopals/util"
	"encoding/base64"
	"fmt"
)

func main() {
	encoded := util.ReadFile("10.txt")
	src, _ := base64.StdEncoding.DecodeString(string(encoded))
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	util.CBCDecrypt(block, iv, src, src)
	util.CBCEncrypt(block, iv, src, src)
	util.CBCDecrypt(block, iv, src, src)

	fmt.Println(string(src))
}
