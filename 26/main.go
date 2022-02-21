package main

import (
	"crypto/aes"
	"fmt"
	"log"
	"strings"

	"github.com/ysmolsky/cryptopals/tools"
)

var key []byte

func init() {
	key = tools.RandBytes(16)
}

const prefix = "comment1=cooking%20MCs;userdata="
const suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

func EncryptOracle(input []byte) ([]byte, uint64) {
	src := append([]byte(prefix), input...)
	src = append(src, []byte(suffix)...)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(src))
	iv := uint64(12392323)
	tools.CTREncrypt(block, iv, dst, src)
	return dst, iv
}

const adminCheck = ";admin=true;"

func DecryptOracle(ct []byte, iv uint64) bool {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(ct))
	tools.CTREncrypt(block, iv, dst, ct)
	fmt.Println(string(dst))
	return strings.Contains(string(dst), adminCheck)
}

func main() {
	ct, iv := EncryptOracle([]byte("test0000000000003admin=true"))

	// 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
	// comment1=cooking %20MCs;userdata= test000000000000 3admin=true;comm ent2=%20like%20a%20pound%20of%20bacon
	forge := byte(';') ^ byte('3')
	ct[48] ^= forge
	isAdmin := DecryptOracle(ct, iv)
	fmt.Printf("isAdmin = %+v\n", isAdmin)
}
