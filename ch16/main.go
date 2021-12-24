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

func EncryptOracle(input []byte) ([]byte, []byte) {
	src := append([]byte(prefix), input...)
	src = append(src, []byte(suffix)...)

	ks := len(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	src = tools.PadPKCS7(src, ks)
	dst := make([]byte, len(src))
	iv := tools.RandBytes(16)
	tools.CBCEncrypt(block, iv, dst, src)
	return dst, iv
}

const adminCheck = ";admin=true;"

func DecryptOracle(ct, iv []byte) bool {

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(ct))
	tools.CBCDecrypt(block, iv, dst, ct)
	pt, err := tools.UnpadPKCS7(dst)
	if err != nil {
		log.Fatal(err)
	}
	return strings.Contains(string(pt), adminCheck)
}

func main() {
	ct, iv := EncryptOracle([]byte("test0000000000003admin=true"))

	// 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
	// comment1=cooking %20MCs;userdata= test000000000000 3admin=true;comm ent2=%20like%20a%20pound%20of%20bacon
	forge := byte(';') ^ byte('3')
	ct[32] ^= forge
	isAdmin := DecryptOracle(ct, iv)
	fmt.Printf("isAdmin = %+v\n", isAdmin)
}
