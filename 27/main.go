package main

import (
	"crypto/aes"
	"fmt"
	"log"
	"net/url"

	"github.com/ysmolsky/cryptopals/tools"
)

var key []byte

func init() {
	key = tools.RandBytes(16)
}

const prefix = "comment1=cooking%20MCs;userdata="
const suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

func EncryptOracle(input []byte) []byte {
	src := append([]byte(prefix), input...)
	src = append(src, []byte(suffix)...)

	ks := len(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	src = tools.PadPKCS7(src, ks)
	dst := make([]byte, len(src))
	tools.CBCEncrypt(block, key, dst, src)
	return dst
}

const adminCheck = ";admin=true;"

func DecryptOracle(ct []byte) error {

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(ct))
	tools.CBCDecrypt(block, []byte(key), dst, ct)
	pt, err := tools.UnpadPKCS7(dst)
	if err != nil {
		return err
	}
	for i := range pt {
		if pt[i] >= 127 {
			return fmt.Errorf("bad characters: %s", url.QueryEscape(string(pt)))
		}
	}
	return nil
}

func main() {
	ct := EncryptOracle([]byte("test0000000000003admin=true"))

	// 0123456789abcdef 0123456789abcdef 0123456789abcdef 0123456789abcdef
	// comment1=cooking %20MCs;userdata= test000000000000 3admin=true;comm ent2=%20like%20a%20pound%20of%20bacon
	ct0 := make([]byte, len(ct))
	copy(ct0, ct)
	ct = append(ct[:16], append(make([]byte, 16), ct[0:16]...)...)
	ct = append(ct, ct0[80:]...)
	err := DecryptOracle(ct)
	fmt.Printf("Error: %+v\n", err)
	if err != nil {
		rec := err.Error()[len("bad characters: "):]
		rec, err = url.QueryUnescape(rec)
		if err != nil {
			log.Fatal(err)
		}
		key := tools.XorBytes([]byte(rec[:16]), []byte(rec[32:48]))

		// with recovered key let's decrypt the original ct.
		block, err := aes.NewCipher([]byte(key))
		if err != nil {
			log.Fatal(err)
		}
		dst := make([]byte, len(ct0))
		tools.CBCDecrypt(block, []byte(key), dst, ct0)
		pt, err := tools.UnpadPKCS7(dst)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Recovered plaintext:")
		fmt.Println(string(pt))
	}
}
