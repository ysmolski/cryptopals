// Hashing with CBC-MAC
// Sometimes people try to use CBC-MAC as a hash function.
// Hash functions are often used for code verification. This snippet of JavaScript (with newline):
//		alert('MZA who was that?');
// Hashes to 296b8d7cb78a243dda4d0a61d33bbdd1 under CBC-MAC with a key of "YELLOW SUBMARINE" and a 0 IV.
// Forge a valid snippet of JavaScript that alerts "Ayo, the Wu is back!" and hashes to the same value.
// Ensure that it runs in a browser.

package main

import (
	"crypto/aes"
	"fmt"
	"log"
	"os"
	"tools"
)

func CBCMAC(msg, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	k := block.BlockSize()
	if k != len(iv) {
		panic("iv size is not equal the size of key")
	}
	if len(msg)%k != 0 {
		panic("msg is not padded to the block size")
	}
	ct := make([]byte, len(msg))
	tools.CBCEncrypt(block, iv, ct, msg)
	n := len(ct) / k
	return ct[k*(n-1) : k*n]
}

var key = []byte("YELLOW SUBMARINE")

func main() {
	iv := make([]byte, 16)
	msg := []byte("alert('MZA who was that?');\n")
	msgPadded := tools.PadPKCS7(msg, 16)
	mac := CBCMAC(msgPadded, key, iv)
	fmt.Printf("mac = %+x\n", mac)

	msg2 := []byte("alert('Ayo, the Wu is back!');\n//")
	msgPadded2 := tools.PadPKCS7(msg2, 16)
	mac2 := CBCMAC(msgPadded2, key, iv)
	fmt.Printf("mac2 = %+x\n", mac2)

	tools.XorBytesInplace(msgPadded, mac2)

	forgery := append(msgPadded2, msgPadded...)
	fmt.Printf("forgery = %+q\n", forgery)

	forgeMac := CBCMAC(forgery, key, iv)

	fmt.Printf("forgery mac = %+x\n", forgeMac)

	forgedMsg, _ := tools.UnpadPKCS7(forgery)
	err := os.WriteFile("script.js", forgedMsg, 0777)
	if err != nil {
		log.Fatal(err)
	}
	// open web.html which should open JS that has the same CBC-Mac as the
	// first string
}
