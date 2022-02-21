package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

var secrets = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

var key []byte

func init() {
	key = tools.RandBytes(16)
}

func EncryptOracle() ([]byte, []byte) {
	src, err := base64.StdEncoding.DecodeString(secrets[int(tools.RandByte()%10)])
	if err != nil {
		log.Fatal(err)
	}
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

func isPaddingGoodOracle(ct, iv []byte) bool {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(ct))
	tools.CBCDecrypt(block, iv, dst, ct)
	_, err = tools.UnpadPKCS7(dst)
	return err == nil
}

func main() {
	ct, iv := EncryptOracle()
	sz := len(iv)
	pt := make([]byte, len(ct))
	blocks := len(ct) / sz
	// prepend iv to ct and work on it as one long buffer
	ct = append(iv, ct...)
	save := make([]byte, len(ct))
	copy(save, ct)
	fmt.Printf("save = %+v\n", save)

	for bl := 0; bl < blocks; bl++ {
		pos := (bl+1)*sz - 1 // byte we gonna modify
		fmt.Printf("block #%d pos=%d\n", bl, pos)
		pad := byte(1)
		backtrack := false // means that we backtracked and should continue iterating the byte b
		for pos >= bl*sz {
			found := false
			i0 := 0
			if backtrack {
				i0 = int(ct[pos]) + 1
			}
			for i := i0; i <= 255; i++ {
				b := byte(i)
				ct[pos] = b
				ok := isPaddingGoodOracle(ct[sz:(bl+2)*sz], ct[:sz])
				if ok {
					pt[pos] = b ^ pad ^ save[pos]
					fmt.Printf("b = %+v, pt = %#v\n", b, string(pt[pos]))
					found = true
					break
				}
			}
			if found {
				for j := pos; j < (bl+1)*sz; j++ {
					ct[j] ^= pad ^ (pad + 1)
				}
				pos--
				pad++
				backtrack = false
			} else {
				fmt.Println("Not found!")
				ct[pos] = save[pos] // restore currently mangled byte
				pos++
				pad--
				// restore the failed byte to previous value to continue from that value
				ct[pos] ^= pad ^ (pad + 1)
				backtrack = true
			}
		}
	}
	fmt.Printf("plaintext = %#v\n", string(pt))
}
