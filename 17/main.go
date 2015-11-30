package main

/*
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions), pad the
string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it,
check its padding, and return true or false depending on whether the padding is valid.
*/

import (
	"crypto/aes"
	"cryptopals/util"
	"encoding/base64"
	"fmt"
	"log"
)

var (
	key  = util.RandAes128()
	msgs = []string{
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
)

func getMsg() (ct, iv []byte) {
	ct, err := base64.StdEncoding.DecodeString(msgs[util.RandByte()%10])
	if err != nil {
		log.Fatal("Cannot decode", err)
	}
	iv = util.RandAes128()
	block, _ := aes.NewCipher(key)
	fmt.Println("before padding", len(ct))
	ct = util.PadTo(ct, block.BlockSize())
	fmt.Println("after padding", len(ct))
	util.CBCEncrypt(block, iv, ct, ct)
	return ct, iv
}

func isPadValid(ct, iv []byte) bool {
	block, _ := aes.NewCipher(key)
	res := make([]byte, len(ct))
	copy(res, ct)
	util.CBCDecrypt(block, iv, res, res)
	_, err := util.CheckPadding(res)
	return err == nil
}

func main() {
	ct, iv0 := getMsg()
	// attack 2nd block
	iv0 = ct[:16]
	ct = ct[16:32]
	plain := make([]byte, len(ct))
	for i := 15; i >= 0; i-- {
		iv := make([]byte, len(iv0))
		copy(iv, iv0)
		pad := byte(16 - i)
		for j := i + 1; j < 16; j++ {
			iv[j] = iv0[j] ^ plain[j] ^ pad
		}
		found := false
		for g := 0; g < 256; g++ {
			iv[i] = iv0[i] ^ byte(g) ^ pad
			valid := isPadValid(ct, iv)
			if valid {
				plain[i] = byte(g)
				found = true
				fmt.Println(i, pad, "iv:", iv)
				break
			}
		}
		if !found {
			fmt.Println("cannot find", i, "th byte")
			break
		}
	}
	fmt.Println(string(plain))
}
