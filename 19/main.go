package main

/*
Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:
19.txt

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.
*/

import (
	"bufio"
	"crypto/aes"
	"cryptopals/util"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

var (
	key    = util.RandAes128()
	nonce  = make([]byte, 16)
	cts    [][]byte
	stream []byte
)

func init() {
	scan := bufio.NewScanner(os.Stdin)
	block, _ := aes.NewCipher(key)
	for scan.Scan() {
		t, _ := base64.StdEncoding.DecodeString(scan.Text())
		util.CTREncrypt(block, nonce, t, t)
		fmt.Println(len(t), hex.EncodeToString(t))
		cts = append(cts, t)
	}
	fmt.Println("ciphertexts:", len(cts))
}

func main() {
	size := 20
	for _, ct := range cts {
		if len(ct) >= size {
			stream = append(stream, ct[:size]...)
		}
	}
	guess := util.BreakRepeatingXor(stream, size)
	fmt.Println("XORing key:", guess)

	for _, ct := range cts {
		pt := util.XorEncrypt(guess, ct[:size])
		fmt.Println(string(pt))
	}
}
