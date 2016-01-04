package main

import (
	"bytes"
	"crypto/aes"
	"cryptopals/util"
	"fmt"
)

type oracleFunc func(src []byte) []byte

func encryptOracle(src []byte) []byte {
	key := util.RandAes128()
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(src))
	copy(out, src)

	// random prepend and append
	prefixSize := util.RandByte()%10 + 5
	postfixSize := util.RandByte()%10 + 5
	postfix := util.RandBytes(int(postfixSize))
	out = append(util.RandBytes(int(prefixSize)), out...)
	out = append(out, postfix...)
	// padding
	out = util.PadTo(out, 16)
	// fmt.Println("before enc", out)

	// random encryption mode
	mode := util.RandByte()
	if mode%2 == 0 {
		// ecb
		fmt.Println("ecb")
		util.ECBEncrypt(block, out, out)
	} else {
		// cbc
		fmt.Println("cbc")
		iv := util.RandAes128()
		util.CBCEncrypt(block, iv, out, out)
	}
	return out
}

func detectEcb(t []byte, blockSize int) bool {
	size := len(t) / blockSize
	for i := 0; i < size; i++ {
		for j := i + 1; j < size; j++ {
			a := i * blockSize
			b := (i + 1) * blockSize
			c := j * blockSize
			d := (j + 1) * blockSize
			if bytes.Equal(t[a:b], t[c:d]) {
				// fmt.Println(i, j)
				// fmt.Println(t)
				return true
			}
		}
	}
	return false
}

func checkBlackBox(oracle oracleFunc) {
	input := make([]byte, 64)
	for i := 0; i < 20; i++ {
		out := oracle(input)
		if detectEcb(out, 16) {
			fmt.Println("   ecb")
		} else {
			fmt.Println("   cbc")
		}
	}
}

func main() {
	checkBlackBox(encryptOracle)
}
