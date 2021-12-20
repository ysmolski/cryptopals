package main

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

func ECBCBCEncryptOracle(input []byte) []byte {
	prefix := tools.RandBytes(int(tools.RandByte()%6) + 5)
	suffix := tools.RandBytes(int(tools.RandByte()%6) + 5)
	res := make([]byte, len(prefix)+len(input)+len(suffix))

	copy(res, prefix)
	copy(res[len(prefix):], input)
	copy(res[len(prefix)+len(input):], suffix)

	ks := 16
	key := tools.RandBytes(ks)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	mode := tools.RandByte() % 2
	res = tools.PadPKCS7(res, ks)
	dst := make([]byte, len(res))
	if mode == 0 {
		tools.ECBEncrypt(block, dst, res)
	} else {
		IV := tools.RandBytes(ks)
		tools.CBCEncrypt(block, IV, dst, res)
	}
	return dst
}

func main() {
	ks := 16
	fill := make([]byte, ks*4)
	ct := ECBCBCEncryptOracle(fill)
	fmt.Println("ct = ")
	for i := 0; i < len(ct)/ks; i++ {
		fmt.Printf("     %#v\n", hex.EncodeToString(ct[i*ks:(i+1)*ks]))
	}
	ecb := false
	for i := 0; i < len(ct)/ks-1; i++ {
		for j := i + 1; j < len(ct)/ks; j++ {
			a := ct[i*ks : (i+1)*ks]
			b := ct[j*ks : (j+1)*ks]
			if bytes.Equal(a, b) {
				ecb = true
			}
		}
	}

	if ecb {
		fmt.Println("ECB detected")
	} else {
		fmt.Println("ECB was not detected")
	}
}
