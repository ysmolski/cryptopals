package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"log"
	"os"

	"github.com/ysmolsky/cryptopals/tools"
)

var key []byte
var unknown []byte

func init() {
	key = tools.RandBytes(16)
	var err error
	unknown, err = tools.ReadBase64File("./12.txt")
	if err != nil {
		panic("cannot read uknown from a file")
	}
}

func EncryptOracle(input []byte) []byte {
	src := append(input, unknown...)

	ks := len(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	src = tools.PadPKCS7(src, ks)
	dst := make([]byte, len(src))
	tools.ECBEncrypt(block, dst, src)
	return dst
}

func blockSize() int {
	// determine block size
	sz := 0
	prevLen := len(EncryptOracle(make([]byte, 1)))
	for i := 2; i < 32; i++ {
		ct := EncryptOracle(make([]byte, i))
		if prevLen != len(ct) {
			sz = len(ct) - prevLen
			break
		}
	}
	return sz
}

func main() {
	sz := blockSize()
	fmt.Println("Block size =", sz)

	ct := EncryptOracle(make([]byte, sz*4))
	if !tools.IsECB(ct, sz) {
		panic("Not ECB")
	}
	fmt.Println("ECB detected.")
	ct = EncryptOracle(make([]byte, 0))
	max := len(ct)
	fmt.Println("Length of unknown msg =", max)

	fill := make([]byte, sz)
	cracked := make([]byte, max)
	for bl := 0; bl < max/sz; bl++ {
		// fmt.Println("block #", bl)
		for i := 1; i < 17 && bl*sz+i-1 < max; i++ {
			// position in cracked
			pos := bl*sz + i - 1
			if pos >= max {
				break
			}
			if bl == 0 {
				copy(fill[len(fill)-i:], cracked[:i])
			} else {
				copy(fill, cracked[pos-sz+1:pos])
			}
			ct := EncryptOracle(fill[:sz-i])
			// fmt.Println("cracked=", cracked, "fill=", fill)
			ideal := ct[bl*sz : (bl+1)*sz]

			// Determine the last byte by trying all possible values and comparing
			// resulting ct with ideal.
			found := false
			for b := 0; b < 256; b++ {
				fill[sz-1] = byte(b)
				ct := EncryptOracle(fill)
				if bytes.Equal(ideal, ct[:sz]) {
					cracked[pos] = byte(b)
					// fmt.Printf("found pos %d byte %c\n", pos, byte(b))
					found = true
					break
				}
			}
			if !found {
				fmt.Println("Cannot find byte at pos", pos)
				if len(cracked)-pos < 16 {
					fmt.Printf("Only %d bytes left... maybe it's padding?\n", len(cracked)-pos)
					fmt.Printf("cracked:\n%#v\n", string(cracked))
					break
				}
				fmt.Println(string(cracked))
				os.Exit(1)
			}
		}
	}
}
