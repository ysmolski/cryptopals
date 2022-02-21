package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ysmolsky/cryptopals/tools"
)

func xor_bytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor_bytes works only for equal sized strings")
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

func main() {
	a, err := hex.DecodeString("686974207468652062756c6c277320657965")
	if err != nil {
		panic("a is not hex string")
	}
	b, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	if err != nil {
		panic("b is not hex string")
	}

	c := tools.XorBytes(a, b)
	fmt.Println(hex.EncodeToString(c))
}
