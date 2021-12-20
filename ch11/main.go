package main

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/ysmolsky/cryptopals/tools"
)

func main() {
	ks := 16
	fill := make([]byte, ks*4)
	ct := tools.ECBCBCEncryptOracle(fill)
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
