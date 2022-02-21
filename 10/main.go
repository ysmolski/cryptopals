package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

func main() {
	ct, err := tools.ReadBase64File("./10.txt")
	if err != nil {
		log.Fatal(err)
	}
	pt := make([]byte, len(ct))
	key := "YELLOW SUBMARINE"
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	IV := make([]byte, len(key))
	tools.CBCDecrypt(block, IV, pt, ct)
	fmt.Printf("pt = %#v\n", string(pt))

	// check that if we encrypt and then descrypt the result we would get the
	// same text
	tools.CBCEncrypt(block, IV, ct, pt)
	pt2 := make([]byte, len(ct))
	tools.CBCDecrypt(block, IV, pt2, ct)
	fmt.Printf("pt2 = %#v\n", string(pt2))

	fmt.Println(bytes.Compare(pt, pt2) == 0)
}
