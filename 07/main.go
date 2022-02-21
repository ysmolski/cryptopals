package main

import (
	"crypto/aes"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

const key = "YELLOW SUBMARINE"

func main() {
	ct, err := tools.ReadBase64File("./7.txt")
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	pt := make([]byte, len(ct))
	tools.ECBDecrypt(block, pt, ct)
	fmt.Println(string(pt))
}
