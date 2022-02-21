package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

func main() {
	src, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		log.Fatal(err)
	}
	key := "YELLOW SUBMARINE"
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(src))
	tools.CTREncrypt(block, 0, dst, src)
	fmt.Println(string(dst))
}
