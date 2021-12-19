package main

import (
	"crypto/aes"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

type ScoredText struct {
	Score float64
	Text  []byte
}
type scoredKeysize struct {
	dist  float64
	ksize int
}

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
