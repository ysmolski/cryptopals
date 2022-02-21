package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/ysmolsky/cryptopals/tools"
)

var (
	key   []byte
	nonce uint64
	cts   [][]byte
)

func init() {
	key = tools.RandBytes(16)
	nonce = 0
	f, err := os.Open("./20.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	cts = make([][]byte, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		src, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			log.Fatal(err)
		}
		dst := make([]byte, len(src))
		tools.CTREncrypt(block, nonce, dst, src)
		cts = append(cts, dst)
	}
}

func main() {
	minpos := 0
	for n, ct := range cts {
		if len(ct) < len(cts[minpos]) {
			minpos = n
		}
	}
	minlen := len(cts[minpos])
	fmt.Println("minpos =", minpos)
	fmt.Println("minlen =", minlen)

	fmt.Println("")
	keys := make([]byte, minlen)
	for i := 0; i < minlen; i++ {
		acc := make([]byte, 0, len(cts))
		for _, ct := range cts {
			acc = append(acc, ct[i])
		}
		scores := tools.BestXorByteKey(acc)
		for _, sc := range scores[:3] {
			fmt.Printf("%d, %f, %#v  %#v\n", i, sc.Score, string(sc.Key), string(sc.Text))
		}
		if i == 0 {
			keys[i] = scores[2].Key
		} else {
			keys[i] = scores[0].Key
		}
		fmt.Println("")
	}
	fmt.Println(keys)

	for i := 0; i < len(cts); i++ {
		dst := make([]byte, len(cts[i]))
		copy(dst, cts[i])
		tools.XorBytesInplace(dst, keys)
		fmt.Println(string(dst[:len(keys)]))
	}

}
