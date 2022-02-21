package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
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
	f, err := os.Open("./19.txt")
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
	for n, ct := range cts {
		fmt.Printf("\n%2d ", n)
		for i, _ := range ct {
			if i%4 == 0 {
				fmt.Printf("| ")
			}
			st := hex.EncodeToString(ct[i : i+1])
			fmt.Printf("%s ", st)
		}
	}
	fmt.Println("")

	pt0 := []byte("He, too, has been changed in his turn,")

	keyStream := make([]byte, len(pt0))
	copy(keyStream, pt0)
	tools.XorBytesInplace(keyStream, cts[37][:len(pt0)])
	for i := 0; i < len(cts); i++ {
		dst := make([]byte, len(cts[i]))
		copy(dst, cts[i])
		tools.XorBytesInplace(dst, keyStream)
		fmt.Printf("%2d = %#v\n", i, string(dst))
	}

	fmt.Println(string(tools.XorBytes([]byte("\x0b\xd1"),
		tools.XorBytes([]byte("\x1b\xce"), []byte("ss")))))
	// fmt.Println("")
	// keys := make([]byte, 16)
	// for i := 0; i < 16; i++ {
	// 	acc := make([]byte, 0, len(cts))
	// 	for _, ct := range cts {
	// 		acc = append(acc, ct[i])
	// 	}
	// 	scores := tools.BestXorByteKey(acc)
	// 	for _, sc := range scores[:3] {
	// 		fmt.Printf("%d, %f, %#v  %#v\n", i, sc.Score, string(sc.Key), string(sc.Text))
	// 	}
	// 	keys[i] = scores[0].Key
	// 	fmt.Println("")
	// }
	// fmt.Println(keys)

	// dst := make([]byte, len(cts[0]))
	// tools.XorBytesInplace(dst, keys)
	// fmt.Println(string(dst))

}
