package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/ysmolsky/cryptopals/tools"
)

var (
	key   []byte
	nonce uint64
	ct    []byte
)

func init() {
	key = tools.RandBytes(16)

	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	var n int
	nonce, n = binary.Uvarint(buf)
	if n <= 0 {
		panic("cannot encode buf into nonce")
	}

	pt, err := tools.ReadBase64File("./25.txt")
	if err != nil {
		log.Fatal(err)
	}
	{
		block, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
		if err != nil {
			log.Fatal(err)
		}
		pt0 := make([]byte, len(pt))
		tools.ECBDecrypt(block, pt0, pt)
		pt = pt0
	}

	ct = make([]byte, len(pt))
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	tools.CTREncrypt(block, nonce, ct, pt)
}

func apiEdit(offset uint64, newtext []byte) []byte {
	tools.CTREdit(ct, key, nonce, offset, newtext)
	// ct is global but we return it anyway
	return ct
}

func main() {
	// fmt.Printf("ct = %#x\n", string(ct[:60]))
	// apiEdit(1, []byte("1234567890123456789012345678901234567890"))
	// fmt.Printf("ct = %#x\n", string(ct[:60]))
	save := make([]byte, len(ct))
	copy(save, ct)
	dummy := make([]byte, len(ct))
	apiEdit(0, dummy)
	fmt.Printf("ct = %#x\n", string(ct[:50]))
	// ct contains A encrypted with key, we can recover pt now
	for i := 0; i < len(ct); i++ {
		save[i] ^= ct[i]
	}
	fmt.Println(string(save))
}
