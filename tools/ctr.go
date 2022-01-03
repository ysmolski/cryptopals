package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"log"
)

func CTREncrypt(block cipher.Block, nonce uint64, dst, src []byte) {
	sz := block.BlockSize()
	if sz != 16 {
		panic("CTR mode supports only 128bit keys")
	}
	if len(dst) != len(src) {
		panic("length of dst and src should be equal")
	}
	buf := make([]byte, sz)
	binary.PutUvarint(buf[:8], nonce)
	var counter uint64
	key := make([]byte, sz)
	for i := 0; i < len(src); i += sz {
		// derive a key
		binary.PutUvarint(buf[8:sz], counter)
		block.Encrypt(key, buf)
		// fmt.Printf("i = %d counter = %d key = %#x\n", i, counter, key)

		h := i + sz
		if h > len(src) {
			h = len(src)
		}
		copy(dst[i:h], src[i:h])
		XorBytesInplace(dst[i:h], key)
		counter++
	}
	// erase key buffer
	copy(key, buf)
}

func CTREdit(ct, key []byte, nonce, offset uint64, newtext []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	sz := block.BlockSize()
	pt2 := make([]byte, len(ct))
	copy(pt2[offset:], newtext)
	buf := make([]byte, sz)
	binary.PutUvarint(buf[:8], nonce)
	keystream := make([]byte, sz)
	// fmt.Println(string(pt2))
	counter := offset / uint64(sz)
	end := offset + uint64(len(newtext))
	for i := counter * uint64(sz); i < end; i += uint64(sz) {
		// derive a key
		binary.PutUvarint(buf[8:sz], counter)
		block.Encrypt(keystream, buf)
		// fmt.Printf("i = %d counter = %d key = %#x\n", i, counter, keystream)
		h := int(i) + sz
		if h > len(pt2) {
			h = len(pt2)
		}
		// fmt.Println("i=", i, "h=", h)
		XorBytesInplace(pt2[i:h], keystream)
		counter++
	}
	// fmt.Println(string(pt2))
	copy(ct[offset:end], pt2[offset:end])
}
