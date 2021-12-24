package tools

import (
	"crypto/cipher"
	"encoding/binary"
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
	var count uint64
	key := make([]byte, sz)
	for i := 0; i < len(src); i += sz {
		// derive a key
		binary.PutUvarint(buf[8:sz], count)
		block.Encrypt(key, buf)

		h := i + sz
		if h > len(src) {
			h = len(src)
		}
		copy(dst[i:h], src[i:h])
		XorBytesInplace(dst[i:h], key)
		count++
	}
	// erase key buffer
	copy(key, buf)
}
