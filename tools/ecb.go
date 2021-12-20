package tools

import "crypto/cipher"

// ECBDecrypt assumes that dst and src of the same length
func ECBDecrypt(block cipher.Block, dst, src []byte) {
	if len(src) != len(dst) {
		panic("src and dst lengths do not match")
	}
	sz := block.BlockSize()
	for i := 0; i < len(src)/sz; i++ {
		from := i * sz
		to := (i + 1) * sz
		block.Decrypt(dst[from:to], src[from:to])
	}
}

// ECBDecrypt assumes that dst and src of the same length
func ECBEncrypt(block cipher.Block, dst, src []byte) {
	if len(src) != len(dst) {
		panic("src and dst lengths do not match")
	}
	sz := block.BlockSize()
	for i := 0; i < len(src)/sz; i++ {
		from := i * sz
		to := (i + 1) * sz
		block.Encrypt(dst[from:to], src[from:to])
	}
}
