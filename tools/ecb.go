package tools

import (
	"bytes"
	"crypto/cipher"
)

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

func IsECB(ct []byte, ks int) bool {
	for i := 0; i < len(ct)/ks-1; i++ {
		for j := i + 1; j < len(ct)/ks; j++ {
			a := ct[i*ks : (i+1)*ks]
			b := ct[j*ks : (j+1)*ks]
			if bytes.Equal(a, b) {
				return true
			}
		}
	}
	return false
}
