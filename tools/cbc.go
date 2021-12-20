package tools

import "crypto/cipher"

func CBCEncrypt(block cipher.Block, IV, dst, src []byte) {
	sz := block.BlockSize()
	if sz != len(IV) {
		panic("IV length should be equal to block size")
	}
	if len(dst) != len(src) {
		panic("length of dst and src should be equal")
	}
	if len(dst)%sz != 0 {
		panic("dst should be padded to the block size")
	}
	if len(src)%sz != 0 {
		panic("src should be padded to the block size")
	}
	prev := IV
	for i := 0; i < len(src)/sz; i++ {
		x := sz * i
		y := sz * (i + 1)
		copy(dst[x:y], src[x:y])
		XorBytesInplace(dst[x:y], prev)
		block.Encrypt(dst[x:y], dst[x:y])
		prev = dst[x:y]
	}
}

func CBCDecrypt(block cipher.Block, IV, dst, src []byte) {
	sz := block.BlockSize()
	if sz != len(IV) {
		panic("IV length should be equal to block size")
	}
	if len(dst) != len(src) {
		panic("length of dst and src should be equal")
	}
	if len(dst)%sz != 0 {
		panic("dst should be padded to the block size")
	}
	if len(src)%sz != 0 {
		panic("src should be padded to the block size")
	}
	prev := IV
	for i := 0; i < len(src)/sz; i++ {
		x := sz * i
		y := sz * (i + 1)
		copy(dst[x:y], src[x:y])
		block.Decrypt(dst[x:y], dst[x:y])
		XorBytesInplace(dst[x:y], prev)
		prev = src[x:y]
	}
}
