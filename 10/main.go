package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

func pad(s string, n int) string {
	if n > len(s) {
		size := n - len(s)
		appendix := make([]byte, size)
		for i := 0; i < size; i++ {
			appendix[i] = byte(size)
		}
		return s + string(appendix)
	}
	return s
}

func readBase64Stdin() []byte {
	scan := bufio.NewScanner(os.Stdin)
	bytes := make([]byte, 0, 1024)

	for scan.Scan() {
		input := scan.Text()
		bs, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		bytes = append(bytes, bs...)
	}
	return bytes

}

func CBCDecrypt(block cipher.Block, iv, dst, src []byte) {
	size := block.BlockSize()
	if len(iv) != size {
		panic("size of IV not equal to block size")
	}
	if len(dst)%size != 0 {
		panic("size of dst and src should be multiples of blocksize")
	}
	if len(dst) == 0 || len(src) == 0 {
		return
	}
	x := make([]byte, size)
	old := make([]byte, size)
	copy(x, iv)
	var i int
	for i = 0; i < len(dst) && i < len(src); i += size {
		copy(old, dst[i:i+size])
		block.Decrypt(dst[i:i+size], src[i:i+size])
		for j := 0; j < size; j++ {
			dst[i+j] ^= x[j]
		}
		copy(x, old)
	}
}

func CBCEncrypt(block cipher.Block, iv, dst, src []byte) {
	size := block.BlockSize()
	if len(iv) != size {
		panic("size of IV not equal to block size")
	}
	if len(dst)%size != 0 {
		panic("size of dst and src should be multiples of blocksize")
	}
	if len(dst) == 0 || len(src) == 0 {
		return
	}
	x := make([]byte, size)
	copy(x, iv)
	var i int
	for i = 0; i < len(dst) && i < len(src); i += size {
		for j := 0; j < size; j++ {
			x[j] ^= src[i+j]
		}
		block.Encrypt(dst[i:i+size], x)
		copy(x, dst[i:i+size])
	}
}

func main() {
	src := readBase64Stdin()
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	CBCDecrypt(block, iv, src, src)
	CBCEncrypt(block, iv, src, src)
	CBCDecrypt(block, iv, src, src)

	fmt.Println(string(src))
}
