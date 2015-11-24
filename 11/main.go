package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func pad(seq []byte, n int) []byte {
	if n > len(seq) {
		size := n - len(seq)
		appendix := make([]byte, size)
		for i := 0; i < size; i++ {
			appendix[i] = byte(size)
		}
		return append(seq, appendix...)
	}
	return seq
}

func padTo(seq []byte, size int) []byte {
	if len(seq)%size != 0 {
		return pad(seq, len(seq)+16-len(seq)%size)
	}
	return seq
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

func ECBDecrypt(block cipher.Block, dst, src []byte) {
	size := block.BlockSize()
	if len(dst)%size != 0 {
		panic("size of dst and src should be multiples of blocksize")
	}
	for i := 0; i < len(dst); i += size {
		block.Decrypt(dst[i:i+size], src[i:i+size])
	}
}

func ECBEncrypt(block cipher.Block, dst, src []byte) {
	size := block.BlockSize()
	if len(dst)%size != 0 {
		panic("size of dst and src should be multiples of blocksize")
	}
	for i := 0; i < len(dst); i += size {
		block.Encrypt(dst[i:i+size], src[i:i+size])
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return nil
	}
	return b
}

func randAes128() []byte {
	return randBytes(16)
}

func randByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}

type oracleFunc func(src []byte) []byte

func encryptOracle(src []byte) []byte {
	key := randAes128()
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(src))
	copy(out, src)

	// random prepend and append
	prefixSize := randByte()%10 + 5
	postfixSize := randByte()%10 + 5
	postfix := randBytes(int(postfixSize))
	out = append(randBytes(int(prefixSize)), out...)
	out = append(out, postfix...)
	// padding
	out = padTo(out, 16)
	// fmt.Println("before enc", out)

	// random encryption mode
	mode := randByte()
	if mode%2 == 0 {
		// ecb
		fmt.Println("ecb")
		ECBEncrypt(block, out, out)
	} else {
		// cbc
		fmt.Println("cbc")
		iv := randAes128()
		CBCEncrypt(block, iv, out, out)
	}
	return out
}

func detectEcb(t []byte, blockSize int) bool {
	size := len(t) / blockSize
	for i := 0; i < size; i++ {
		for j := i + 1; j < size; j++ {
			a := i * blockSize
			b := (i + 1) * blockSize
			c := j * blockSize
			d := (j + 1) * blockSize
			if bytes.Equal(t[a:b], t[c:d]) {
				// fmt.Println(i, j)
				// fmt.Println(t)
				return true
			}
		}
	}
	return false

}

func checkBlackBox(oracle oracleFunc) {
	input := make([]byte, 64)
	for i := 0; i < 20; i++ {
		out := oracle(input)
		if detectEcb(out, 16) {
			fmt.Println("   ecb")
		} else {
			fmt.Println("   cbc")
		}

	}
}

func main() {
	// fmt.Println("after enc ", out)
	checkBlackBox(encryptOracle)
}
