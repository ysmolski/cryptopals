package tools

import (
	"crypto/aes"
	"crypto/rand"
	"log"
)

func PadPKCS7(a []byte, n int) []byte {
	num := n - len(a)%n
	add := make([]byte, num)
	for i := range add {
		add[i] = byte(num)
	}
	a = append(a, add...)
	return a
}

func RandBytes(n int) []byte {
	res := make([]byte, n)
	_, err := rand.Read(res)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func RandByte() byte {
	res := make([]byte, 1)
	_, err := rand.Read(res)
	if err != nil {
		log.Fatal(err)
	}
	return res[0]
}

func ECBCBCEncryptOracle(input []byte) []byte {
	prefix := RandBytes(int(RandByte()%6) + 5)
	suffix := RandBytes(int(RandByte()%6) + 5)
	res := make([]byte, len(prefix)+len(input)+len(suffix))

	copy(res, prefix)
	copy(res[len(prefix):], input)
	copy(res[len(prefix)+len(input):], suffix)

	ks := 16
	key := RandBytes(ks)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	mode := RandByte() % 2
	res = PadPKCS7(res, ks)
	dst := make([]byte, len(res))
	if mode == 0 {
		ECBEncrypt(block, dst, res)
	} else {
		IV := RandBytes(ks)
		CBCEncrypt(block, IV, dst, res)
	}
	return dst
}
