package tools

import (
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
