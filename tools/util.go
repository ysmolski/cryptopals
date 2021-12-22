package tools

import (
	"crypto/rand"
	"fmt"
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

func UnpadPKCS7(a []byte) ([]byte, error) {
	last := int(a[len(a)-1])
	for i := 1; i < last; i++ {
		pos := len(a) - 1 - i
		if int(a[pos]) != last {
			return nil, fmt.Errorf("Bad padding: expected %d at pos %d", last, pos)
		}
	}
	return a[:len(a)-1-last], nil
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
