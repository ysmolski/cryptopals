package main

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("bytes slices should be of equal size")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res, nil
}

func main() {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"
	aBytes, _ := hex.DecodeString(a)
	bBytes, _ := hex.DecodeString(b)
	c, _ := xorBytes(aBytes, bBytes)
	s := hex.EncodeToString(c)
	fmt.Println(s)
}
