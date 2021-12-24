package tools

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"log"
	"testing"
)

func TestCTREncrypt(t *testing.T) {
	key := "1234567890123456"
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	tests := [][]byte{
		[]byte("1"),
		[]byte("test msg"),
		[]byte("123456789012345"),
		[]byte("1234567890123456"),
		[]byte("12345678901234567"),
		[]byte("akdflkkjhh3h f0h0hfqidfh02h foiwh f h20h 09hf hf owkfj qwef0 12345678901234567"),
	}
	for _, src := range tests {
		dst := make([]byte, len(src))
		nonce := uint64(len(src))
		CTREncrypt(block, nonce, dst, src)
		fmt.Printf("dst = %#v\n", string(dst))
		CTREncrypt(block, nonce, dst, dst)

		if !bytes.Equal(dst, src) {
			t.Errorf("doubly encoded text %#v should be equal itself", string(src))
		}
	}
}

func TestCTRValue(t *testing.T) {
	src, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		log.Fatal(err)
	}
	exp := "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
	key := "YELLOW SUBMARINE"
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(src))
	CTREncrypt(block, 0, dst, src)
	if string(dst) != exp {
		t.Errorf("expected %#v, got %#v", exp, string(dst))
	}
}
