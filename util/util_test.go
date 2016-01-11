package util

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestPadTo(t *testing.T) {
	m := []byte{0, 1, 2}
	got := PadTo(m, 6)
	e := []byte{0, 1, 2, 3, 3, 3}
	if bytes.Compare(got, e) != 0 {
		t.Errorf("expected %x, got %x", e, got)
	}
}

func TestCBC(t *testing.T) {
	msg := []byte("12345678901234567890")
	key := RandAes128()
	iv := RandBytes(16)
	block, _ := aes.NewCipher(key)
	padded := PadTo(msg, 16)
	ct := make([]byte, len(padded))
	CBCEncrypt(block, iv, ct, padded)

	block, _ = aes.NewCipher(key)
	padded2 := make([]byte, len(ct))
	CBCDecrypt(block, iv, padded2, ct)
	if bytes.Compare(padded, padded2) != 0 {
		t.Errorf("expected %x, got %x", padded, padded2)
	}
}
