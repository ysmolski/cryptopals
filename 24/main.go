package main

/*
Create the MT19937 stream cipher and break it
You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
*/

import (
	"bytes"
	"cryptopals/util"
	"errors"
	"fmt"
)

func untemper(y uint64) uint64 {
	y = y ^ y>>18

	y = y ^ y<<15&4022730752

	tmp := y ^ y<<7&2636928640
	tmp = y ^ tmp<<7&2636928640
	tmp = y ^ tmp<<7&2636928640
	y = y ^ tmp<<7&2636928640

	tmp = y ^ y>>11
	y = y ^ tmp>>11

	return y
}

type MTCrypto struct {
	mt    *util.MT19937
	cache [4]byte
	idx   int
}

func NewMTCrypto(key int) *MTCrypto {
	mtc := &MTCrypto{mt: util.NewMT19337(uint64(key))}
	mtc.cacheNext()
	return mtc
}

func (m *MTCrypto) cacheNext() {
	next := m.mt.Next()
	for i := 3; i >= 0; i-- {
		rem := byte(next % 256)
		m.cache[i] = rem
		next = next / 256
	}
	m.idx = 0
}

func (m *MTCrypto) Next() byte {
	if m.idx >= 4 {
		m.cacheNext()
	}
	res := m.cache[m.idx]
	m.idx++
	return res
}

func MTEncrypt(key int, dst, src []byte) error {
	mtc := NewMTCrypto(key)
	if len(dst) == 0 || len(src) == 0 {
		return errors.New("dst and stc should not be empty")
	}
	for i := 0; i < len(dst) && i < len(src); i++ {
		x := mtc.Next()
		dst[i] = src[i] ^ x
	}
	return nil
}

func main() {
	{
		// testing that crypto works back and forth
		t := []byte("some secret stuff AAAA")
		ct := make([]byte, len(t))
		MTEncrypt(0, ct, t)
		t2 := make([]byte, len(t))
		MTEncrypt(0, t2, ct)
		fmt.Println(bytes.Equal(t, t2))
	}
	{
		// generate random bytes with AAA's appended
		t := util.RandBytes(int(util.RandByte()))
		knownText := "AAAAAAAAAAAAA"
		t = append(t, []byte(knownText)...)
		ct := make([]byte, len(t))
		MTEncrypt(int(util.RandByte())*int(util.RandByte()), ct, t)
		for i := 0; i < 0xFFFF; i++ {
			z := make([]byte, len(ct))
			MTEncrypt(i, z, ct)
			if string(z[len(z)-len(knownText):]) == knownText {
				fmt.Println("Found the key:", i)
				break
			}
		}
	}

}
