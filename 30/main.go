package main

import (
	"bytes"
	"cryptopals/30/md4f"
	"encoding/binary"
	"fmt"
)

var (
	// we pretend that we do not know the key
	key = []byte("swordfish")
)

func Sign(message []byte) []byte {
	h := md4f.New()
	h.Write(key)
	h.Write(message)
	return h.Sum(nil)
}

// isValid returns true if msg has valid sign
func isValid(msg, sign []byte) bool {
	h2 := Sign(msg)
	return bytes.Compare(h2, sign) == 0
}

func pad(msg []byte, keyLen int) []byte {
	var res []byte

	len := len(msg) + keyLen
	fmt.Println("(key + msg) len:", len)
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		res = append(res, tmp[0:56-len%64]...)
	} else {
		res = append(res, tmp[0:64+56-len%64]...)
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	res = append(res, tmp[0:8]...)
	return res
}

func main() {
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	// msg := []byte("123")
	attack := []byte(";admin=true")
	// attack := []byte("a")
	origin := Sign(msg)
	fmt.Printf("original sign: %x\n", origin)

	// take original sign and break it into abcde values and calculate sign using those as initial values
	var h [4]uint32
	for j := 0; j < len(h); j++ {
		h[j] = binary.LittleEndian.Uint32(origin[j*4 : (j+1)*4])
		fmt.Printf("h[%d]=%x\n", j, h[j])
	}

	// try to find key len to make proper padding
	for i := 1; i < 1024; i++ {

		gluePad := pad(msg, i)
		forged := append(msg, gluePad...)

		// length of previously calculated msg including gluePadding
		preLen := len(forged) + i

		forged = append(forged, attack...)

		// use original sign and len of forged msg + key as initial values for sha1 hash
		sha := md4f.NewForged(h, uint64(preLen))
		sha.Write(attack)
		newSign := sha.Sum(nil)

		v := isValid(forged, newSign)
		if v {
			fmt.Println("forged sign for:", string(forged))
			fmt.Println("Key size is:", i)
			break
		}
	}
}
