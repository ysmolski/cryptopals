package main

/*
Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)
(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
Forge a variant of this message that ends with ";admin=true".
*/

import (
	"bytes"
	"cryptopals/29/sha1f"
	"encoding/binary"
	"fmt"
)

var (
	// we pretend that we do not know the key
	key = []byte("swordfish")
)

func Sign(message []byte) []byte {
	h := sha1f.New()
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
		tmp[i] = byte(len >> (56 - 8*i))
	}
	res = append(res, tmp[0:8]...)
	return res
}

func main() {
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	//msg := []byte("123")
	attack := []byte(";admin=true")
	origin := Sign(msg)
	fmt.Printf("original sign: %x\n", origin)

	// take original sign and break it into abcde values and calculate sign using those as initial values
	var h [5]uint32
	for j := 0; j < 5; j++ {
		h[j] = binary.BigEndian.Uint32(origin[j*4 : (j+1)*4])
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
		sha := sha1f.NewForged(h, uint64(preLen))
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
