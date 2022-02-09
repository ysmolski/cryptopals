// Challenge 53: Kelsey and Schneier's Expandable Messages
//
// Attack a long message M of 2^k blocks.
//
// 	Generate an expandable message of length (k, k + 2^k - 1) using the
// 	strategy outlined above. Hash M and generate a map of intermediate hash
// 	states to the block indices that they correspond to. From your expandable
// 	message's final state, find a single-block "bridge" to intermediate state
// 	in your map. Note the index i it maps to. Use your expandable message to
// 	generate a prefix of the right length such that len(prefix || bridge ||
// 	M[i..]) = len(M).
//
// The padding in the final block should now be correct, and your forgery should
// hash to the same value as M.

package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"tools"
)

const HashSize = 2

var HashInit []byte

func init() {
	// Hashing function F
	HashInit = tools.RandBytes(HashSize)
}

// getPadding return sha1 padding for the length of a message
func getPadding(length uint64) []byte {
	d := bytes.Buffer{}
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if length%64 < 56 {
		d.Write(tmp[0 : 56-length%64])
	} else {
		d.Write(tmp[0 : 64+56-length%64])
	}

	// Length in bits.
	length <<= 3
	binary.BigEndian.PutUint64(tmp[:], length)
	d.Write(tmp[0:8])
	return d.Bytes()
}

// padMessage pads message according to sha1 algorithm
func padMessage(msg []byte) []byte {
	pad := getPadding(uint64(len(msg)))
	padded := append([]byte(nil), msg...)
	padded = append(padded, pad...)
	return padded
}

// Sum computes and returns 16-bit digest for the message.
func Sum(msg, hash []byte, pad bool) []byte {
	aesBlockSize := 16
	var padded []byte
	if pad {
		padded = padMessage(msg)
	} else {
		padded = msg
	}
	// fmt.Printf("inp = %+x\n\n", padded)
	h := hash
	dst := make([]byte, aesBlockSize)
	for i := 0; i < len(padded); i += HashSize {
		key := tools.PadPKCS7(h, aesBlockSize)
		c, err := aes.NewCipher(key)
		if err != nil {
			panic("cannot initialize AES cipher")
		}
		src := make([]byte, HashSize, aesBlockSize)
		copy(src, padded[i:i+HashSize])
		src = tools.PadPKCS7(src, aesBlockSize)
		c.Encrypt(dst, src)
		// fmt.Printf("key = %+x\n", key)
		// fmt.Printf("src = %+x\n", src)
		// fmt.Printf("dst = %+x\n\n", dst)
		h = dst[:HashSize]
	}
	return h
}

// Sum computes and returns 16-bit digest for the message, and a mapping from
// hashes to block indexes
func SumAndMap(msg, hash []byte, pad bool) ([]byte, map[string]int) {
	aesBlockSize := 16
	var padded []byte
	if pad {
		padded = padMessage(msg)
	} else {
		padded = msg
	}
	h := hash
	dst := make([]byte, aesBlockSize)
	hashes := make(map[string]int)
	for i := 0; i < len(padded); i += HashSize {
		if i/HashSize > k {
			if _, ok := hashes[string(h)]; !ok {
				hashes[string(h)] = i / HashSize
			}
		}
		key := tools.PadPKCS7(h, aesBlockSize)
		c, err := aes.NewCipher(key)
		if err != nil {
			panic("cannot initialize AES cipher")
		}
		src := make([]byte, HashSize, aesBlockSize)
		copy(src, padded[i:i+HashSize])
		src = tools.PadPKCS7(src, aesBlockSize)
		c.Encrypt(dst, src)
		h = dst[:HashSize]
	}
	return h, hashes
}

func findCollisionLastBlock(h, one, many []byte) ([]byte, []byte) {
	// sum without last block. that block we are going to randomize
	manySum := Sum(many[:len(many)-HashSize], h, false)
	for {
		one = tools.RandBytes(HashSize)
		oneSum := Sum(one, h, false)
		a := tools.RandBytes(HashSize)
		fullSum := Sum(a, manySum, false)
		if bytes.Equal(fullSum, oneSum) {
			copy(many[len(many)-HashSize:], a)
			return one, many
		}
	}
	return nil, nil
}

func pow(a, b int) int {
	p := 1
	for b > 0 {
		if b&1 != 0 {
			p *= a
		}
		b >>= 1
		a *= a
	}
	return p
}

type Collision struct {
	one  []byte
	many []byte
	hash []byte
}

func genExpandableMsg(k int) []Collision {
	msg := make([]Collision, 0)
	hash := HashInit
	for i := k - 1; i >= 0; i-- {
		one := tools.RandBytes(HashSize)
		many := tools.RandBytes((pow(2, i) + 1) * HashSize)
		one, many = findCollisionLastBlock(hash, one, many)
		h2 := Sum(one, hash, false)
		// fmt.Println("k =", i)
		// fmt.Printf("one = %+x\n", one)
		// fmt.Printf("many = %+x\n", many)
		// fmt.Printf("hash = %+x\n", h2)
		// fmt.Printf("hash = %+x\n", Sum(many, hash, false))
		msg = append(msg, Collision{one, many, h2})
		hash = h2
	}
	return msg
}

const k = 14

func main() {
	// Message M has 2^k blocks. One block is 2 bytes (16 bits).
	mLen := pow(2, k)
	fmt.Println("blocks in m:", mLen)
	fmt.Println(" bytes in m:", mLen*HashSize)
	m := tools.RandBytes(mLen * HashSize)
	copy(m, []byte("Super long message starts with this line. Zeroes ..."))
	copy(m[len(m)-8:], []byte("The end."))
	mPaddedHash := Sum(m, HashInit, true)

	_, mMap := SumAndMap(m, HashInit, false)
	fmt.Printf("distinct intermediate hashes = %d\n", len(mMap))

	idx := 0 // block # in m
	ok := false
	var i int // in expMsg slice
	var expMsg []Collision
	fmt.Println("\n[*] Constructing expandable message that hashes into one of intermediate hashes of m")
outer:
	for {
		expMsg = genExpandableMsg(k)

		for i = len(expMsg) - 1; i >= len(expMsg)-1; i-- {
			state := expMsg[i].hash
			fmt.Printf("%d-th hash=%+x one=%x many=%x\n", i, state, expMsg[i].one, expMsg[i].many)
			idx, ok = mMap[string(state)]
			if ok {
				fmt.Println("[*] Final hash matches intermediate state for block #", idx)
				break outer
			}
		}
	}
	if ok {
		t := idx - k + 1 // length in blocks to construct
		prefix := make([]byte, 0, idx*HashSize)
		j := 0
		fmt.Println("\n[*] Constructing prefix")
		for j < len(expMsg) {
			msgBlocks := pow(2, k-1-j)
			fmt.Printf("    %2d t = %5d, expMsg blocks=%5d\n", j, t, msgBlocks)
			if t > msgBlocks {
				prefix = append(prefix, expMsg[j].many...)
				t -= msgBlocks
			} else {
				prefix = append(prefix, expMsg[j].one...)
			}
			j++
		}
		forgery := append(prefix, m[idx*HashSize:]...)
		fmt.Println("forgery len =", len(forgery))
		fmt.Println("\n[*] Checking if Sum(Pad(forgery)) == Sum(Pad(m)):")
		fmt.Printf("    msg hash = %+x\n", mPaddedHash)
		fmt.Printf("forgery hash = %+x\n", Sum(forgery, HashInit, true))
	}
}
