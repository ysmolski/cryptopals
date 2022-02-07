// Challenge 52: Iterated Hash Function Multicollisions
//
// What's an iterated hash function? For all intents and purposes, we're talking
// about the Merkle-Damgard construction. It looks like this:
//
// function MD(M, H, C):
//   for M[i] in pad(M):
// 	H := C(M[i], H)
//   return H
//
// For message M, initial state H, and compression function C.
//
// This should look really familiar, because SHA-1 and MD4 are both in this
// category. What's cool is you can use this formula to build a makeshift hash
// function out of some spare crypto primitives you have lying around (e.g.
// C = AES-128).
//
// Back on task: the cost of collisions scales sublinearly. What does that mean?
// If it's feasible to find one collision, it's probably feasible to find a lot.
//
// How? For a given state H, find two blocks that collide. Now take the resulting
// hash from this collision as your new H and repeat. Recognize that with each
// iteration you can actually double your collisions by subbing in either of the
// two blocks for that slot.
//
// This means that if finding two colliding messages takes 2^(b/2) work (where
// b is the bit-size of the hash function), then finding 2^n colliding messages
// only takes n*2^(b/2) work.
//
// Let's test it. First, build your own MD hash function. We're going to be
// generating a LOT of collisions, so don't knock yourself out. In fact, go out of
// your way to make it bad. Here's one way:
//
// Take a fast block cipher and use it as C. Make H pretty small. I won't look
// down on you if it's only 16 bits. Pick some initial H. H is going to be the
// input key and the output block from C. That means you'll need to pad it on
// the way in and drop bits on the way out.
// Now write the function f(n) that will generate 2^n collisions in this hash
// function.

// Why does this matter? Well, one reason is that people have tried to strengthen
// hash functions by cascading them together. Here's what I mean:
//
// 	  Take hash functions f and g. Build h such that h(x) = f(x) || g(x).
//
// The idea is that if collisions in f cost 2^(b1/2) and collisions in g cost
// 2^(b2/2), collisions in h should come to the princely sum of 2^((b1+b2)/2).
//
// But now we know that's not true!
//
// Here's the idea:
//
// 	  Pick the "cheaper" hash function. Suppose it's f. Generate 2^(b2/2)
// 	  colliding messages in f. There's a good chance your message pool has
// 	  a collision in g. Find it.
//
// And if it doesn't, keep generating cheap collisions until you find it.
//
// Prove this out by building a more expensive (but not too expensive) hash
// function to pair with the one you just used. Find a pair of messages that
// collide under both functions. Measure the total number of calls to the
// collision function.

package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"tools"
)

const HashSize = 2
const HashSizeG = 3

var HashF, HashG []byte

func init() {
	// Hashing function F
	HashF = tools.RandBytes(HashSize)
	// HashG is our second function G, that have different starting constant H
	HashG = tools.RandBytes(HashSizeG)
}

// Sum computes and returns 16-bit digest for the message.
func Sum(msg, hash []byte, pad bool) []byte {
	aesBlockSize := 16
	var padded []byte
	if pad {
		padded = tools.PadPKCS7(msg, HashSize)
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

// Sum computes and returns 24-bit digest for the message.
func SumG(msg, hash []byte, pad bool) []byte {
	aesBlockSize := 16
	var padded []byte
	if pad {
		padded = tools.PadPKCS7(msg, HashSizeG)
	} else {
		padded = msg
	}
	// fmt.Printf("inp = %+x\n\n", padded)
	h := hash
	dst := make([]byte, aesBlockSize)
	for i := 0; i < len(padded); i += HashSizeG {
		key := tools.PadPKCS7(h, aesBlockSize)
		c, err := aes.NewCipher(key)
		if err != nil {
			panic("cannot initialize AES cipher")
		}
		src := make([]byte, HashSizeG, aesBlockSize)
		copy(src, padded[i:i+HashSizeG])
		src = tools.PadPKCS7(src, aesBlockSize)
		c.Encrypt(dst, src)
		// fmt.Printf("key = %+x\n", key)
		// fmt.Printf("src = %+x\n", src)
		// fmt.Printf("dst = %+x\n\n", dst)
		h = dst[:HashSizeG]
	}
	return h
}

func findCollision(h []byte) (a, b []byte) {
	// Two options to generate a collision.
	// First: use random strings and birthday attack.
	// cache maps hash(a) to a
	cache := make(map[string][]byte)
	for {
		a = tools.RandBytes(HashSize)
		aSum := Sum(a, h, false)
		for hash, arg := range cache {
			hash := []byte(hash)
			if bytes.Equal(aSum, hash) && !bytes.Equal(arg, a) {
				return arg, a
			}
		}
		cache[string(aSum)] = a
	}
	return nil, nil
}

var findCollisionCounter = 0

// f generates 2^n collisions for the hashing function Sum
func f(n int) [][]byte {
	h := HashF
	cols := make([][]byte, 0)
	for i := 0; i < n; i++ {
		a, b := findCollision(h)
		findCollisionCounter++
		s := Sum(a, h, false)
		// fmt.Printf("h = %+x, a = %+x, sum = %+x\n", h, a, s)
		// fmt.Printf("h = %+x, b = %+x, sum = %+x\n\n", h, b, s)
		h = s
		if len(cols) == 0 {
			cols = append(cols, a, b)
		} else {
			size := len(cols)
			for j := 0; j < size; j++ {
				ext := append([]byte(nil), cols[j]...)
				ext = append(ext, a...)
				cols = append(cols, ext)
			}
			for j := 0; j < size; j++ {
				ext := append([]byte(nil), cols[j]...)
				ext = append(ext, b...)
				cols = append(cols, ext)
			}
			cols = cols[size:]
		}
	}
	// fmt.Printf("cols = %+x\n", cols)
	return cols
}

func main() {
	// Generate collision for F function, increasing the generated pool on each
	// iteration: 2^8, 2^9, and so on. Check if we have collision for G in the
	// pool.
	findCollisionCounter = 0
	for n := 11; n <= 13; n++ {
		// Collisions are generated without padding
		cols := f(n)
		fmt.Println("Collisions generated in F:", len(cols))
		countG := make(map[string]bool)
		gCalls := 0
	outer:
		for i := 0; i < len(cols); i++ {
			for j := i + 1; j < len(cols); j++ {
				x := SumG(cols[i], HashG, true)
				y := SumG(cols[j], HashG, true)
				gCalls += 2
				if bytes.Equal(x, y) {
					if bytes.Equal(cols[i], cols[j]) {
						panic("messsages should not be equal")
					}
					fmt.Printf("x = %+x\ny = %+x\n", cols[i], cols[j])
					fmt.Printf("G(x) = %+x\n", SumG(cols[i], HashG, true))
					fmt.Printf("G(y) = %+x\n", SumG(cols[j], HashG, true))
					fmt.Println("findCollision calls =", findCollisionCounter)
					fmt.Println("SumG calls =", gCalls)
					countG[string(x)] = true
					break outer
				}
			}
			// fmt.Printf("hash = %+x\n", Sum(cols[i], HashF, true))
		}
		fmt.Println("Unique collision digests in G:", len(countG))
		if len(countG) > 0 {
			break
		}
	}
}
