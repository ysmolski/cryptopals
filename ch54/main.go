// Challenge 53: Kelsey and Kohno's Nostradamus Attack

package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"tools"
)

const HashSize = 3

var HashInit []byte

func init() {
	// Hashing function IV
	HashInit = tools.RandBytes(HashSize)
}

// getPadding returns sha1 padding for the length of a message
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
		h = dst[:HashSize]
	}
	return h
}

func collideStates(h1, h2 []byte) (a, b, h []byte) {
	// using IV=h1 we map result of hash to input value
	cache := make(map[string][]byte)
	n2 := pow(2, HashSize*8/2+1)
	for i := 0; i < n2; i++ {
		a = tools.RandBytes(HashSize)
		aSum := Sum(a, h1, false)
		cache[string(aSum)] = a
	}
	for {
		a = tools.RandBytes(HashSize)
		aSum := Sum(a, h1, false)
		cache[string(aSum)] = a
		b = tools.RandBytes(HashSize)
		bSum := Sum(b, h2, false)
		if input, ok := cache[string(bSum)]; ok {
			return input, b, bSum
		}
	}
	return nil, nil, nil
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

type Hash string

type MsgHash struct {
	msg  []byte   // This message produces
	hash []byte   // this hash state.
	next *MsgHash // Next state in pair-states collision.
}

type Diamond map[Hash]*MsgHash

// makeDiamond returns a Diamond structure and final hash state
func makeDiamond(k int) (Diamond, []byte) {
	hLen := pow(2, k)
	start := make(Diamond)
	h := make([][]byte, hLen)
	current := make([]*MsgHash, hLen)
	for i := 0; i < hLen; i++ {
		// make initial states unique
		for {
			h[i] = tools.RandBytes(HashSize)
			if _, ok := start[Hash(h[i])]; !ok {
				break
			}
		}
		current[i] = &MsgHash{nil, nil, nil}
		start[Hash(h[i])] = current[i]
	}

	var finalState []byte
	for hLen > 1 {
		for i := 0; i < hLen; i += 2 {
			fmt.Printf(".")
			// fmt.Printf("hLen = %v i = %+v\n", hLen, i)
			m1, m2, nextHash := collideStates(h[i], h[i+1])
			// fmt.Printf("hash(%x, %x) == hash(%x, %x) == %x\n", h[i], m1, h[i+1], m2, nextHash)
			next := &MsgHash{nil, nil, nil}
			if hLen == 2 {
				next = nil
				finalState = nextHash
			}
			current[i].msg = m1
			current[i].hash = nextHash
			current[i].next = next
			current[i+1].msg = m2
			current[i+1].hash = nextHash
			current[i+1].next = next
			current[i/2] = next
			h[i/2] = nextHash
		}
		hLen /= 2
	}
	fmt.Println(" DONE")

	return start, finalState
}

func followTree(hm *MsgHash) []byte {
	s := make([]byte, 0, k)
	for hm != nil {
		s = append(s, hm.msg...)
		hm = hm.next
	}
	return s
}

const k = 9

func main() {
	fmt.Println("[*] Generate diamond structure for k =", k)
	d, finalState := makeDiamond(k)
	fmt.Printf("%+v initial states. final state = %+x\n", len(d), finalState)

	predictionLen := 48
	wholeLen := predictionLen + HashSize*(k+1)
	fmt.Println("[*] Commit to the final message len of", wholeLen)
	padding := getPadding(uint64(wholeLen))
	commitHash := Sum(padding, finalState, false)
	fmt.Printf("[*] Commit to the hash of prediction = %x\n", commitHash)

	prediction := make([]byte, predictionLen+HashSize)
	copy(prediction, "This is my prediction that xyz will happen")

	fmt.Println("[*] Alter last block in prediction until hash sum matches any of starting states in the diamond tree")
	var suffix []byte
	sumWithoutLast := Sum(prediction[:predictionLen], HashInit, false)
	for {
		last := tools.RandBytes(HashSize)
		sumWithLast := Sum(last, sumWithoutLast, false)
		if tree, ok := d[Hash(sumWithLast)]; ok {
			copy(prediction[predictionLen:], last)
			suffix = followTree(tree)
			break
		}
	}

	fmt.Printf("prediction = %+q\n", prediction)
	fmt.Printf("suffix = %+x\n", suffix)
	fmt.Println("forged length =", len(prediction)+len(suffix))
	actualHash := Sum(append(prediction, suffix...), HashInit, true)
	fmt.Printf("[*] Actual Hash for padded prediction = %+x\n", actualHash)
}
