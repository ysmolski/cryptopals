package main

/*
Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
*/

import (
	"bytes"
	"crypto/aes"
	"cryptopals/util"
	"fmt"
)

type oracleFunc func(src []byte) []byte

var (
	key       = util.RandAes128()
	prefixLen = int(util.RandByte())%32 + 1
	prefix    = util.RandBytes(prefixLen)
)

func encryptOracle(src []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(src))
	copy(out, src)

	target := []byte("secret bytes. nobody is gonna read them.")
	out = append(prefix, out...)
	out = append(out, target...)
	out = util.PadTo(out, 16)
	// fmt.Println("before enc", out)
	util.ECBEncrypt(block, out, out)

	return out
}

func detectEcb(t []byte, blockSize int) bool {
	size := len(t) / blockSize
	for i := 0; i < size; i++ {
		for j := i + 1; j < size; j++ {
			a := i * blockSize
			b := (i + 1) * blockSize
			c := j * blockSize
			d := (j + 1) * blockSize
			if bytes.Equal(t[a:b], t[c:d]) {
				return true
			}
		}
	}
	return false
}

func sameBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return 0
}

func main() {
	// calculate prefix size and amount of bytes to fix prefix into integer blocks count
	var prev []byte
	var sameLen int
	var prefixPads []int
	var prefixBlocks []int
	var maxSameLen int
	for i := 0; i < 16; i++ {
		ct := encryptOracle(make([]byte, i))
		// fmt.Printf("%2d %2d %s\n", i, sameLen, hex.EncodeToString(ct))
		if prev != nil {
			sameLen = sameBytes(prev, ct)
			if sameLen > 0 && sameLen%16 == 0 && sameLen > maxSameLen {
				prefixPads = append(prefixPads, i-1)
				prefixBlocks = append(prefixBlocks, sameLen/16)
				maxSameLen = sameLen
			}
		}
		prev = ct
	}
	prefixPad := prefixPads[len(prefixPads)-1]
	prefixSize := prefixBlocks[len(prefixBlocks)-1]
	ct := encryptOracle(make([]byte, prefixPad))
	targetBlocks := len(ct)/16 - prefixSize
	fmt.Println("bytes to align prefix:", prefixPad)
	fmt.Println("Prefix has", prefixSize, "blocks")
	fmt.Println("Target has", targetBlocks, "blocks")

	block := prefixSize
	t := make([]byte, targetBlocks*16)
	for i := 0; i < 16; i++ {
		inp := make([]byte, prefixPad+15-i)
		match := encryptOracle(inp)[block*16 : (block+1)*16]
		inp = append(inp, t[:i]...)
		inp = append(inp, 0)
		for b := byte(0); b <= 255; b++ {
			inp[len(inp)-1] = b
			found := encryptOracle(inp)[block*16 : (block+1)*16]
			if bytes.Equal(match, found) {
				t[i] = b
				break
			}

		}

	}
	fmt.Println("target:", string(t))
}
