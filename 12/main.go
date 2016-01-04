package main

/*
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Do not decode this string now. Don't do it.
Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.
What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
2. Detect that the function is using ECB. You already know, but do this step anyways.
3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
6. Repeat for the next byte.

Congratulations.
This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
*/

import (
	"bytes"
	"crypto/aes"
	"cryptopals/util"
	"encoding/base64"
	"fmt"
)

type oracleFunc func(src []byte) []byte

var key = util.RandAes128()

func encryptOracle(src []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(src))
	copy(out, src)

	appendix, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	out = append(out, appendix...)
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

func decryptBlackBox(oracle oracleFunc) {
	lastKnown := 0
	blockSize := 0
	// find the blockSize
	for i := 0; i < 32; i++ {
		input := make([]byte, i)
		out := oracle(input)
		// fmt.Println(len(out))
		if lastKnown == 0 {
			lastKnown = len(out)
		} else if len(out) != lastKnown {
			blockSize = len(out) - lastKnown
			fmt.Println("block size:", blockSize)
			break
		}
	}
	if blockSize == 0 {
		return
	}
	// ensure that it is ECB mode
	isEcb := detectEcb(oracle(make([]byte, 1024)), blockSize)
	fmt.Println("is ECB:", isEcb)

	blocksAdded := len(oracle(make([]byte, 0))) / blockSize
	fmt.Println("blocks added:", blocksAdded)

	text := make([]byte, blockSize*blocksAdded)

	for block := 0; block < blocksAdded; block++ {
		fmt.Println("\nblock #", block)
		for i := 0; i < blockSize; i++ {
			// capture first block when we prefix with data of blockSize-1 size
			prefix := make([]byte, blockSize-1-i)
			short := oracle(prefix)
			short = short[blockSize*block : blockSize*(block+1)]

			fmt.Println("to match:", short)
			// lets find which first block matches oneByteShort block
			dummy := make([]byte, blockSize)
			if i > 0 && block == 0 {
				start := blockSize - 1 - i
				end := blockSize - 1
				tStart := blockSize * block
				tEnd := i + blockSize*block
				fmt.Println(start, end, tStart, tEnd)
				copy(dummy[start:end], text[tStart:tEnd])
			}
			if block > 0 {
				start := 0
				end := blockSize - 1
				tStart := blockSize*(block-1) + i + 1
				tEnd := blockSize*block + i
				fmt.Println("copy", start, end, tStart, tEnd)
				copy(dummy[start:end], text[tStart:tEnd])
			}
			fmt.Println("trying last byte", dummy)
			for b := 0; b < 256; b++ {
				dummy[blockSize-1] = byte(b)
				out := oracle(dummy)
				if bytes.Equal(out[:blockSize], short) {
					fmt.Printf("found %d-th block, %d-th byte: %d\n", block, i, b)
					text[blockSize*block+i] = byte(b)
					break
				}
			}
		}
		fmt.Println(text)
	}
	fmt.Println(string(text))
}

func main() {
	// fmt.Println("after enc ", out)
	decryptBlackBox(encryptOracle)
}
