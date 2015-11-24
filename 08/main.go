package main

/*
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
*/

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		t := scanner.Text()
		size := len(t) / 32
		for i := 0; i < size; i++ {
			for j := i + 1; j < size; j++ {
				a := i * 32
				b := (i + 1) * 32
				c := j * 32
				d := (j + 1) * 32
				if t[a:b] == t[c:d] {
					fmt.Println(i, j)
					fmt.Println(t)
				}
			}
		}
	}
}
