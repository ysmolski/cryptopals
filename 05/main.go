package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	key := []byte("ICE")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanBytes)
	ptr := 0
	bytes := make([]byte, 1)
	for scanner.Scan() {
		t := scanner.Bytes()
		bytes[0] = t[0] ^ key[ptr]
		fmt.Print(hex.EncodeToString(bytes))
		ptr++
		if ptr >= len(key) {
			ptr = 0
		}
	}
	fmt.Println()
}
