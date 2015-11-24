package main

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"os"
)

func readHexIntoBytes() []byte {
	scan := bufio.NewScanner(os.Stdin)
	bytes := make([]byte, 0, 1024)

	for scan.Scan() {
		input := scan.Text()
		bs, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			fmt.Println(err)
			return bytes
		}
		bytes = append(bytes, bs...)
	}
	return bytes
}
func main() {
	key := []byte("YELLOW SUBMARINE")

	bytes := readHexIntoBytes()
	fmt.Println(len(bytes))
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	// dst := make([]byte, 16)
	for i := 0; i < len(bytes); i += 16 {
		block.Decrypt(bytes[i:i+16], bytes[i:i+16])
	}
	fmt.Println(string(bytes))
}
