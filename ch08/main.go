package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	f, err := os.Open("./8.txt")
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	line := 1
	for scanner.Scan() {
		hexed := scanner.Text()
		ct, err := hex.DecodeString(hexed)
		if err != nil {
			log.Fatal(err)
		}
		sz := 16
		blocks := len(ct) / sz // blocks
		ECB := false
		for i := 0; i < blocks-1; i++ {
			for j := i + 1; j < blocks; j++ {
				if bytes.Compare(ct[i*sz:(i+1)*sz], ct[j*sz:(j+1)*sz]) == 0 {
					fmt.Printf("line %d: block #%d equals #%d\n", line, i, j)
					ECB = true
				}
			}
		}
		if ECB {
			fmt.Printf("ct = \n")
			for i := 0; i < blocks; i++ {
				fmt.Printf("    %s\n", hexed[i*sz*2:(i+1)*sz*2])
			}
		}
		line += 1
	}
}
