package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"github.com/ysmolsky/cryptopals/tools"
)

func main() {
	f, err := os.Open("./4.txt")
	if err != nil {
		panic("cannot open file")
	}

	bestTexts := make([]tools.ScoredText, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		str := scanner.Text()
		ct, err := hex.DecodeString(str)
		if err != nil {
			panic("it is not a hex string")
		}

		// pick the most similar to English text
		texts := tools.BestXorByteKey(ct)
		bestTexts = append(bestTexts, texts[0])
	}
	// sort best candidates for each line and pick the closest to english text
	sort.Slice(bestTexts, func(i, j int) bool {
		return bestTexts[i].Score > bestTexts[j].Score
	})
	fmt.Printf("Score Plaintext\n")
	for _, t := range bestTexts[0:5] {
		fmt.Printf("%5.3f %#v\n", t.Score, string(t.Text))
	}
}
