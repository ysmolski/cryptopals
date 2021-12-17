package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"github.com/ysmolsky/cryptopals/tools"
)

type ScoredText struct {
	Score float64
	Text  []byte
}

func main() {
	f, err := os.Open("./4.txt")
	if err != nil {
		panic("cannot open file")
	}

	bestTexts := make([]ScoredText, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		str := scanner.Text()
		ct, err := hex.DecodeString(str)
		if err != nil {
			panic("it is not a hex string")
		}

		texts := make([]ScoredText, 25)
		for b := 0; b <= 255; b++ {
			pt := tools.XorBytes(ct, []byte{byte(b)})
			score := tools.TextScoreEnglish(pt)
			texts = append(texts, ScoredText{score, pt})
		}
		sort.Slice(texts, func(i, j int) bool {
			return texts[i].Score > texts[j].Score
		})
		// pick the most similar to English text
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
