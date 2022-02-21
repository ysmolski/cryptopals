package main

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ysmolsky/cryptopals/tools"
)

type ScoredText struct {
	Score float64
	Text  []byte
}

func main() {
	ct, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	if err != nil {
		panic("it is not hex string")
	}
	score := tools.TextScoreEnglish(ct)
	fmt.Printf("%5.3f %#v\n", score, string(ct))

	texts := make([]ScoredText, 25)
	for b := 0; b <= 255; b++ {
		pt := tools.XorBytes(ct, []byte{byte(b)})
		score := tools.TextScoreEnglish(pt)
		texts = append(texts, ScoredText{score, pt})
	}
	sort.Slice(texts, func(i, j int) bool {
		return texts[i].Score < texts[j].Score
	})
	for _, t := range texts {
		fmt.Printf("%5.3f %#v\n", t.Score, string(t.Text))
	}
}
