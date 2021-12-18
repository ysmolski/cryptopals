package main

import (
	"fmt"
	"log"
	"sort"

	"github.com/ysmolsky/cryptopals/tools"
)

type ScoredText struct {
	Score float64
	Text  []byte
}
type scoredKeysize struct {
	dist  float64
	ksize int
}

func main() {
	ct, err := tools.ReadBase64File("./6.txt")
	if err != nil {
		log.Fatal(err)
	}

	// Find the most likely key sizes. Picking the best one won't do us any
	// good here, we need to check the whole 'hood.
	const testChunks = 4
	const maxKeysize = 40
	scoredKeysizes := make([]scoredKeysize, 0, maxKeysize)
	for ksize := 1; ksize <= maxKeysize; ksize++ {
		// find an average of distances between consequential chunks of size ksize
		dist := 0.0
		for i := 0; i < len(ct)-ksize && i < ksize*testChunks; i += ksize {
			dist += float64(tools.EditDistance(ct[i:i+ksize], ct[i+ksize:i+2*ksize])) / float64(ksize)
		}
		dist = dist / float64(testChunks)
		scoredKeysizes = append(scoredKeysizes, scoredKeysize{dist, ksize})
		// fmt.Printf("ksize=%d dist=%f\n", ksize, dist)
	}
	sort.Slice(scoredKeysizes, func(i, j int) bool {
		return scoredKeysizes[i].dist < scoredKeysizes[j].dist
	})

	fmt.Printf("The best fitting keysizes and their average distance on %d chunks:\n", testChunks)
	for _, v := range scoredKeysizes[:7] {
		fmt.Printf("ksize=%d dist=%f\n", v.ksize, v.dist)
	}

	// Let's iterate through the potential keysizes
	for i := range scoredKeysizes[:7] {
		keysize := scoredKeysizes[i].ksize
		fmt.Printf("\nkeysize=%d, edit distance = %f\n", keysize, scoredKeysizes[i].dist)

		// ct is transposed into keysize chunks. Each chunk is ct xored by one
		// byte. For each chunk we find one byte key.
		chunks := tools.TransposeByN(ct, keysize)
		guess := make([]byte, keysize)
		avgTopScore := 0.0
		for i, ch := range chunks {
			ptScored := tools.BestXorByteKey(ch)
			// for _, p := range ptScored[:5] {
			// 	fmt.Printf("%v %#v\n", p.Score, string(p.Text[:40]))
			// }
			guess[i] = ptScored[0].Key
			avgTopScore += ptScored[0].Score
			// fmt.Println("")
		}
		avgTopScore /= float64(len(chunks))

		fmt.Printf("avg. score = %f, key = %#v\n", avgTopScore, string(guess))
	}
}
