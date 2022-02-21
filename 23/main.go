package main

import (
	"fmt"
	"time"

	"github.com/ysmolsky/cryptopals/tools/mtrand"
)

func main() {
	orig := mtrand.NewSource()
	orig.Seed(uint32(time.Now().Unix()))
	// let the original RNG run for a while
	for i := 0; i < 100; i++ {
		orig.Rand()
	}
	n := 624
	mt := make([]uint32, n)
	for i := 0; i < n; i++ {
		mt[i] = mtrand.Untemper(orig.Rand())
	}
	clone := mtrand.Reconstruct(mt)

	fmt.Println("original =", orig.Rand(), "clone =", clone.Rand())
	for i := 0; i < 10000000; i++ {
		if orig.Rand() != clone.Rand() {
			panic("RNGs are converging!")
		}
	}
	fmt.Println("all is fine, clone behaves indentically")
}
