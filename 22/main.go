package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ysmolsky/cryptopals/tools/mtrand"
)

func breakSeed(value uint32) uint32 {
	now := uint32(time.Now().Unix())
	for {
		mtrand.Seed(now)
		if mtrand.Rand() == value {
			return now
		}
		now--
	}
	panic("could not find seed")
}

func badSeed() {
	rand.Seed(time.Now().UnixNano())

	wait := rand.Intn(1000) + 40
	time.Sleep(time.Duration(wait) * time.Second)

	mtrand.Seed(uint32(time.Now().Unix()))
	wait = rand.Intn(1000) + 40
	time.Sleep(time.Duration(wait) * time.Second)
}

func main() {
	badSeed()

	value := mtrand.Rand()
	fmt.Println("Random value after delay:", value)

	// value := uint32(2384110541)
	foundSeed := breakSeed(value)
	fmt.Println("Seed discovered:", breakSeed(value))
	mtrand.Seed(foundSeed)
	fmt.Println("Reproduced value:", mtrand.Rand())
}
