package main

import (
	"cryptopals/util"
	"fmt"
	"math/rand"
	"time"
)

func waitRandom() {
	stime := rand.Int31n(1000) + 40
	time.Sleep(time.Duration(stime) * time.Second)
}

func crackSeed(n uint64) {
	ts := uint64(time.Now().Unix())
	for ts > 0 {
		mt := util.NewMT19337(ts)
		try := mt.Next()
		if try == n {
			fmt.Println("seed found:", ts)
			return
		}
		ts--
	}
	fmt.Println("seed was not found!")
}

func main() {
	waitRandom()
	ts := uint64(time.Now().Unix())
	mt := util.NewMT19337(ts)
	waitRandom()
	output := mt.Next()
	fmt.Println("output:", output)

	crackSeed(output)
}
