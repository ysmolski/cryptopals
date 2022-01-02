package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ysmolsky/cryptopals/tools"
	"github.com/ysmolsky/cryptopals/tools/mtrand"
)

var seed uint32

func init() {
	rand.Seed(time.Now().Unix())
	seed = uint32(rand.Int() & 0xFFFF)
}

func oracle(input []byte) []byte {
	rng := mtrand.NewSource()
	rng.Seed(seed)

	prefix := tools.RandBytes(int(tools.RandByte()))
	pt := append(prefix, input...)
	ct := make([]byte, len(pt))
	mtrand.MTEncrypt(rng, ct, pt)
	return ct
}

func main() {
	known := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ct := oracle(known)
	prefixLen := len(ct) - len(known)
	stream := make([]byte, len(known))
	copy(stream, ct[prefixLen:])

	for i := 0; i < len(stream); i++ {
		stream[i] ^= 'a'
	}

	seed := -1
outer:
	for i := 0; i < 0xFFFF; i++ {
		rng := mtrand.NewSource()
		rng.Seed(uint32(i))
		// lets pretend that we do not know how many to skip
		// so we skip until we find first matching byte
		c := 0
		for c < len(ct)*2 {
			for byte(rng.Rand()&0xFF) != stream[0] {
				c++
			}
			passed := true
			// test how many will of aaa's will be indentical
			for j := 1; j < len(stream); j++ {
				if stream[j] != byte(rng.Rand()&0xff) {
					passed = false
					break
				}
				c++
			}
			if passed {
				fmt.Println("Found seed:", i)
				seed = i
				break outer
			}
		}
	}
	if seed >= 0 {
		rng := mtrand.NewSource()
		rng.Seed(uint32(seed))
		recovered := make([]byte, len(ct))
		mtrand.MTEncrypt(rng, recovered, ct)
		fmt.Printf("recovered = %+v\n", string(recovered))
	}
}
