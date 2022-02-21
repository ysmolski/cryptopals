// Challenge 56: RC4 Single-Byte Biases

package main

import (
	"crypto/rc4"
	"encoding/base64"
	"fmt"
	"log"
	"sort"
	"tools"
)

func pow(a, b int) int {
	p := 1
	for b > 0 {
		if b&1 != 0 {
			p *= a
		}
		b >>= 1
		a *= a
	}
	return p
}

var cookie []byte
var dst []byte

func init() {
	var err error
	cookie, err = base64.StdEncoding.DecodeString("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F")
	if err != nil {
		log.Fatal(err)
	}
}

func oracle(req []byte) []byte {
	c, err := rc4.NewCipher(tools.RandBytes(16))
	if err != nil {
		log.Fatal(err)
	}
	req = append(req, cookie...)
	dst := make([]byte, len(req))
	c.XORKeyStream(dst, req)
	return dst
}

type ByteCount struct {
	b int
	c int
}

func sortBytes(hist [256]int) []ByteCount {
	pairs := make([]ByteCount, len(hist))
	for pos, cnt := range hist {
		pairs[pos] = ByteCount{pos, cnt}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].c > pairs[j].c })
	return pairs
}

func main() {
	// len is 30
	prefix := make([]byte, 0, 48)
	prefix = append(prefix, byte('A'))
	runs := pow(2, 24)
	fmt.Println("runs =", runs)
	// target positions:
	// 15 has bias for 240
	// 31 has bias for 224
	p1 := 15
	p2 := 31
	bias1 := 240
	bias2 := 224
	pt := make([]byte, 30)
	for plen := 2; plen < 18; plen++ {
		prefix = append(prefix, byte('A'))
		var hist1 [256]int
		var hist2 [256]int
		for i := 0; i < runs; i++ {
			if i%1000000 == 0 {
				fmt.Printf(".")
			}
			ct := oracle(prefix)
			hist1[ct[p1]] += 1
			hist2[ct[p2]] += 1
			// fmt.Printf("ct = %+x\n", ct)
		}
		fmt.Println("")
		if p1-plen >= 0 {
			pairs1 := sortBytes(hist1)
			for _, bc := range pairs1[:2] {
				fmt.Printf("pt[%d] = %+q  cnt=%d\n", p1-plen, byte(bc.b^bias1), bc.c)
			}
			pt[p1-plen] = byte(pairs1[0].b ^ bias1)
		}
		pairs2 := sortBytes(hist2)
		for _, bc := range pairs2[:2] {
			fmt.Printf("pt[%d] = %+q  cnt=%d\n", p2-plen, byte(bc.b^bias2), bc.c)
		}
		pt[p2-plen] = byte(pairs2[0].b ^ bias2)
		fmt.Printf("pt = %+q\n", string(pt))
	}
}
