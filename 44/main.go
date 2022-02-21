package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
)

type Parameters struct {
	P, Q, G *big.Int
}

type PublicKey struct {
	Parameters
	A *big.Int
}

type PrivateKey struct {
	PublicKey
	a *big.Int // private exponent
}

func PregenParameters() *Parameters {
	p := new(Parameters)
	p.P, _ = new(big.Int).SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
	p.Q, _ = new(big.Int).SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	p.G, _ = new(big.Int).SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
	return p
}

func calcAGivenK(r, s, k, d, q *big.Int) *big.Int {
	rInv := new(big.Int).ModInverse(r, q)
	if rInv == nil {
		log.Fatal("cannot invert r")
	}
	a := new(big.Int).Mul(s, k)
	a.Sub(a, d)
	a.Mul(a, rInv)
	a.Mod(a, q)
	return a
}

type Signature struct {
	r, s, hash *big.Int
}

func findSameK(filename string) (a, b *Signature) {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	signs := make([]Signature, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		_ = scanner.Text() // msg
		// skip the msg
		scanner.Scan()
		s := scanner.Text()[3:]
		snum, ok := new(big.Int).SetString(s, 10)
		if !ok {
			log.Fatalf("cannot read %s into big.Int", s)
		}
		scanner.Scan()
		r := scanner.Text()[3:]
		rnum, ok := new(big.Int).SetString(r, 10)
		if !ok {
			log.Fatalf("cannot read %s into big.Int", r)
		}
		scanner.Scan()
		m := scanner.Text()[3:]
		hash, ok := new(big.Int).SetString(m, 16)
		if !ok {
			log.Fatalf("cannot read %s into big.Int", m)
		}
		signs = append(signs, Signature{rnum, snum, hash})
	}

	for i := 0; i < len(signs)-1; i++ {
		for j := i + 1; j < len(signs); j++ {
			if signs[i].r.Cmp(signs[j].r) == 0 {
				return &signs[i], &signs[j]
			}
		}
	}
	return nil, nil
}

func main() {
	// test()
	params := PregenParameters()
	priv := new(PrivateKey)
	priv.Parameters = *params
	// we don't really need public key to solve chall. 44
	priv.PublicKey.A, _ = new(big.Int).SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)
	a, b := findSameK("44.txt")
	if a == nil || b == nil {
		log.Fatalf("could not find signatures with the same k (r)")
	}
	fmt.Println("Same k (r):")
	fmt.Printf("1: r=%s s=%s, hash=%s\n", a.r, a.s, a.hash)
	fmt.Printf("2: r=%s s=%s, hash=%s\n", b.r, b.s, b.hash)

	// determine k from two signatures with the same k
	// k = (a.hash-b.hash) * invmod(a.s-b.s, q)
	k := new(big.Int).Sub(a.hash, b.hash)
	k.Mod(k, priv.Q)

	inv := new(big.Int).Sub(a.s, b.s)
	inv.Mod(inv, priv.Q)
	res := inv.ModInverse(inv, priv.Q)
	if inv == nil {
		log.Fatalf("cannot determine multiplicative inverse of %s mod %s", res, priv.Q)
	}
	k.Mul(k, inv)
	k.Mod(k, priv.Q)
	fmt.Println("k =", k)

	privExp := calcAGivenK(a.r, a.s, k, a.hash, priv.Q)

	fmt.Println("privExp =", privExp)
	aHex := hex.EncodeToString(privExp.Bytes())
	fmt.Println("hex(privExp) =", aHex)
	aSha1 := sha1.Sum([]byte(aHex))
	fmt.Printf("SHA1(hex(privExp)) = %x\n", aSha1)
}
