package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
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

func GenKey(priv *PrivateKey) {
	if priv.P == nil || priv.Q == nil || priv.G == nil {
		panic("parameters should not be empty")
	}
	priv.a = new(big.Int)
	buf := make([]byte, priv.Q.BitLen()/8)
	for {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			log.Fatal(err)
		}
		priv.a.SetBytes(buf)
		if priv.a.Sign() != 0 && priv.a.Cmp(priv.Q) < 0 {
			break
		}
	}
	priv.A = new(big.Int)
	priv.A.Exp(priv.G, priv.a, priv.P)
}

func Sign(priv *PrivateKey, hash []byte) (r, s *big.Int) {
	n := priv.Q.BitLen()
	if priv.P.Sign() <= 0 || priv.Q.Sign() <= 0 || priv.G.Sign() <= 0 || priv.a.Sign() <= 0 || n%8 != 0 {
		log.Fatal("parameters should not be empty")
	}
	n >>= 3
	// generate 1 < k < q
	k := new(big.Int)
	buf := make([]byte, n)
	for {
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			log.Fatal(err)
		}
		k.SetBytes(buf)
		if k.Sign() != 0 && k.Cmp(priv.Q) < 0 {
			break
		}
	}
	kInv := new(big.Int).ModInverse(k, priv.Q)
	if kInv == nil {
		log.Fatal("cannot calculate multiplicative inverse of k")
	}
	// r = (g**k mod p) mod q
	r = new(big.Int)
	r.Exp(priv.G, k, priv.P)
	r.Mod(r, priv.Q)

	d := new(big.Int).SetBytes(hash)
	// s = (d + a*r) * invmod(k, q) mod q
	s = new(big.Int)
	s.Mul(priv.a, r)
	s.Add(d, s)
	s.Mod(s, priv.Q)
	s.Mul(s, kInv)
	s.Mod(s, priv.Q)
	return
}

func Verify(pub *PublicKey, r, s *big.Int, hash []byte) bool {
	if pub.P.Sign() <= 0 || pub.Q.Sign() <= 0 || pub.G.Sign() <= 0 || pub.A.Sign() <= 0 {
		return false
	}
	sInv := new(big.Int).ModInverse(s, pub.Q)
	if sInv == nil {
		return false
	}
	d := new(big.Int).SetBytes(hash)
	// v1 = d * invmod(s, q) mod q
	v1 := new(big.Int).Mul(d, sInv)
	v1.Mod(v1, pub.Q)

	// v2 = r * invmod(s, q) mod q
	v2 := new(big.Int).Mul(r, sInv)
	v2.Mod(v2, pub.Q)

	// z = ((g**v1 * A**v2) mod p) mod q
	z := new(big.Int).Exp(pub.G, v1, pub.P)
	z.Mul(z, new(big.Int).Exp(pub.A, v2, pub.P))
	z.Mod(z, pub.P)
	z.Mod(z, pub.Q)

	return z.Cmp(r) == 0
}

func test() {
	params := PregenParameters()
	priv := new(PrivateKey)
	priv.Parameters = *params
	GenKey(priv)
	// fmt.Printf("priv = %+v\n", priv)
	// fmt.Printf("priv.a = %+v\n", priv.a)

	doc := []byte("im here")
	hash := sha1.Sum(doc)
	r, s := Sign(priv, hash[:])

	fmt.Printf("r = %+v\n", r)
	fmt.Printf("s = %+v\n", s)

	ok := Verify(&priv.PublicKey, r, s, hash[:])
	fmt.Println(ok)
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

func main() {
	// test()
	params := PregenParameters()
	priv := new(PrivateKey)
	priv.Parameters = *params
	priv.PublicKey.A, _ = new(big.Int).SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	hash, _ := hex.DecodeString("d2d0714f014a9784047eaeccf956520045c45265")
	r, _ := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)

	// determine k from 0 .. 0x10000
	k := new(big.Int)
	one := big.NewInt(1)
	for k.Int64() < 0x10000 {
		r2 := new(big.Int).Exp(priv.G, k, priv.P)
		r2.Mod(r2, priv.Q)
		if r2.Cmp(r) == 0 {
			break
		}
		k.Add(k, one)
	}
	fmt.Println("found k =", k)

	a := calcAGivenK(r, s, k, new(big.Int).SetBytes(hash), priv.Q)
	fmt.Println("a =", a)
	aHex := hex.EncodeToString(a.Bytes())
	fmt.Println("hex(a) =", aHex)

	aSha1 := sha1.Sum([]byte(aHex))
	fmt.Printf("SHA1(hex(a)) = %x\n", aSha1)
}
