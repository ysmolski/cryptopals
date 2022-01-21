package main

import (
	"crypto/rand"
	"crypto/sha1"
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

func main() {
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
