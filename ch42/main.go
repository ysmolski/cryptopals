package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"math/big"
)

var (
	n0  = big.NewInt(0)
	n1  = big.NewInt(1)
	n2  = big.NewInt(2)
	n3  = big.NewInt(3)
	n10 = big.NewInt(10)
)

func cbrtBinary(i *big.Int) (cbrt *big.Int, rem *big.Int) {
	var (
		guess = new(big.Int).Div(i, n2)
		dx    = new(big.Int)
		absDx = new(big.Int)
		minDx = new(big.Int).Abs(i)
		step  = new(big.Int).Abs(new(big.Int).Div(guess, n2))
		cube  = new(big.Int)
	)
	for {
		cube.Exp(guess, n3, nil)
		dx.Sub(i, cube)
		cmp := dx.Cmp(n0)
		if cmp == 0 {
			return guess, n0
		}

		absDx.Abs(dx)
		switch absDx.Cmp(minDx) {
		case -1:
			minDx.Set(absDx)
		case 0:
			return guess, dx
		}

		switch cmp {
		case -1:
			guess.Sub(guess, step)
		case +1:
			guess.Add(guess, step)
		}

		step.Div(step, n2)
		if step.Cmp(n0) == 0 {
			step.Set(n1)
		}
	}
}

// ExtendedGCD returns x, y and gcd(a, b) that satisfies:
// ax + by = gcd(a, b)
func ExtendedGCD(a, b *big.Int) (x, y, gcd *big.Int) {
	oldr, r := a, b
	olds, s := big.NewInt(1), big.NewInt(0)
	oldt, t := big.NewInt(0), big.NewInt(1)
	for r.Cmp(new(big.Int)) != 0 {
		quot := new(big.Int).Div(oldr, r)
		oldr, r = r, new(big.Int).Sub(oldr, new(big.Int).Mul(quot, r))
		olds, s = s, new(big.Int).Sub(olds, new(big.Int).Mul(quot, s))
		oldt, t = t, new(big.Int).Sub(oldt, new(big.Int).Mul(quot, t))
	}
	if oldt.Cmp(new(big.Int)) < 0 {
		oldt.Add(oldt, a)
	}
	x, y, gcd = olds, oldt, oldr
	return
}

func Invmod(a, m *big.Int) *big.Int {
	// if m.Cmp(a) < 0 {
	// 	panic("a should be less than m")
	// }
	_, y, _ := ExtendedGCD(m, a)
	return y
}

type PublicKey struct {
	N *big.Int //modulus
	E *big.Int
}

type PrivateKey struct {
	PublicKey          // public part
	D         *big.Int // private exponent
	P, Q      *big.Int // prime factors of N
}

func RSAGenPQ(bits int, e int64) *PrivateKey {
	priv := new(PrivateKey)
	priv.E = big.NewInt(e)
	var totient *big.Int
	for {
		// Primes generation is not correct, but I hope it will be enought for
		// crypto challenges.
		p, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			panic("error generating random prime")
		}
		q, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			panic("error generating random prime")
		}
		one := big.NewInt(1)
		totient = new(big.Int).Sub(p, one)
		tmp := new(big.Int).Sub(q, one)
		totient.Mul(totient, tmp)
		if tmp.Rem(totient, priv.E).Cmp(new(big.Int)) != 0 {
			priv.P = p
			priv.Q = q
			break
		}
		// fmt.Println("(p-1)(q-1) divisible by e")
	}

	priv.N = new(big.Int).Mul(priv.P, priv.Q)
	priv.D = Invmod(priv.E, totient)
	return priv
}

// RSAEncrypt encrypts msg with E, N from pub and returns
// bytes representation of the bignum result
func RSAEncrypt(msg []byte, pub *PublicKey) []byte {
	num := new(big.Int).SetBytes(msg)
	c := new(big.Int).Exp(num, pub.E, pub.N)
	return c.Bytes()
}

func (priv *PrivateKey) RSADecrypt(c []byte) []byte {
	cnum := new(big.Int).SetBytes(c)
	cnum.Exp(cnum, priv.D, priv.N)
	return cnum.Bytes()
}

// ASN.1 prefix used for SHA1. We allow use of SHA1 only for the simplicity.
var HashPrefix = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}

func main() {
	msg := "hi mom"
	h := sha1.Sum([]byte(msg))
	hashed := h[:]

	priv := RSAGenPQ(1024, 3)
	pub := &priv.PublicKey

	var forgedSignature []byte
	maxGarbageSize := len(pub.N.Bytes()) - 4 - len(HashPrefix) - len(hashed)
	// lets figure out the garbageSize. This algo does not work for sha256
	for garbageSize := 60; garbageSize < maxGarbageSize; garbageSize++ {
		// 00 01 ff ... ff 00h ASN.1 HASH GARBAGE
		// fmt.Println(garbageSize)
		dig := make([]byte, len(pub.N.Bytes()))
		dig[1] = 0x01
		fill := len(dig) - 3 - len(HashPrefix) - len(hashed) - garbageSize

		for i := 0; i < fill; i++ {
			dig[i+2] = 0xff
		}
		copy(dig[fill+3:], HashPrefix)
		copy(dig[fill+3+len(HashPrefix):], hashed)

		garb := make([]byte, garbageSize)
		copy(dig[len(dig)-garbageSize:], garb)
		// fmt.Printf("dig  = %x\n", dig)

		dnum := new(big.Int).SetBytes(dig)
		root, _ := cbrtBinary(dnum)
		fmt.Printf("     %x\n", root.Bytes())
		cube := new(big.Int).Exp(root, big.NewInt(3), pub.N)
		// fmt.Printf("cube =   %x\n", cube.Bytes())

		// if cube matches dig from the start til the end of hashed then we
		// found our signature=root
		if bytes.Equal(dig[1:len(dig)-garbageSize], cube.Bytes()[:len(dig)-garbageSize-1]) {
			fmt.Println("found proper garbageSize:", garbageSize)
			forgedSignature = root.FillBytes(make([]byte, len(dig)))
			break
		}
	}
	fmt.Printf("sign=%x len=%d\n", forgedSignature, len(forgedSignature))

	// Now, verify that sign is "correct" signature for the hashed value
	ok := verifyOracle(pub, hashed, forgedSignature)
	fmt.Println("verify =", ok)
}

func verifyOracle(pub *PublicKey, hashed, sig []byte) bool {
	k := len(pub.N.Bytes())
	hashLen := sha1.Size
	if k != len(sig) {
		return false
	}
	m := new(big.Int).SetBytes(sig)
	m.Exp(m, pub.E, pub.N)
	em := m.FillBytes(make([]byte, k))
	ok := subtle.ConstantTimeByteEq(em[0], 0)
	ok &= subtle.ConstantTimeByteEq(em[1], 1)
	// here we make the mistake of scanning bytes until zero
	// so it can be any amount of FF bytes
	i := 2
	ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
	for ; em[i] == 0xff; i++ {
	}
	ok &= subtle.ConstantTimeByteEq(em[i], 0)
	i++
	ok &= subtle.ConstantTimeCompare(em[i:i+len(HashPrefix)], HashPrefix)
	i += len(HashPrefix)
	ok &= subtle.ConstantTimeCompare(em[i:i+hashLen], hashed)
	return ok == 1
}
