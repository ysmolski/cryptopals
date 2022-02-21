package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
)

type PublicKey struct {
	N *big.Int //modulus
	E *big.Int
}

type PrivateKey struct {
	PublicKey          // public part
	D         *big.Int // private exponent
	P, Q      *big.Int // prime factors of N
}

type IsEvenFn func([]byte) bool

func GenParityOracle(priv *PrivateKey) IsEvenFn {
	return func(ct []byte) bool {
		pt := priv.RSADecrypt(ct)
		// fmt.Println(pt[len(pt)-1])
		return pt[len(pt)-1]&1 != 1
	}
}

func main() {
	bits := 1024
	e := int64(0x10001)
	var ct []byte
	var pub *PublicKey
	var isEvenOracle IsEvenFn // oracle with hidden private key
	{
		pt, err := base64.StdEncoding.DecodeString("VGhhdCdzIHdoeSBJIGZvdW4kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
		if err != nil {
			log.Fatal(err)
		}
		// pt := []byte("1")
		// fmt.Println(new(big.Int).SetBytes(pt))
		priv := RSAGenPQ(bits, e)
		pub = &priv.PublicKey
		ct = RSAEncrypt(pt, &priv.PublicKey)
		isEvenOracle = GenParityOracle(priv)
	}
	fmt.Println("pub mod =", pub.N)
	lower := big.NewInt(0)
	higher := new(big.Int).Set(pub.N)

	big2 := big.NewInt(2)
	encTwo := new(big.Int).Exp(big2, big.NewInt(e), pub.N)
	c0 := new(big.Int).SetBytes(ct)
	c := new(big.Int).Mul(c0, encTwo)
	c.Mod(c, pub.N)
	mid := new(big.Int)

	exp2 := big.NewInt(1)
	for ; exp2.Cmp(pub.N) < 0; exp2.Mul(exp2, big2) {
		mid.Add(lower, higher)
		mid.Div(mid, big2)
		fmt.Printf("%+q\n", string(higher.Bytes()))
		// fmt.Printf("lower=%+v mid=%+v higher=%+v\n", lower, mid, higher)
		even := isEvenOracle(c.Bytes())
		if even {
			higher.Set(mid)
		} else {
			lower.Set(mid)
		}
		c.Mul(c, encTwo)
		c.Mod(c, pub.N)
	}
	fmt.Printf("Found: %+q\n", string(lower.Bytes()))
	fmt.Printf("Found: %+q\n", string(mid.Bytes()))
	fmt.Printf("Found: %+q\n", string(higher.Bytes()))

}

func RSAGenPQ(bits int, e int64) *PrivateKey {
	priv := new(PrivateKey)
	priv.E = big.NewInt(e)
	var totient *big.Int
	for {
		// Primes generation is not robust, but I hope it will be enought for
		// crypto challenges.
		p, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			panic("error generating random prime")
		}
		q, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			panic("error generating random prime")
		}
		if p.Cmp(q) == 0 {
			continue
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
	priv.D = new(big.Int).ModInverse(priv.E, totient)
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
