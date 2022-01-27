package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"tools"
)

type PublicKey struct {
	N *big.Int // public modulus
	E *big.Int
}

type PrivateKey struct {
	PublicKey          // public part
	D         *big.Int // private exponent
	P, Q      *big.Int // prime factors of N
}

type IsPaddingValidFn func([]byte) bool

func GenPaddingOracle(priv *PrivateKey) IsPaddingValidFn {
	return func(ct []byte) bool {
		pt := priv.RSADecrypt(ct)
		// fmt.Println("padding:", pt[:2])
		return pt[0] == 0 && pt[1] == 2
	}
}

type interval struct {
	a, b *big.Int
}

func main() {
	bits := 256
	e := int64(3)
	var c []byte
	var pub *PublicKey
	var paddingOracle IsPaddingValidFn // oracle with hidden private key
	{
		m := []byte("kick it, CC")
		priv := RSAGenPQ(bits, e)
		pub = &priv.PublicKey
		c = RSAEncrypt(m, &priv.PublicKey)
		paddingOracle = GenPaddingOracle(priv)
	}
	fmt.Println("n=", pub.N)

	n := pub.N
	k := big.NewInt(int64(n.BitLen() >> 3))
	bigOne := big.NewInt(1)
	bigTwo := big.NewInt(2)
	bigThree := big.NewInt(3)
	bigE := big.NewInt(e)

	B := new(big.Int).Exp(
		bigTwo,
		new(big.Int).Mul(
			big.NewInt(8),
			new(big.Int).Sub(k, bigTwo)),
		n)
	fmt.Println("B=", B)
	B2 := new(big.Int).Mul(bigTwo, B)
	B3 := new(big.Int).Mul(bigThree, B)

	calcM := func(si *big.Int, prev []interval) []interval {
		m := make([]interval, 0)
		for _, ab := range prev {
			a := ab.a
			b := ab.b

			r0 := new(big.Int).Mul(a, si)
			r0.Sub(r0, B3)
			r0.Add(r0, bigOne)
			r0.Div(r0, n)

			r1 := new(big.Int).Mul(b, si)
			r1.Sub(r1, B2)
			r1.Div(r1, n)
			// fmt.Println("r0=", r0)
			// fmt.Println("r1=", r1)
			for r := new(big.Int).Set(r0); r.Cmp(r1) <= 0; r.Add(r, bigOne) {
				rem := new(big.Int)
				x := new(big.Int).Mul(r, n)
				x.Add(x, B2)
				x.QuoRem(x, si, rem)
				// ceil
				if rem.Sign() > 0 {
					x.Add(x, bigOne)
				}
				if x.Cmp(a) < 0 {
					x = a
				}

				y := new(big.Int).Mul(r, n)
				y.Add(y, B3)
				y.Sub(y, bigOne)
				y.Div(y, si)
				if y.Cmp(b) > 0 {
					y = b
				}
				// fmt.Println("r=", r, x, y)
				if x.Cmp(y) <= 0 {
					m = append(m, interval{x, y})
				}
			}
		}
		return m
	}

	c0 := new(big.Int).SetBytes(c)
	mprev := make([]interval, 1)
	mprev[0] = interval{B2, B3}
	mprev[0].b.Sub(mprev[0].b, bigOne)
	fmt.Printf("a = %v b = %v\n", mprev[0].a, mprev[0].b)

	goodPadding := func(si *big.Int) bool {
		try := new(big.Int).Exp(si, bigE, n)
		try.Mul(c0, try)
		try.Mod(try, n)
		return paddingOracle(try.Bytes())
	}

	// Step 2.a: Starting the search
	si := new(big.Int).Div(n, B3)
	for ; !goodPadding(si); si.Add(si, bigOne) {
	}
	fmt.Println("s1=", si)
	m := calcM(si, mprev)

	var sprev *big.Int
	// for i := 0; i < 3; i++ {
	for {
		mprev = m
		sprev = si

		si = new(big.Int)
		if len(mprev) > 1 {
			// Step 2.b: Searching with more than one interval left
			for si.Add(sprev, bigOne); !goodPadding(si); si.Add(si, bigOne) {
			}
		} else {
			// Step 2.c: Searching with one interval left
			a := mprev[0].a
			b := mprev[0].b
			fmt.Println("a =", a, "b =", b)
			r := new(big.Int).Mul(b, sprev)
			r.Sub(r, B2)
			r.Mul(r, bigTwo)
			r.Div(r, n)
			// fmt.Println("ri=", r)
			sUpper := new(big.Int)
		rsLoop:
			for ; ; r.Add(r, bigOne) {
				si.Mul(r, n)
				si.Add(si, B2)
				si.Div(si, b)
				// fmt.Println("si =", si)

				sUpper.Mul(r, n)
				sUpper.Add(sUpper, B3)
				sUpper.Div(sUpper, a)
				for ; si.Cmp(sUpper) <= 0; si.Add(si, bigOne) {
					if goodPadding(si) {
						break rsLoop
					}
				}
			}
		}
		m = calcM(si, mprev)
		// fmt.Println("si =", si, "|m| =", len(m))
		if len(m) == 1 && m[0].a.Cmp(m[0].b) == 0 {
			break
		}
	}

	fmt.Println("Solution found:")
	fmt.Printf("a = %v b = %v\n", m[0].a, m[0].b)
	fmt.Println("m =", m[0].a.Bytes())

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
	k := pub.N.BitLen()
	k >>= 3
	if len(msg) >= k-11 {
		log.Fatalf("msg len is %d, but RSA padding can fit %d", len(msg), k-11)
	}
	block := make([]byte, k)
	block[1] = 2
	ps := tools.RandBytes(k - len(msg) - 3)
	copy(block[2:], ps)
	copy(block[k-len(msg):], msg)
	// fmt.Println(block)

	m := new(big.Int).SetBytes(block)
	c := new(big.Int).Exp(m, pub.E, pub.N)
	b := c.FillBytes(make([]byte, k))
	return b
}

func (priv *PrivateKey) RSADecrypt(c []byte) []byte {
	k := priv.N.BitLen()
	k >>= 3
	cnum := new(big.Int).SetBytes(c)
	cnum.Exp(cnum, priv.D, priv.N)
	b := cnum.FillBytes(make([]byte, k))
	return b
}
