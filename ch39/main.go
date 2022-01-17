package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

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
	if m.Cmp(a) < 0 {
		panic("a should be less than m")
	}
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

func main() {
	// fmt.Println(ExtendedGCD(big.NewInt(67), big.NewInt(12)))
	// fmt.Println(Invmod(big.NewInt(17), big.NewInt(3120)))

	bits := 160
	priv := RSAGenPQ(bits, 3)
	fmt.Printf("priv = %+v\n", priv)
	fmt.Println("N has bits:", priv.N.BitLen())
	{
		plaintext := []byte("equal to 20 bytes123") // our message
		fmt.Printf("\nm  = %#v\n", string(plaintext))
		c := RSAEncrypt(plaintext, &priv.PublicKey)
		fmt.Println("c  =", c)

		m2 := priv.RSADecrypt(c)
		fmt.Printf("m2 = %#v\n", string(m2))
	}
	{
		plaintext := []byte("short") // our message
		fmt.Printf("\nm  = %#v\n", string(plaintext))
		c := RSAEncrypt(plaintext, &priv.PublicKey)
		fmt.Println("c  =", c)

		m2 := priv.RSADecrypt(c)
		fmt.Printf("m2 = %#v\n", string(m2))
	}
}
