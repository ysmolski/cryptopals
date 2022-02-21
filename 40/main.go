package main

import (
	"crypto/rand"
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

type Intercept struct {
	ct  []byte
	pub *PublicKey
}

func main() {
	bits := 256
	e := int64(3)
	captured := make([]Intercept, 3)
	for i := range captured {
		plaintext := []byte("equal to 20 bytes123") // our message
		priv := RSAGenPQ(bits, e)
		captured[i].pub = &priv.PublicKey
		captured[i].ct = RSAEncrypt(plaintext, &priv.PublicKey)
		fmt.Printf("c[i].pub = %+v\n", captured[i].pub)
		fmt.Printf("c[i].ct = %+x\n", captured[i].ct)
	}

	// verify that GCD(Ni, Nj) = 1
	gcd := new(big.Int)
	gcd.GCD(nil, nil, captured[0].pub.N, captured[1].pub.N)
	fmt.Println("gcd 0 1 =", gcd)
	gcd.GCD(nil, nil, captured[0].pub.N, captured[2].pub.N)
	fmt.Println("gcd 0 2 =", gcd)
	gcd.GCD(nil, nil, captured[1].pub.N, captured[2].pub.N)
	fmt.Println("gcd 1 2 =", gcd)

	// result =
	// (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
	// (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
	// (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

	ms := make([]*big.Int, 3)
	ms[0] = new(big.Int).Mul(captured[1].pub.N, captured[2].pub.N)
	ms[1] = new(big.Int).Mul(captured[0].pub.N, captured[2].pub.N)
	ms[2] = new(big.Int).Mul(captured[0].pub.N, captured[1].pub.N)

	c := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		c[i] = new(big.Int).SetBytes(captured[i].ct)
		c[i].Mul(c[i], ms[i])
		inv := Invmod(ms[i], captured[i].pub.N)
		c[i].Mul(c[i], inv)
	}
	c[0].Add(c[0], c[1])
	c[0].Add(c[0], c[2])
	N := new(big.Int).Mul(captured[0].pub.N, captured[1].pub.N)
	N.Mul(N, captured[2].pub.N)
	root, _ := cbrtBinary(c[0].Mod(c[0], N))
	fmt.Println("recovered =", string(root.Bytes()))
}
