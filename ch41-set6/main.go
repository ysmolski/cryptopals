package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"tools"
)

type Intercept struct {
	ct  []byte
	pub *PublicKey
}

type Decryptor func([]byte) []byte

func GenDecryptOracle(priv *PrivateKey) Decryptor {
	return func(ct []byte) []byte {
		return priv.RSADecrypt(ct)
	}
}

func main() {
	bits := 1024
	e := int64(0x10001)
	// What was intercepted.
	capt := new(Intercept)
	var decryptOracle Decryptor // oracle with hidden private key
	{
		plaintext := []byte("our secret message is unknown to others")
		priv := RSAGenPQ(bits, e)
		capt.pub = &priv.PublicKey
		capt.ct = RSAEncrypt(plaintext, &priv.PublicKey)
		decryptOracle = GenDecryptOracle(priv)
	}
	// c' = s**e * ct = (s*pt)**e mod N
	s := new(big.Int).SetBytes(tools.RandBytes(16))
	// cp = s^e * ct mod N
	cp := new(big.Int)
	cp.Exp(s, capt.pub.E, capt.pub.N)
	cp.Mul(cp, new(big.Int).SetBytes(capt.ct))
	cp.Mod(cp, capt.pub.N)

	// pt = s*pt * invmod(s, N) mod N
	pprime := new(big.Int).SetBytes(decryptOracle(cp.Bytes()))
	sInv := Invmod(s, capt.pub.N)
	pprime.Mul(pprime, sInv)
	pprime.Mod(pprime, capt.pub.N)

	fmt.Printf("revealed pt = %s\n", pprime.Bytes())
}

var (
	n0  = big.NewInt(0)
	n1  = big.NewInt(1)
	n2  = big.NewInt(2)
	n3  = big.NewInt(3)
	n10 = big.NewInt(10)
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
