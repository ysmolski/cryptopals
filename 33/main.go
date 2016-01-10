package main

/*
Implement Diffie-Hellman

For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.

Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.
Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.
Do the same for "b" and "B".
"A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.
Do the same with A**b, check that you come up with the same "s".
To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).

Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes
*/

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	pStr = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
)

func randomBig(max *big.Int) *big.Int {
	i, _ := rand.Int(rand.Reader, max)
	return i
}

func genExpPair(p, g *big.Int) (pub, priv *big.Int) {
	a := randomBig(p)
	A := big.NewInt(0)
	A.Exp(g, a, p)
	return A, a
}

func main() {
	p := big.NewInt(0)
	p.SetString(pStr, 16)
	g := big.NewInt(2)

	A, a := genExpPair(p, g)
	B, b := genExpPair(p, g)

	s1 := big.NewInt(0)
	s2 := big.NewInt(0)
	s1.Exp(B, a, p)
	s2.Exp(A, b, p)
	fmt.Printf("a=%s\nA=%s\nb=%s\nB=%s\ns1=%s\ns2=%s \n", a, A, b, B, s1, s2)
}
