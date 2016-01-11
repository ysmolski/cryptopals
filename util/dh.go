package util

import (
	"crypto/rand"
	"math/big"
)

func RandomBig(max *big.Int) *big.Int {
	i, _ := rand.Int(rand.Reader, max)
	return i
}

func GenExpPair(p, g *big.Int) (pub, priv *big.Int) {
	a := RandomBig(p)
	A := big.NewInt(0)
	A.Exp(g, a, p)
	return A, a
}
