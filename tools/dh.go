package tools

import (
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"
)

func DHKEGenKeys(public, private, p, g *big.Int) {
	n, err := rand.Int(rand.Reader, p)
	if err != nil {
		log.Fatal(err)
	}
	private.Set(n)
	public.Exp(g, private, p)
}

func DHKESessionKey(public, private, p *big.Int) []byte {
	s := new(big.Int)
	s.Exp(public, private, p)
	dig := sha256.Sum256(s.Bytes())
	return dig[:]
}
