package main

import (
	"crypto/aes"
	"crypto/sha1"
	"cryptopals/util"
	"fmt"
	"log"
	"math/big"
)

var (
	pStr = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
	// pStr = "37"
)

func aesCrypt(s *big.Int, t []byte) (ct, iv []byte) {
	sum := sha1.Sum([]byte(s.String()))
	blockA, _ := aes.NewCipher(sum[0:16])
	tPadded := util.PadTo(t, 16)
	ct = make([]byte, len(tPadded))
	iv = util.RandBytes(16)
	util.CBCEncrypt(blockA, iv, ct, tPadded)
	return
}

func aesDecrypt(s *big.Int, ct, iv []byte) (t []byte) {
	sum := sha1.Sum([]byte(s.String()))
	blockA, _ := aes.NewCipher(sum[0:16])
	tPadded := make([]byte, len(ct))
	util.CBCDecrypt(blockA, iv, tPadded, ct)
	t, err := util.CheckPadding(tPadded)
	if err != nil {
		log.Fatal(err, tPadded)
	}
	return
}

func main() {
	p := big.NewInt(0)
	p.SetString(pStr, 16)
	g := big.NewInt(2)
	A, a := util.GenExpPair(p, g)
	fmt.Println("A->B: p, g, A")

	// A->B
	// Send "p", "g", "A"

	B, b := util.GenExpPair(p, g)
	sB := big.NewInt(0)
	sB.Exp(A, b, p)
	fmt.Println("B->A: B")

	// B->A
	// Send "B"

	sA := big.NewInt(0)
	sA.Exp(B, a, p)

	t1 := []byte("secret message from Alice")
	ct1, iv1 := aesCrypt(sA, t1)
	fmt.Printf("A->B ct1=%x iv1=%x\n", ct1, iv1)

	// A->B
	// Send ct1, iv1 == AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv

	t1B := aesDecrypt(sB, ct1, iv1)
	fmt.Println("B received:", string(t1B))

	t2 := []byte("secret message from Bob")
	ct2, iv2 := aesCrypt(sB, t2)
	fmt.Printf("B->A ct2=%x iv2=%x\n", ct2, iv2)

	// B->A
	// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv

	t2A := aesDecrypt(sA, ct2, iv2)
	fmt.Println("A received:", string(t2A))

	fmt.Printf(" a = %s\n A = %s\n b = %s\n B = %s\n sA == sB -> %t \n", a, A, b, B, sA.Cmp(sB) == 0)
}
