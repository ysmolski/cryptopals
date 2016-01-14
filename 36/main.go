package main

/*
Implement Secure Remote Password (SRP)

Replace A and B with C and S (client & server)

C & S
Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)

S
Generate salt as random integer
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate v=g**x % N
Save everything but x, xH

C->S
Send I, A=g**a % N (a la Diffie Hellman)

S->C
Send salt, B=kv + g**b % N

S, C
Compute string uH = SHA256(A|B), u = integer of uH

C
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate S = (B - k * g**x)**(a + u * x) % N
Generate K = SHA256(S)

S
Generate S = (A * v**u) ** b % N
Generate K = SHA256(S)

C->S
Send HMAC-SHA256(K, salt)

S->C
Send "OK" if HMAC-SHA256(K, salt) validates

*/

import (
	"crypto/sha256"
	"cryptopals/util"
	"fmt"
	"math/big"
)

var (
	NStr = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327fffffffffffff"
)

func main() {
	// C & S
	N, _ := big.NewInt(0).SetString(NStr, 0)
	g := big.NewInt(2)
	k := big.NewInt(3)
	// i := []byte("some@email.com")
	p := []byte("secret-pass")

	// S
	salt := util.RandBytes(16)
	xH := sha256.Sum256(append(salt, p...))
	x := big.NewInt(0).SetBytes(xH[0:32])
	fmt.Printf("%s \n%x\n\n", x, x)
	v := big.NewInt(0).Exp(g, x, N)
	v.Mod(v, N)
	fmt.Printf("v = %x\n", v)

	// C->S: I, A=g**a % N
	A, a := util.GenExpPair(N, g)

	// S->C: salt, B=kv + g**b % N
	b := util.RandomBig(N)
	B := big.NewInt(0).Exp(g, b, N)
	kv := big.NewInt(0).Mul(k, v)
	B.Add(kv, B)
	B.Mod(B, N)

	// S, C
	uH := sha256.Sum256([]byte(A.String() + B.String()))
	u := big.NewInt(0).SetBytes(uH[0:32])

	// C
	xHClient := sha256.Sum256(append(salt, p...))
	xClient := big.NewInt(0).SetBytes(xHClient[0:32])
	// S = (B - k * g**x)**(a + u * x) % N
	left := big.NewInt(0)
	left.Exp(g, xClient, N)
	left.Mul(k, left)
	left.Sub(B, left)
	right := big.NewInt(0)
	right.Mul(u, xClient)
	right.Add(a, right)
	sClient := big.NewInt(0).Exp(left, right, N)
	sClient.Mod(sClient, N) // S
	KClient := sha256.Sum256(sClient.Bytes())
	fmt.Printf("KClient = %x\n", KClient)

	HMacClient := util.HMacSha256(KClient[:32], salt)
	fmt.Printf("HMAC Client = %x\n", HMacClient)

	// S
	// sServer = (A * v**u) ** b % N
	left.Exp(v, u, N)
	left.Mul(A, left)
	sServer := big.NewInt(0).Exp(left, b, N)
	KServer := sha256.Sum256(sServer.Bytes())
	fmt.Printf("KServer = %x\n", KServer)

	HMacServer := util.HMacSha256(KServer[:32], salt)
	fmt.Printf("HMAC Server = %x\n", HMacServer)
}
