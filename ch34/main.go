package main

import (
	"crypto/aes"
	"fmt"
	"log"
	"math/big"
	"tools"
)

func main() {
	p, ok := new(big.Int).SetString(`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16)
	if !ok {
		panic("cannot load p")
	}
	g := big.NewInt(2)

	// protocol init DHKE
	publicA := new(big.Int)
	privateA := new(big.Int)
	tools.DHKEGenKeys(publicA, privateA, p, g)

	fmt.Println("A -> M (p, g, publicA)")
	fmt.Println("M -> B (p, g, p)")
	forgedPublicA := p

	publicB := new(big.Int)
	privateB := new(big.Int)
	tools.DHKEGenKeys(publicB, privateB, p, g)
	fmt.Println("B -> M (publicB)")
	fmt.Println("M -> A (p instead of B)")
	forgedPublicB := p

	// generated on A side
	sA := tools.DHKESessionKey(forgedPublicB, privateA, p)
	fmt.Printf("sA = %x\n", sA)

	// generated on B side
	sB := tools.DHKESessionKey(forgedPublicA, privateB, p)
	fmt.Printf("sB = %x\n", sB)

	// generated on M side. Since s is zero, no need to know private a or
	// b key.
	sM := tools.DHKESessionKey(forgedPublicA, new(big.Int).SetInt64(13), p)
	fmt.Printf("sM = %x\n", sM)

	block, err := aes.NewCipher(sA[:16])
	if err != nil {
		log.Fatal(err)
	}
	ivA := tools.RandBytes(block.BlockSize())
	msgA := []byte("This message is from A to B")
	dataA := tools.PadPKCS7(msgA, block.BlockSize())
	ct := make([]byte, len(dataA))
	tools.CBCEncrypt(block, ivA, ct, dataA)

	// here we prove that M can decrypt pt using sM.
	recovered := MITM(sM, ivA, ct)
	fmt.Printf("M intercepted this message: %#v\n", string(recovered))
}

func MITM(sM, iv, ct []byte) []byte {
	block, err := aes.NewCipher(sM[:16])
	if err != nil {
		log.Fatal(err)
	}
	padded := make([]byte, len(ct))
	tools.CBCDecrypt(block, iv, padded, ct)
	pt, err := tools.UnpadPKCS7(padded)
	if err != nil {
		log.Fatal(err)
	}
	return pt
}
