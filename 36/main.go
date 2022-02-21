package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"tools"
)

var N = new(big.Int)
var G = big.NewInt(2)
var K = big.NewInt(3)

func init() {
	var ok bool
	N, ok = new(big.Int).SetString(`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16)
	if !ok {
		panic("cannot load p")
	}
}

type Server struct {
	N, G, K *big.Int
	// email to UserRec
	users map[string]UserRec
}

type UserRec struct {
	salt, v *big.Int
}

func SaltedPass(salt *big.Int, password string) *big.Int {
	hash := sha256.New()
	hash.Write(salt.Bytes())
	hash.Write([]byte(password))
	hex := hash.Sum(nil)
	x := new(big.Int).SetBytes(hex)
	return x
}

func NewServer(n, g, k *big.Int) *Server {
	return &Server{N: n, G: g, K: k, users: make(map[string]UserRec)}
}

func (s *Server) AddUser(email, password string) {
	salt, err := rand.Int(rand.Reader, s.N)
	if err != nil {
		log.Fatal(err)
	}
	x := SaltedPass(salt, password)
	v := new(big.Int)
	v.Exp(s.G, x, s.N)
	s.users[email] = UserRec{salt, v}
	fmt.Println(salt, v)
}

func (s *Server) Login1(email string) (user UserRec, public, private *big.Int) {
	user = s.users[email]
	var err error
	private, err = rand.Int(rand.Reader, s.N)
	if err != nil {
		log.Fatal(err)
	}
	// B=kv + g**b % N
	public = new(big.Int)
	public.Exp(s.G, private, s.N)
	kv := new(big.Int)
	kv.Mul(s.K, user.v)
	public.Add(kv, public)
	public.Mod(public, s.N)
	return
}

func SumPublicKeys(a, b *big.Int) *big.Int {
	hash := sha256.New()
	hash.Write(a.Bytes())
	hash.Write(b.Bytes())
	uhex := hash.Sum(nil)
	u := new(big.Int).SetBytes(uhex)
	return u
}

func main() {
	email := "foo@bar.com"
	pass := "can be0anything$02bk2nd" // known only to the client
	serv := NewServer(N, G, K)
	// agree on parameters and register an user
	serv.AddUser(email, pass)

	// C->S
	//     Send I, A=g**a % N (a la Diffie Hellman)

	A := new(big.Int)
	a := new(big.Int)
	tools.DHKEGenKeys(A, a, N, G)

	// S->C
	//     Send salt, B=kv + g**b % N
	userRec, B, b := serv.Login1(email)
	salt := userRec.salt
	fmt.Println(salt)
	fmt.Println(B)
	fmt.Println(b)

	// S, C
	//     Compute string uH = SHA256(A|B), u = integer of uH

	// C
	//     Generate string xH=SHA256(salt|password)
	//     Convert xH to integer x somehow (put 0x on hexdigest)
	//     Generate S = (B - k * g**x)**(a + u * x) % N
	//     Generate K = SHA256(S)
	sClient := new(big.Int)
	{
		u := SumPublicKeys(A, B)
		x := SaltedPass(salt, pass)
		i := new(big.Int)
		i.Exp(G, x, N)
		i.Mul(K, i)
		i.Sub(B, i)
		j := new(big.Int)
		j.Mul(u, x)
		j.Add(a, j)
		sClient.Exp(i, j, N)
	}
	keyClient := sha256.Sum256(sClient.Bytes())
	fmt.Printf("keyClient = %x\n", string(keyClient[:]))

	// S
	//     Generate S = (A * v**u) ** b % N
	//     Generate K = SHA256(S)
	sServer := new(big.Int)
	{
		u := SumPublicKeys(A, B)
		i := new(big.Int)
		i.Exp(userRec.v, u, serv.N)
		i.Mul(A, i)
		sServer.Exp(i, b, serv.N)
	}
	keyServer := sha256.Sum256(sServer.Bytes())
	fmt.Printf("keyServer = %x\n", string(keyServer[:]))

	// C->S
	//     Send HMAC-SHA256(K, salt)
	hm := hmac.New(sha256.New, keyClient[:])
	hm.Write(salt.Bytes())
	challenge := hm.Sum(nil)

	// S->C
	//     Send "OK" if HMAC-SHA256(K, salt) validates
	hm2 := hmac.New(sha256.New, keyServer[:])
	hm2.Write(salt.Bytes())
	valid := hm2.Sum(nil)

	if hmac.Equal(valid, challenge) {
		fmt.Println("OK")
	} else {
		fmt.Println("NOT VALID")
	}
}
