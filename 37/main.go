package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"tools"
)

var N = new(big.Int)
var G = big.NewInt(2)
var K = big.NewInt(3)

const (
	EndPoint = "127.0.0.1:9999"
)

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
	// fmt.Println(salt, v)
}

func (s *Server) StartUserSession(email string) (user UserRec, public, private *big.Int) {
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

func runServer() {
	// create server with one user
	s := NewServer(N, G, K)
	email := "foo@bar.com"
	pass := "easy"
	s.AddUser(email, pass)

	ln, err := net.Listen("tcp", EndPoint)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("listening on", EndPoint)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("connection error: %v", err)
			continue
		}
		go s.serveClient(conn)
	}
}

func makeLineReader(conn net.Conn) func() string {
	bufReader := bufio.NewReader(conn)
	readLine := func() string {
		line, err := bufReader.ReadString('\n')
		if err != nil {
			log.Printf("err = %+v\n", err)
		}
		return strings.TrimSpace(line)
	}
	return readLine
}

func (s *Server) serveClient(conn net.Conn) {
	log.Println(conn.RemoteAddr(), "connected")
	defer log.Println(conn.RemoteAddr(), "disconnected")
	readLine := makeLineReader(conn)

	var err error

	// Receive email and A
	email := readLine()
	log.Printf("email = %+v\n", email)
	str := readLine()
	A, ok := new(big.Int).SetString(str, 10)
	if !ok {
		fmt.Fprintf(conn, "bad format\n")
		log.Printf("bad number A = %+v\n", str)
		return
	}
	log.Printf("A = %+v\n", A)

	// Send salt, B=kv + g**b % N
	userRec, B, b := s.StartUserSession(email)
	salt := userRec.salt
	_, err = fmt.Fprintln(conn, salt.String())
	if err != nil {
		log.Fatal(err)
	}
	_, err = fmt.Fprintln(conn, B.String())
	if err != nil {
		log.Fatal(err)
	}

	// Generate S = (A * v**u) ** b % N
	// Generate K = SHA256(S)
	sServer := new(big.Int)
	{
		u := SumPublicKeys(A, B)
		i := new(big.Int)
		i.Exp(userRec.v, u, s.N)
		i.Mul(A, i)
		sServer.Exp(i, b, s.N)
	}
	keyServer := sha256.Sum256(sServer.Bytes())
	log.Printf("keyServer = %x\n", string(keyServer[:]))

	hm := hmac.New(sha256.New, keyServer[:])
	hm.Write(salt.Bytes())
	ourSign := hm.Sum(nil)
	log.Printf("ourSign = %+x\n", ourSign)
	str = readLine()
	clientSign, err := hex.DecodeString(str)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("cliSign = %+x\n", clientSign)

	if hmac.Equal(ourSign, clientSign) {
		_, err = fmt.Fprintln(conn, "OK")
	} else {
		_, err = fmt.Fprintln(conn, "INVALID")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func loginClient(spoof bool, spoofedA *big.Int) bool {
	conn, err := net.Dial("tcp", EndPoint)
	if err != nil {
		log.Fatal(err)
	}
	readLine := makeLineReader(conn)

	// Don't ask user for email and password interactively
	email := "foo@bar.com"
	pass := ""

	// Send I, A=g**a % N (a la Diffie Hellman)
	A := new(big.Int)
	a := new(big.Int)
	tools.DHKEGenKeys(A, a, N, G)
	// Attack #1
	if spoof {
		A.Set(spoofedA)
	}
	// Attack #2
	// By setting A to zero or multiple of N,
	// we make S calculated on the server side equal to 0.
	// A.Set(A.Mul(N, big.NewInt(2)))
	_, err = fmt.Fprintln(conn, email)
	if err != nil {
		log.Fatal(err)
	}
	_, err = fmt.Fprintln(conn, A.String())
	if err != nil {
		log.Fatal(err)
	}

	// Receive Salt, B
	str := readLine()
	salt, ok := new(big.Int).SetString(str, 10)
	if !ok {
		fmt.Fprintf(conn, "bad format\n")
		log.Printf("bad number salt = %+v\n", str)
		return false
	}
	log.Printf("salt = %+v\n", salt)
	str = readLine()
	B, ok := new(big.Int).SetString(str, 10)
	if !ok {
		fmt.Fprintf(conn, "bad format\n")
		log.Printf("bad number B = %+v\n", str)
		return false
	}
	log.Printf("B = %+v\n", B)

	// Generate string xH=SHA256(salt|password)
	// Convert xH to integer x somehow (put 0x on hexdigest)
	// Generate S = (B - k * g**x)**(a + u * x) % N
	// Generate K = SHA256(S)
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
	// Attack
	if spoof {
		sClient.SetInt64(0)
	}
	keyClient := sha256.Sum256(sClient.Bytes())
	log.Printf("keyClient = %x\n", string(keyClient[:]))

	// Send HMAC-SHA256(K, salt)
	hm := hmac.New(sha256.New, keyClient[:])
	hm.Write(salt.Bytes())
	signedSalt := hm.Sum(nil)
	_, err = fmt.Fprintln(conn, hex.EncodeToString(signedSalt))
	if err != nil {
		log.Fatal(err)
	}
	resp := readLine()
	log.Printf("resp = %+v\n", resp)
	return resp == "OK"
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "server" {
		runServer()
	}

	cases := []struct {
		spoof bool
		A     *big.Int
	}{
		{false, nil},
		{true, big.NewInt(0)},
		{true, new(big.Int).Mul(N, big.NewInt(1))},
		{true, new(big.Int).Mul(N, big.NewInt(2))},
	}
	for _, t := range cases {
		valid := loginClient(t.spoof, t.A)
		fmt.Printf("spoofed = %t, A = %v, is valid = %+v\n", t.spoof, t.A, valid)
	}
}
