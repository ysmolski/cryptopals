package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"strings"
	"time"
	"tools"
)

var N = new(big.Int)
var G = big.NewInt(2)
var K = big.NewInt(3)
var secretPass string // used by a user to try to login into our malicious server
var words []string    // used by the server to guess password

func init() {
	var ok bool
	N, ok = new(big.Int).SetString(`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff`, 16)
	if !ok {
		panic("cannot load p")
	}
	ws, err := ioutil.ReadFile("./wordlist.txt")
	if err != nil {
		log.Fatal(err)
	}
	words = strings.Fields(string(ws))
	mrand.Seed(time.Now().UnixNano())
	secretPass = words[mrand.Intn(len(words))]
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
	v := new(big.Int).Exp(s.G, x, s.N)
	s.users[email] = UserRec{salt, v}
}

func (s *Server) Login1(email string) (user UserRec, public, private *big.Int, u128 []byte) {
	// B=public, b=private
	user = s.users[email]
	var err error
	private, err = rand.Int(rand.Reader, s.N)
	if err != nil {
		log.Fatal(err)
	}
	// B=g**b % N
	public = new(big.Int)
	public.Exp(s.G, private, s.N)
	u128 = tools.RandBytes(16)
	return
}

func (s *Server) ForgedLogin(email string) (salt, public, private *big.Int, u128 []byte) {
	// We generate a new salt for every login attempt, but maybe we should
	// register users as they try to login and save salt for future logins.
	// For now it will do since client won't try to detect that server is
	// malicious.
	var err error
	salt, err = rand.Int(rand.Reader, s.N)
	if err != nil {
		log.Fatal(err)
	}
	private, err = rand.Int(rand.Reader, s.N)
	if err != nil {
		log.Fatal(err)
	}
	// B=public, b=private
	// B=g**b % N
	public = new(big.Int)
	public.Exp(s.G, private, s.N)
	u128 = tools.RandBytes(16)
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

func MaliciousServer() {
	email := "foo@bar.com"

	// agree on parameters
	serv := NewServer(N, G, K)
	// Registering users does not make any sense.
	// Malicious server accepts any email and try to crack password for it.
	// serv.AddUser(email, "validpass")

	// C->S
	//     Send I, A=g**a % N (a la Diffie Hellman)

	A := new(big.Int)
	a := new(big.Int) // used only by the client
	tools.DHKEGenKeys(A, a, N, G)

	// S->C
	//     Send salt, B=g**b % N, u = 128 bit random number
	salt, B, b, uH := serv.ForgedLogin(email)
	u := new(big.Int).SetBytes(uH)

	// C
	//     Generate number x=SHA256(salt|password)
	//     Generate S = B**(a + u*x) % N
	//     Generate K = SHA256(S)
	// C->S
	//     Send clientHMAC = HMAC-SHA256(K, salt)
	var clientHMAC []byte
	{
		x := SaltedPass(salt, secretPass)
		j := new(big.Int)
		j.Mul(u, x)
		j.Add(a, j)
		sClient := new(big.Int).Exp(B, j, N)
		keyClient := sha256.Sum256(sClient.Bytes())
		hm := hmac.New(sha256.New, keyClient[:])
		hm.Write(salt.Bytes())
		clientHMAC = hm.Sum(nil)
	}

	// Now Server has "received" keyClient and will try to guess
	// password using dictionary. The only value server does not know is
	// v, but it can be calculated for every word from dictionary. This is why
	// not mixing password in B is weakness and allows this kind of attack.
	// S
	//     For every word from wordlist:
	//     Generate x = SHA256(salt|password)
	//              v = g**x % n
	//     Generate S = (A * v**u) ** b % N
	//     Generate K = SHA256(S)
	//     Generate guessHMAC = HMAC-SHA256(K, salt)
	//     Compare clientHMAC with guessHMAC. They match for correct pass.
	var word string
	for _, word = range words {
		sServer := new(big.Int)
		x := SaltedPass(salt, word)
		v := new(big.Int).Exp(serv.G, x, serv.N)
		i := new(big.Int).Exp(v, u, serv.N)
		i.Mul(A, i)
		sServer.Exp(i, b, serv.N)
		keyServer := sha256.Sum256(sServer.Bytes())
		hm2 := hmac.New(sha256.New, keyServer[:])
		hm2.Write(salt.Bytes())
		guessHMAC := hm2.Sum(nil)
		if hmac.Equal(guessHMAC, clientHMAC) {
			fmt.Println("found password: ", word)
			break
		}
	}
	fmt.Println("Checking recovered password against secretPass...")
	fmt.Printf("secretPass = %+v\n", secretPass)
	fmt.Printf("recovered  = %+v\n", word)
	if secretPass == word {
		fmt.Println("100% match")
	} else {
		fmt.Println("Something went wrong. They do not match.")
	}
}

func main() {
	MaliciousServer()
}

func NormalServer() {
	email := "foo@bar.com"

	serv := NewServer(N, G, K)
	// agree on parameters and register an user
	serv.AddUser(email, "validpass")

	// C->S
	//     Send I, A=g**a % N (a la Diffie Hellman)

	A := new(big.Int)
	a := new(big.Int) // used only by the client
	tools.DHKEGenKeys(A, a, N, G)

	// S->C
	//     Send salt, B=g**b % N, u = 128 bit random number
	userRec, B, b, uH := serv.Login1(email)
	salt := userRec.salt
	u := new(big.Int).SetBytes(uH)

	// C
	//     Generate number x=SHA256(salt|password)
	//     Generate S = B**(a + u*x) % N
	//     Generate K = SHA256(S)
	sClient := new(big.Int)
	{
		pass := "validpass" // known only to the client
		x := SaltedPass(salt, pass)
		j := new(big.Int)
		j.Mul(u, x)
		j.Add(a, j)
		sClient.Exp(B, j, N)
	}
	keyClient := sha256.Sum256(sClient.Bytes())
	fmt.Printf("keyClient = %x\n", string(keyClient[:]))

	// S
	//     Generate S = (A * v**u) ** b % N
	//     Generate K = SHA256(S)
	sServer := new(big.Int)
	{
		i := new(big.Int).Exp(userRec.v, u, serv.N)
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
		fmt.Println("NOT OK")
	}
}
