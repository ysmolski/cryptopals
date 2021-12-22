package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"

	"github.com/ysmolsky/cryptopals/tools"
)

var key []byte
var unknown []byte

func init() {
	key = tools.RandBytes(16)
}

func main() {
	// 0123456789abcdef 0123456789abcdef 0123456789abcdef
	// email=foobar%40d omain.com&id=100 &role=user
	// email=foobar%40d omain.com+++++++ +++&id=100&role= user
	// email=foobar%40d omain.com+++++++ admin&id=100&rol e=user
	email := "foobar@domain.com"
	ct := profileFor(email)
	fmt.Printf("encoded = %#v\n", hex.EncodeToString(ct))

	// email=foobar%40d omain.com+++++++ +++&id=100&role= user
	email = "foobar@domain.com          "
	ct = profileFor(email)
	forge := make([]byte, 0)
	forge = append(forge, ct[:3*16]...)
	end := make([]byte, 0)
	end = append(end, ct[3*16:]...)

	// email=foobar%40d omain.com+++++++ admin&id=100&rol e=user
	email = "foobar@domain.com       admin"
	ct = profileFor(email)
	admin := ct[2*16 : 3*16]

	forge = append(forge, admin...)
	forge = append(forge, end...)

	vals := decodeProfile(forge)
	fmt.Printf("decoded forge = %+v\n\n", vals)
}

func profileFor(email string) []byte {
	pars := make(url.Values)
	pars.Add("email", email)
	pars.Add("id", "100")
	pars.Add("role", "user")
	src := []byte(pars.Encode())

	blSize := len(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	src = tools.PadPKCS7(src, blSize)

	dst := make([]byte, len(src))
	tools.ECBEncrypt(block, dst, src)
	return dst
}

func decodeProfile(ct []byte) url.Values {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, len(ct))
	tools.ECBDecrypt(block, dst, ct)
	dst, err = tools.UnpadPKCS7(dst)
	if err != nil {
		log.Fatal(err)
	}
	vals, err := url.ParseQuery(string(dst))
	if err != nil {
		log.Fatal(err)
	}
	return vals
}
