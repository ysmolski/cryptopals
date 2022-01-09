package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"sha1go"
	"strings"
	"time"
)

var prefix []byte

func init() {
	ws, err := ioutil.ReadFile("./wordlist.txt")
	if err != nil {
		log.Fatal(err)
	}
	words := strings.Fields(string(ws))
	rand.Seed(time.Now().UnixNano())
	prefix = []byte(words[rand.Intn(len(words))])
}

func sha1padding(length uint64) []byte {
	d := bytes.Buffer{}
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if length%64 < 56 {
		d.Write(tmp[0 : 56-length%64])
	} else {
		d.Write(tmp[0 : 64+56-length%64])
	}

	// Length in bits.
	length <<= 3
	binary.BigEndian.PutUint64(tmp[:], length)
	d.Write(tmp[0:8])
	return d.Bytes()
}

// signWithSecretPrefix signs URL prefixing it with secret word
func signWithSecretPrefix(msg []byte) [sha1go.Size]byte {
	d := append(prefix, msg...)
	return sha1go.Sum(d)
}

// isValidURL checks if mac for message is correct
func isValidURL(mac []byte, msg []byte) bool {
	d := append(prefix, msg...)
	got := sha1go.Sum(d)
	return bytes.Equal(got[:], mac)
}

func main() {
	spoofSuffix := []byte(";admin=true")
	data := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	mac1 := signWithSecretPrefix(data)
	fmt.Printf("initial mac: %x\n", mac1)
	// we need to guess the length of prefix
	for plen := 0; plen < 20; plen++ {
		padding := sha1padding(uint64(plen + len(data)))
		oldlen := uint64(plen + len(data) + len(padding))
		forgedHash := sha1go.NewForgery(mac1, oldlen)
		forgedHash.Write(spoofSuffix)

		forgedSum := forgedHash.Sum(nil)
		forgedMsg := append(data, append(padding, spoofSuffix...)...)

		valid := isValidURL(forgedSum, forgedMsg)
		if valid {
			fmt.Printf("Found valid padding: %x\n", padding)
			fmt.Printf("forged mac: %x\n", forgedSum)
			fmt.Printf("forged msg: %#v\n", string(forgedMsg))
			break
		}
	}
}
