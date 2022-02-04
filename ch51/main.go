// Challenge 51: Compression Ratio Side-Channel Attacks
//
// Write this oracle:
//
// oracle(P) -> length(encrypt(compress(format_request(P))))
//
// Format the request like this:
//
// POST / HTTP/1.1
// Host: hapless.com
// Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
// Content-Length: ((len(P)))
// ((P))
//
// (Pretend you can't see that session id. You're the attacker.)
//
// Compress using zlib or whatever.
//
// Encryption... is actually kind of irrelevant for our purposes, but be a sport.
// Just use some stream cipher. Dealer's choice. Random key/IV on every call to
// the oracle.
//
// And then just return the length in bytes.
//
// Now, the idea here is to leak information using the compression library.
// A payload of "sessionid=T" should compress just a little bit better than, say,
// "sessionid=S".
//
// There is one complicating factor. The DEFLATE algorithm operates in terms of
// individual bits, but the final message length will be in bytes. Even if you do
// find a better compression, the difference may not cross a byte boundary. So
// that's a problem.

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"encoding/base64"
	"fmt"
	"log"
	"tools"
)

var headers = `POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
%s
`

func oracleStreamCipher(request []byte) int {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	fmt.Fprintf(w, headers, len(request), string(request))
	w.Close()
	ciph, err := rc4.NewCipher(tools.RandBytes(32))
	if err != nil {
		log.Fatal(err)
	}
	ct := make([]byte, b.Len())
	ciph.XORKeyStream(ct, b.Bytes())
	// fmt.Printf("ct = %+x\n", ct)

	return len(ct)
}

func oracleCBCCipher(request []byte) int {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	fmt.Fprintf(w, headers, len(request), string(request))
	w.Close()
	block, err := aes.NewCipher(tools.RandBytes(16))
	if err != nil {
		log.Fatal(err)
	}
	mode := cipher.NewCBCEncrypter(block, tools.RandBytes(16))
	pt := tools.PadPKCS7(b.Bytes(), 16)
	// fmt.Printf("pt = %+q\n", string(pt))
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return len(ct)
}

var abc []byte

func init() {
	abc = make([]byte, 0, 52)
	for i := 48; i <= 57; i++ {
		abc = append(abc, byte(i))
	}
	for i := 65; i <= 90; i++ {
		abc = append(abc, byte(i))
	}
	for i := 97; i <= 122; i++ {
		abc = append(abc, byte(i))
	}
	abc = append(abc, []byte("+/=")...)
}

func breakStreamCipher() {
	b := []byte("sessionid= ")
	for j := 0; j < 100; j++ {
		min := oracleStreamCipher(b)
		ch := byte(' ')
		for i := 0; i < len(abc); i++ {
			b[len(b)-1] = abc[i]
			l := oracleStreamCipher(b)
			if l < min {
				min = l
				ch = abc[i]
			}
			// fmt.Printf("%s, len = %+v\n", string(b), l)
		}
		if ch == ' ' {
			fmt.Println("Could not find char, stopping")
			break
		}
		b[len(b)-1] = ch
		fmt.Printf("%s, len = %+v\n", string(b), min)
		b = append(b, byte(' '))
	}
	fmt.Printf("matching string: %s\n", string(b[:len(b)-1]))
	decoded, err := base64.StdEncoding.DecodeString(string(b[11 : len(b)-1]))
	if err == nil {
		fmt.Println("Can decode base64:", decoded)
	}
}

// findPrefix find the prefix before b that increases length returned by oracle
// by one block
func findPrefix(b []byte) []byte {
	prefix := make([]byte, 0)
	size := oracleCBCCipher(append(prefix, b...))
	// fmt.Printf("%s, len = %+v\n", string(prefix), size)
	for i := 0; i < len(abc); i++ {
		prefix = append(prefix, abc[i])
		s := oracleCBCCipher(append(prefix, b...))
		// fmt.Printf("%s, len = %+v\n", string(prefix), s)
		if s > size {
			break
		}
	}
	return prefix
}

func breakCBCCipher() {
	b := []byte("sessionid= ")
	for j := 0; j < 100; j++ {
		prefix := findPrefix(b)
		fmt.Println("Found prefix len =", len(prefix))
		// We found the prefix which increased length by 16, now we can find
		// the value of sessionid= that compresses better and thus decreasing
		// the length by 16.
		min := oracleCBCCipher(append(prefix, b...))
		ch := byte(' ')
		for i := 0; i < len(abc); i++ {
			b[len(b)-1] = abc[i]
			l := oracleCBCCipher(append(prefix, b...))
			if l < min {
				min = l
				ch = abc[i]
			}
		}
		if ch == ' ' {
			fmt.Println("Could not find char, stopping.")
			break
		}
		b[len(b)-1] = ch
		fmt.Printf("%s, len = %+v\n", string(b), min)
		b = append(b, byte(' '))
		prefix = prefix[1:]
	}
	fmt.Printf("matching string: %s\n", string(b[:len(b)-1]))
	decoded, err := base64.StdEncoding.DecodeString(string(b[11 : len(b)-1]))
	if err == nil {
		fmt.Println("Can decode base64:", decoded)
	}
}

func main() {
	// Part one: when the encryption does not alter the length of oracle
	// breakStreamCipher()

	// Part two: Encryption is CBC and the oracle returned the padded length.
	breakCBCCipher()
}
