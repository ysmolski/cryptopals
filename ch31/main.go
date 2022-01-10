package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
	"tools"
)

var (
	key []byte
)

const endpoint = "127.0.0.1:8080"

func init() {
	key = []byte("NDUEj92nd84bwjd")
}

func hmacFile(filename string) ([]byte, error) {
	ws, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return hmac(key, ws), nil
}

func hmac(key, msg []byte) []byte {
	if len(key) > sha1.BlockSize {
		s := sha1.Sum(key)
		key = s[:]
	}
	if len(key) < sha1.BlockSize {
		key = append(key, make([]byte, sha1.BlockSize-len(key))...)
	}

	outer := tools.XorBytes(key, []byte{0x5c})
	inner := tools.XorBytes(key, []byte{0x36})
	h := sha1.New()
	h.Write(inner)
	h.Write(msg)
	innerSum := h.Sum(nil)
	h.Reset()
	h.Write(outer)
	h.Write(innerSum)
	return h.Sum(nil)
}

func server() {
	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if !r.Form.Has("file") || !r.Form.Has("sign") {
			http.Error(w, "bad params", http.StatusBadRequest)
			return
		}
		sign := r.Form.Get("sign")
		signBytes, err := hex.DecodeString(sign)
		if err != nil {
			http.Error(w, "bad params", http.StatusBadRequest)
			return
		}
		file := r.Form.Get("file")
		expSignature, err := hmacFile(file)
		if err != nil {
			http.Error(w, "bad params", http.StatusBadRequest)
			return
		}
		if !insecureEqual(expSignature, signBytes) {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	})
	log.Fatal(http.ListenAndServe(endpoint, nil))
}

func insecureEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(30 * time.Millisecond)
	}
	return true
}

func main() {
	// should be equal to de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
	// fmt.Printf("hmac = %x\n", hmac([]byte("key"), []byte("The quick brown fox jumps over the lazy dog")))
	if len(os.Args) > 1 && os.Args[1] == "server" {
		server()
	} else {
		breakHmac()
	}
}

// sign[6] = 230 el = 162
// sign[7] = 172 el = 185
// sign[8] = 21 el = 208
// sign[9] = 156 el = 235
// sign[10] = 251 el = 252
// sign[11] = 92 el = 278

func breakHmac() {
	url := fmt.Sprintf("http://%s/test?file=wordlist.txt&sign=", endpoint)
	sign := make([]byte, 20)
	const startPos = 0
	const bytesDelay = 30
	const nextDelay = 30 - 5
	const calls = 6
	// make calls to average the response time for wrong bytes
	var avg int64
	for b := 0; b < calls; b++ {
		sign[startPos] = byte(b)
		t := respTime(url, sign)
		fmt.Printf("%d ", t)
		avg += t
	}
	avg /= calls
	exp := avg + nextDelay
	fmt.Println("\navg=", avg, "next >", exp)
	for i := startPos; i < len(sign); i++ {
		sign[i] = 0
		fails := 0
		for {
			elapsed := respTime(url, sign)
			fmt.Printf("%d ", elapsed)
			if elapsed >= exp {
				var avg int64
				for b := 0; b < calls; b++ {
					t := respTime(url, sign)
					fmt.Printf("%d ", t)
					avg += t
				}
				avg /= calls
				fmt.Println("")
				if avg >= exp {
					exp = avg + nextDelay
					fmt.Printf("sign[%d] = 0x%x t = %d next > %d\n", i, sign[i], avg, exp)
					break
				}
			}
			sign[i]++
			if sign[i] == 0 {
				// we have not found any sign[i] that produces higher then
				// average response time.
				fails++
				fmt.Println("failed times", fails)
				if fails >= 2 {
					// if too many fails that let's retry previous byte
					fmt.Println("retrying prev byte")
					sign[i] = 0
					i--
					sign[i] = 0
					fails = 0
				}
			}
		}
	}
	fmt.Println(hex.EncodeToString(sign))
}

func respTime(url string, sign []byte) int64 {
	timer := time.Now()
	resp, err := http.Get(url + hex.EncodeToString(sign))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	// _, err = io.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	return time.Since(timer).Milliseconds()
}
