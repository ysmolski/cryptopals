package main

import (
	"bytes"
	"cryptopals/util"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	key := []byte("key")
	msg := []byte("The quick brown fox jumps over the lazy dog")
	s := util.HMacSha1(key, msg)
	expected, _ := hex.DecodeString("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
	if bytes.Compare(s, expected) != 0 {
		log.Fatalf("expected %x, got %x sign", expected, s)
	}

	sign := make([]byte, 20)
	for i := 0; i < len(sign); i++ {
		// TODO: determine delay for success bytes
		expectedSeconds := float64(i+1) * 0.050
		for b := byte(0); b <= 255; b++ {
			sign[i] = b
			signHex := hex.EncodeToString(sign)
			t := time.Now()
			url := "http://localhost:8000/test?file=foo&signature=" + signHex
			resp, err := http.Get(url)
			elapsed := time.Since(t)
			resp.Body.Close()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%d %x %f\n", resp.StatusCode, sign, elapsed.Seconds())
			if elapsed.Seconds() > expectedSeconds-0.010 {
				break
			}
		}
	}
}
