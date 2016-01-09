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

func getStatus(sign []byte) (int, float64) {
	signHex := hex.EncodeToString(sign)
	t := time.Now()
	url := "http://localhost:8000/test?file=foo&signature=" + signHex
	resp, err := http.Get(url)
	elapsed := time.Since(t)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	return resp.StatusCode, elapsed.Seconds()
}

func main() {
	key := []byte("key")
	msg := []byte("The quick brown fox jumps over the lazy dog")
	s := util.HMacSha1(key, msg)
	expected, _ := hex.DecodeString("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
	if bytes.Compare(s, expected) != 0 {
		log.Fatalf("expected %x, got %x sign", expected, s)
	}

	sign := make([]byte, 20)
	_, elapsed := getStatus(sign)
	averageTime := elapsed
	succTime := 0.0
	for i := 0; i < len(sign); i++ {
		expected := float64(i+1) * succTime * 0.95
		fmt.Println("expected:", expected)
		for b := byte(0); b <= 255; b++ {
			sign[i] = b
			status, elapsed := getStatus(sign)
			fmt.Printf("%d %x %f %f\n", status, sign, elapsed, averageTime)
			if succTime == 0.0 {
				if elapsed > averageTime*4 {
					succTime = elapsed
					break
				}
				averageTime = (elapsed + averageTime) / 2
			} else {
				if elapsed > expected {
					break
				}
			}
		}
	}
}
