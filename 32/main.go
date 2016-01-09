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

func average(sign []byte, tries int) float64 {
	sum := 0.0
	for i := 0; i < tries; i++ {
		_, el := getStatus(sign)
		sum += el
	}
	return sum / float64(tries)
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

	avg := average(sign, 100)
	fmt.Println("avg:", avg)

	succTime := 0.0
	for i := 0; i < len(sign); i++ {
		expected := float64(i+1) * (succTime - avg)
		found := false
		fmt.Printf("%d bytes expected: %f\n", i+1, expected)
		var max float64
		var ch byte
		for b := 0; b < 256; b++ {
			sign[i] = byte(b)
			status, elapsed := getStatus(sign)
			//fmt.Printf("%d %x %f\n", status, sign, elapsed)
			if elapsed > max {
				max = elapsed
				ch = byte(b)
			}
			if succTime == 0.0 {
				if elapsed > avg*2 {
					elapsed := average(sign, 5)
					fmt.Printf("%d %x took %f\n", status, sign, elapsed)
					succTime = elapsed
					fmt.Printf("delay for success byte: %f\n\n", succTime)
					found = true
					break
				}
			} else {
				if elapsed > expected {
					prev := elapsed
					elapsed := average(sign, 5)
					if elapsed > expected {
						fmt.Printf("%d %x took %f\n", status, sign, elapsed)
						succTime = (elapsed/float64(i+1) + succTime) / 2
						fmt.Printf("delay for success byte: %f\n\n", succTime)
						found = true
						break
					} else {
						fmt.Printf("... false positive %x: %f -> %f\n", b, prev, elapsed)
						continue
					}
				}
			}
		}
		if !found {
			// let's try the best char in position i so far
			fmt.Printf("resorting to the best char %x: %f...\n", ch, max)
			sign[i] = ch
			status, _ := getStatus(sign)
			elapsed := average(sign, 10)
			fmt.Printf("%d %x took %f\n", status, sign, elapsed)
			succTime = (elapsed/float64(i+1) + succTime) / 2
			fmt.Printf("delay for success byte: %f\n\n", succTime)
		}
	}
}
