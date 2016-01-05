package main

import (
	"crypto/sha1"
	"fmt"
)

func SignSha1(key, message []byte) []byte {
	h := sha1.New()
	h.Write(key)
	h.Write(message)
	return h.Sum(nil)
}

func main() {
	h := sha1.Sum([]byte("keysome stuff"))
	fmt.Printf("%x\n", h)
	h2 := SignSha1([]byte("key"), []byte("some stuff"))
	fmt.Printf("%x\n", h2)
	h3 := SignSha1([]byte("key2"), []byte("some stuff"))
	fmt.Printf("%x\n", h3)
}
