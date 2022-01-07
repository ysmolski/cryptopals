package main

import (
	"fmt"
	"sha1go"

	"tools"
)

var key []byte

func init() {
	key = tools.RandBytes(16)
}

func sha1(msg []byte) [sha1go.Size]byte {
	d := append(key, msg...)
	return sha1go.Sum(d)
}

func main() {
	data := []byte("some data bla bla bl1")
	fmt.Printf("% x\n", sha1(data))
}
