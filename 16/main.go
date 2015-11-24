package main

import (
	"cryptopals/util"
	"fmt"
)

var (
	key = util.RandAes128()
	iv  = util.RandAes128()
)

func crypt(userdata []byte) []byte {
	return nil
}

func isAdmin(ct []byte) bool {
	return false
}

func main() {
	ud := []byte("somedata")
	ct := crypt(ud)

	adm := isAdmin(ct)
	fmt.Println(adm)
}
