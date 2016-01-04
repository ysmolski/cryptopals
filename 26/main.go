package main

/*
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have this property?
*/

import (
	"bytes"
	"crypto/aes"
	"cryptopals/util"
	"fmt"
)

var (
	key     = util.RandAes128()
	nonce   = util.RandAes128()
	prefix  = []byte("comment1=cooking%20MCs;userdata=")
	postfix = []byte(";comment2=%20like%20a%20pound%20of%20bacon")
)

func crypt(userdata []byte) []byte {
	res := bytes.Replace(userdata, []byte("="), []byte("%3D"), -1)
	res = bytes.Replace(res, []byte(";"), []byte("%3B"), -1)
	res = append(prefix, res...)
	res = append(res, postfix...)
	block, _ := aes.NewCipher(key)
	res = util.PadTo(res, 16)
	fmt.Println("crypt peek:", string(res))
	util.CTREncrypt(block, nonce, res, res)
	return res
}

func isAdmin(ct []byte) bool {
	block, _ := aes.NewCipher(key)
	res := make([]byte, len(ct))
	copy(res, ct)
	util.CTREncrypt(block, nonce, res, res)
	fmt.Println("isAdmin peek:", string(res))
	return bytes.Count(res, []byte(";admin=true;")) > 0
}

func main() {
	// prepare aligned data
	ud := []byte("123456709-120456123456:admin<true")
	ct := crypt(ud)
	fmt.Printf("ct: %d %x\n", len(ct), ct)
	// Bytes we going to flip, characters : and <
	// The only difference with CBC mode is that we flip bytes at exact place,
	// while in CBC mode we flipped bytes in the block prior the actual block.
	base := 48
	pos := []int{base + 6, base + 12}
	for _, p := range pos {
		fmt.Print("at position ", p, " flip byte ", ct[p], " to ")
		ct[p] = ct[p] ^ 1
		fmt.Println(ct[p])
	}
	fmt.Println("Is Admin ==", isAdmin(ct))
}
