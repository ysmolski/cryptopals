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
	"errors"
	"fmt"
)

var (
	key     = util.RandAes128()
	iv      = util.RandAes128()
	prefix  = []byte("comment1=cooking;userdata=")
	postfix = []byte(";comment2=meat")
)

func crypt(userdata []byte) []byte {
	res := bytes.Replace(userdata, []byte("="), []byte("%3D"), -1)
	res = bytes.Replace(res, []byte(";"), []byte("%3B"), -1)
	res = append(prefix, res...)
	res = append(res, postfix...)
	block, _ := aes.NewCipher(key)
	res = util.PadTo(res, 16)
	// Use key for IV
	util.CBCEncrypt(block, key, res, res)
	return res
}

func decrypt(ct []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	res := make([]byte, len(ct))
	util.CBCDecrypt(block, key, res, ct)
	for i := 0; i < len(res); i++ {
		if res[i] > 127 {
			return nil, errors.New("Wrong text: " + string(res))
		}
	}
	return res, nil
}

func main() {
	// prepare aligned data
	ud := []byte("data")
	ct := crypt(ud)
	fmt.Printf("ct: %d %x\n", len(ct), ct)
	// attack the message ct
	decoy := make([]byte, len(ct))
	copy(decoy[:16], ct[:16])
	copy(decoy[32:48], ct[:16])
	fmt.Printf("decoy: %d %x\n", len(decoy), decoy)
	_, err := decrypt(decoy)
	if err != nil {
		// recover key because 1st block contains PT1, 2nd block contains PT1 XOR KEY
		pt := err.Error()[12:]
		fmt.Println("Error:", err)
		foundKey := make([]byte, 16)
		for i := 0; i < 16; i++ {
			foundKey[i] = pt[i] ^ pt[i+32]
		}
		fmt.Println("found key:", foundKey)
		fmt.Println("(found_key == original_key) =", bytes.Compare(key, foundKey) == 0)
	}
}
