package main

/*
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
*/

import (
	"crypto/aes"
	"cryptopals/util"
	"fmt"
	"net/url"
)

type oracleFunc func(src []byte) []byte

var key = util.RandAes128()

func encryptProfile(email string) []byte {
	block, _ := aes.NewCipher(key)
	profile := profileFor(string(email))
	out := make([]byte, len(profile))
	copy(out, profile)

	out = util.PadTo(out, 16)
	fmt.Println("before enc:", out)
	util.ECBEncrypt(block, out, out)

	return out
}

func decryptProfile(ct []byte) url.Values {
	block, _ := aes.NewCipher(key)
	res := make([]byte, len(ct))
	// fmt.Println("before enc", string(out))
	util.ECBDecrypt(block, res, ct)
	// unpad
	last := int(res[len(res)-1])
	if last < block.BlockSize() {
		canStrip := true
		for i := len(res) - last; i < len(res); i++ {
			if res[i] != byte(last) {
				canStrip = false
				break
			}
		}
		if canStrip {
			res = res[:len(res)-last]
		}
	}

	fmt.Println("After decode:", string(res))

	vals, err := url.ParseQuery(string(res))
	if err != nil {
		fmt.Println("Cannot parse string", string(res))
		return nil
	}
	return vals
}

func profileFor(email string) string {
	v := url.Values{}
	v.Set("email", email)
	// v.Add("uid", strconv.Itoa(10))
	// v.Add("role", "user")
	return v.Encode() + "&uid=10&role=user"
}

func main() {
	e1 := "so@e.comadmin              "
	ct := encryptProfile(e1)
	// capture admin block
	adminBlock := ct[16:32]

	e2 := "foo.baz@bar.com            "
	ct = encryptProfile(e2)
	ct = append(ct[:48], adminBlock...)
	vals := decryptProfile(ct)
	fmt.Println(vals["email"])
	fmt.Println(vals["uid"])
	fmt.Println(vals["role"])
}
