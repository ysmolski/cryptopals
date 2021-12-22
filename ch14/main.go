package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"log"
	"os"

	"github.com/ysmolsky/cryptopals/tools"
)

var key []byte
var prefix []byte
var unknown []byte

func init() {
	key = tools.RandBytes(16)
	prefix = tools.RandBytes(int(tools.RandByte()) % 64)
	var err error
	unknown, err = tools.ReadBase64File("./12.txt")
	if err != nil {
		panic("cannot read uknown from a file")
	}
}

func EncryptOracle(input []byte) []byte {
	src := append(prefix, input...)
	src = append(src, unknown...)

	ks := len(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal(err)
	}
	src = tools.PadPKCS7(src, ks)
	dst := make([]byte, len(src))
	tools.ECBEncrypt(block, dst, src)
	return dst
}

func blockSize() int {
	// determine block size
	sz := 0
	prevLen := len(EncryptOracle(make([]byte, 1)))
	for i := 2; i < 32; i++ {
		ct := EncryptOracle(make([]byte, i))
		if prevLen != len(ct) {
			sz = len(ct) - prevLen
			break
		}
	}
	return sz
}

func detectPrefix(sz int) (int, int) {
	blocks := 0
	prev := EncryptOracle(make([]byte, 0))
	ct := EncryptOracle(make([]byte, 1))
	for j := 0; j < len(ct)-sz; j += sz {
		if bytes.Equal(prev[j:j+sz], ct[j:j+sz]) {
			blocks++
		} else {
			break
		}
	}
	// Prefix contains at least blocks amount of data,
	// now, detect how many more additional bytes. The block after blocks
	// will stop changing when enough bytes were added to the input.
	added := 0
	check := blocks * sz
	for i := 1; i <= sz+1; i++ {
		input := make([]byte, i)
		ct := EncryptOracle(input)
		// fmt.Println(len(ct), hex.EncodeToString(ct))
		if bytes.Equal(prev[check:check+sz], ct[check:check+sz]) {
			break
		}
		added++
		prev = ct
	}
	return blocks, sz - added
}

func main() {
	sz := blockSize()
	fmt.Println("Block size =", sz)

	ct := EncryptOracle(make([]byte, sz*4))
	if !tools.IsECB(ct, sz) {
		panic("Not ECB")
	}
	fmt.Println("ECB detected.")

	prBlocks, prBytes := detectPrefix(sz)
	prLen := prBlocks*sz + prBytes
	fmt.Println("Prefix blocks =", prBlocks, "\nPrefix bytes =", prBytes)

	ct = EncryptOracle(make([]byte, 0))
	secrectLen := len(ct) - prLen
	fmt.Println("Length of unknown msg+padding =", secrectLen)

	// End prefix with aligned block. We will prepend all inputs with mockup to
	// discard first blocks in the ct as prefix part.
	mockup := make([]byte, sz-prBytes)
	// discard this amount of bytes in ct
	discard := prLen + len(mockup)

	fill := make([]byte, sz)
	unknown := make([]byte, secrectLen)
	for bl := 0; bl < secrectLen/sz; bl++ {
		// fmt.Println("block #", bl)
		for i := 1; i < 17 && bl*sz+i-1 < secrectLen; i++ {
			// position in unknown
			pos := bl*sz + i - 1
			if pos >= secrectLen {
				break
			}
			if bl == 0 {
				copy(fill[len(fill)-i:], unknown[:i])
			} else {
				copy(fill, unknown[pos-sz+1:pos])
			}
			ct := EncryptOracle(append(mockup, fill[:sz-i]...))
			// fmt.Println("unknown=", unknown, "fill=", fill)
			ideal := ct[discard+bl*sz : discard+(bl+1)*sz]

			// Determine the last byte by trying all possible values and comparing
			// resulting ct with ideal.
			found := false
			for b := 0; b < 256; b++ {
				fill[sz-1] = byte(b)
				ct := EncryptOracle(append(mockup, fill...))
				if bytes.Equal(ideal, ct[discard:discard+sz]) {
					unknown[pos] = byte(b)
					// fmt.Printf("found pos %d byte %c\n", pos, byte(b))
					found = true
					break
				}
			}
			if !found {
				fmt.Println("Cannot find byte at pos", pos)
				if len(unknown)-pos < 16 {
					fmt.Printf("Only %d bytes left... maybe it's padding?\n", len(unknown)-pos)
				}
				fmt.Printf("unknown:\n%#v\n", string(unknown))
				os.Exit(1)
			}
		}
	}
	fmt.Printf("unknown:\n%#v\n", string(unknown))
}
