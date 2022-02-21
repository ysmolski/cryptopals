package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/ysmolsky/cryptopals/tools"
)

type ScoredText struct {
	Score float64
	Text  []byte
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) > 1 {
		fmt.Println("usage: ./ch05 [key]")
		fmt.Println("if key is provided then this program encrypts stdin into stdout")
		os.Exit(1)
	}

	if len(args) == 1 {
		pt, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %s", err)
			os.Exit(1)
		}
		ct := tools.XorBytes(pt, []byte(args[0]))
		// hexed := hex.EncodeToString(ct)
		// fmt.Fprintf(os.Stdout, hexed)
		fmt.Fprintf(os.Stdout, "%#v\n", string(ct))
	} else {
		pt := "Burning 'em, if you ain't quick and nimble\n" +
			"I go crazy when I hear a cymbal"
		key := "ICE"
		expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
			"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
		ct := tools.XorBytes([]byte(pt), []byte(key))
		got := hex.EncodeToString(ct)
		fmt.Printf("%#v XOR %#v ->\n%#v\n", pt, key, got)
		fmt.Printf("expected == got: %t\n", expected == got)
	}
}
