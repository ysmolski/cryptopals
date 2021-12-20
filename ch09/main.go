package main

import (
	"fmt"

	"github.com/ysmolsky/cryptopals/tools"
)

func main() {
	padded := tools.PadPKCS7([]byte("YELLOW SUBMARINE"), 20)
	fmt.Printf("%#v\n", string(padded))
	padded = tools.PadPKCS7([]byte("YELLOW SUBMAR"), 16)
	fmt.Printf("%#v\n", string(padded))
	padded = tools.PadPKCS7([]byte("YELLOW SUBMARINE"), 16)
	fmt.Printf("%#v\n", string(padded))
}
