package main

import (
	"fmt"

	"github.com/ysmolsky/cryptopals/tools/mtrand"
)

func main() {
	mtrand.Seed(123)
	for i := 0; i < 625; i++ {
		fmt.Println(mtrand.Rand())
	}
}
