package main

import (
	"cryptopals/util"
	"fmt"
)

func main() {
	mt := util.NewMT19337(0)
	fmt.Println(mt.Next())
	fmt.Println(mt.Next())
}
