package main

/*
The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.
*/

import (
	"cryptopals/util"
	"fmt"
)

func untemper(y uint64) uint64 {
	y = y ^ y>>18

	y = y ^ y<<15&4022730752

	tmp := y ^ y<<7&2636928640
	tmp = y ^ tmp<<7&2636928640
	tmp = y ^ tmp<<7&2636928640
	y = y ^ tmp<<7&2636928640

	tmp = y ^ y>>11
	y = y ^ tmp>>11

	return y
}

func main() {
	mt := util.NewMT19337(0)
	clone := util.NewMT19337(100)
	var i uint64
	for i = 0; i < 624; i++ {
		o := mt.Next()
		clone.SetMT(i, untemper(o))
	}
	clone.SetIndex(624)
	fmt.Println("Original Clone")
	for i := 0; i < 10; i++ {
		o := mt.Next()
		c := clone.Next()
		fmt.Printf("%x %x\n", o, c)
	}

}
