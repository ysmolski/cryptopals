package main

import "fmt"

func pad(s string, n int) string {
	if n > len(s) {
		size:=n-len(s)
		appendix := make([]byte, size)
		for i:=0; i<size; i++ {
			appendix[i] = byte(size)
		}
		return s + string(appendix)
	}
	return s
}

func main() {
	fmt.Println([]byte(pad("YELLOW SUBMARINE", 20)))
}
