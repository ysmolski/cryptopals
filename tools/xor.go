package tools

import (
	"bytes"
	"math"
)

func XorBytes(a, b []byte) []byte {
	if len(a) < len(b) {
		t := a
		a = b
		b = t
	}
	// a is longer than b
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i%len(b)]
	}
	return c
}

// https://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html

var FreqLetters = map[byte]float64{
	' ': 0.15575645,
	'e': 0.12575645,
	't': 0.09085226,
	'a': 0.08000395,
	'o': 0.07591270,
	'i': 0.06920007,
	'n': 0.06903785,
	's': 0.06340880,
	'h': 0.06236609,
	'r': 0.05959034,
	'd': 0.04317924,
	'l': 0.04057231,
	'u': 0.02841783,
	'c': 0.02575785,
	'm': 0.02560994,
	'f': 0.02350463,
	'w': 0.02224893,
	'g': 0.01982677,
	'y': 0.01900888,
	'p': 0.01795742,
	'b': 0.01535701,
	'v': 0.00981717,
	'k': 0.00739906,
	'x': 0.00179556,
	'j': 0.00145188,
	'q': 0.00117571,
	'z': 0.00079130,
}

func TextScoreEnglish(a []byte) float64 {
	a = bytes.ToLower(a)
	counts := make(map[byte]int)
	for _, ch := range a {
		// if ch < 'a' || ch > 'z' {
		// 	continue
		// }
		if _, ok := counts[ch]; !ok {
			counts[ch] = 0
		}
		counts[ch] += 1
	}
	freqs := make(map[byte]float64)
	for ch, c := range counts {
		freqs[ch] = float64(c) / float64(len(a))
		// fmt.Printf("%c %f\n", ch, freqs[ch])
	}
	return cosineDistance(freqs, FreqLetters)
}

func cosineDistance(x, y map[byte]float64) float64 {
	// x0*y0 + x1*y1 + ..
	// ---------------------------------------------
	// sqroot(x0^2+x1^2+...) + sqroot(y0^1+y1^2+...)

	var upper float64
	var xlen float64
	for xk, xv := range x {
		if yv, ok := y[xk]; ok {
			upper += xv * yv
		}
		xlen += xv * xv
	}
	xlen = math.Sqrt(xlen)

	var ylen float64
	for _, yv := range y {
		ylen += yv * yv
	}
	ylen = math.Sqrt(ylen)

	// fmt.Printf("%f\n-----------------\n%f * %f\n", upper, xlen, ylen)
	return upper / (xlen * ylen)
}
