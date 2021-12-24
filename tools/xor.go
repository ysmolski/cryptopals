package tools

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

// XorBytesInplace xors bytes from dst and src and puts the result into dst.
func XorBytesInplace(dst, src []byte) {
	m := src
	if len(dst) < len(src) {
		m = dst
	}
	for i := range m {
		dst[i] = dst[i] ^ src[i]
	}
}

// TransposeByN transposes seq by putting elements
// 0, 0+n, 0+2n, ... into 1st chunk
// 1, 1+n, 1+2n, ... into 2nd chunk
// ... and so on until
// n-1, n-1+n, n-1+2n, ... into n-th chunk
func TransposeByN(seq []byte, n int) [][]byte {
	tr := make([][]byte, n)
	for i := range tr {
		tr[i] = make([]byte, 0, 8)
	}
	for i, el := range seq {
		col := i % n
		tr[col] = append(tr[col], el)
	}
	return tr
}
