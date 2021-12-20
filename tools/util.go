package tools

func PadPKCS7(a []byte, n int) []byte {
	num := n - len(a)%n
	add := make([]byte, num)
	for i := range add {
		add[i] = byte(num)
	}
	a = append(a, add...)
	return a
}
