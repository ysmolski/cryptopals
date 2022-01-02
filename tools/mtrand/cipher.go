package mtrand

func MTEncrypt(randSrc *Source, dst, src []byte) {
	if len(dst) != len(src) {
		panic("length of dst and src should be equal")
	}
	copy(dst, src)
	for i := 0; i < len(src); i++ {
		dst[i] ^= byte(randSrc.Rand() & 0xff)
	}
}
