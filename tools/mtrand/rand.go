package mtrand

// The coefficients for MT19937 are:
const (
	w = uint32(32)
	n = uint32(624)
	m = uint32(397)
	r = uint32(31)

	a = uint32(0x9908B0DF)

	u = uint32(11)
	d = uint32(0xFFFFFFFF)
	s = uint32(7)
	b = uint32(0x9D2C5680)
	t = uint32(15)
	c = uint32(0xEFC60000)

	l = uint32(18)
)

var (
	mt                          []uint32
	index, lowerMask, upperMask uint32
)

func init() {
	mt = make([]uint32, n)
	index = n + 1
	lowerMask = (1 << r) - 1
	upperMask = d & (^lowerMask)
	// fmt.Printf("lowerMask = %x %x\n", lowerMask, upperMask)
}

func Seed(seed uint32) {
	f := uint32(1812433253)
	index = n
	mt[0] = seed
	for i := uint32(1); i < n; i++ {
		// lowest w bits
		mt[i] = f*(mt[i-1]^(mt[i-1]>>(w-2))) + i
	}
	// fmt.Println(mt)
}

// Rand extracts a tempered value based on MT[index]
// calling twist() every n numbers.
func Rand() uint32 {
	if index >= n {
		if index > n {
			panic("generator was never seeded")
		}
		twist()
	}
	y := mt[index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> l)
	index++
	return y
}

// twist generates the next n values from the series x_i.
func twist() {
	for i := uint32(0); i < n; i++ {
		x := mt[i]&upperMask + mt[(i+1)%n]&lowerMask
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ a
		}
		mt[i] = mt[(i+m)%n] ^ xA
	}
	index = 0
}
