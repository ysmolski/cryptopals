package mtrand

// The coefficients for MT19937 are:
const (
	w = uint32(32)
	n = uint32(624)
	m = uint32(397)
	r = uint32(31)

	a = uint32(0x9908B0DF)

	u  = uint32(11)
	d  = uint32(0xFFFFFFFF)
	ss = uint32(7)
	b  = uint32(0x9D2C5680)
	t  = uint32(15)
	c  = uint32(0xEFC60000)

	l = uint32(18)
)

var (
	lowerMask, upperMask uint32
	defSource            *Source
)

type Source struct {
	mt    []uint32
	index uint32
}

func init() {
	lowerMask = (1 << r) - 1
	upperMask = d & (^lowerMask)
	defSource = NewSource()
	// fmt.Printf("lowerMask = %x %x\n", lowerMask, upperMask)
}

func NewSource() *Source {
	return &Source{make([]uint32, n), n + 1}
}

func Seed(seed uint32) {
	defSource.Seed(seed)
}

func Rand() uint32 {
	return defSource.Rand()
}

func (s *Source) Seed(seed uint32) {
	f := uint32(1812433253)
	s.index = n
	s.mt[0] = seed
	for i := uint32(1); i < n; i++ {
		// lowest w bits
		s.mt[i] = f*(s.mt[i-1]^(s.mt[i-1]>>(w-2))) + i
	}
	// fmt.Println(mt)
}

// Rand extracts a tempered value based on MT[index]
// calling twist() every n numbers.
func (s *Source) Rand() uint32 {
	if s.index >= n {
		if s.index > n {
			panic("generator was never seeded")
		}
		s.twist()
	}
	y := s.mt[s.index]
	// fmt.Printf("y0=%#x\n", y)
	y = y ^ ((y >> u) & d)
	// fmt.Printf("y1=%#x\n", y)
	y = y ^ ((y << ss) & b)
	// fmt.Printf("y2=%#x\n", y)
	y = y ^ ((y << t) & c)
	// fmt.Printf("y3=%#x\n", y)
	y = y ^ (y >> l)
	// fmt.Printf("y4=%#x\n", y)
	s.index++
	return y
}

// twist generates the next n values from the series x_i.
func (s *Source) twist() {
	for i := uint32(0); i < n; i++ {
		x := s.mt[i]&upperMask + s.mt[(i+1)%n]&lowerMask
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ a
		}
		s.mt[i] = s.mt[(i+m)%n] ^ xA
	}
	s.index = 0
}

func Untemper(y uint32) uint32 {
	// fmt.Printf("y4=%#x\n", y)
	y = y ^ (y >> l)
	// fmt.Printf("y3=%#x\n", y)
	y = y ^ (y<<t)&c
	// fmt.Printf("y2=%#x\n", y)
	y = y ^ ((y << ss) & 0x80)
	y = y ^ ((y << ss) & 0x5600)
	y = y ^ ((y << ss) & 0x2c0000)
	y = y ^ ((y << ss) & 0x0d000000)
	y = y ^ ((y << ss) & 0x90000000)
	// fmt.Printf("y1=%#x\n", y)
	y = y ^ ((y >> u) & 0x1ffc00)
	y = y ^ ((y >> u) & 0x3ff)
	// fmt.Printf("y0=%#x\n", y)
	return y
}

func Reconstruct(mt []uint32) *Source {
	ll := uint32(len(mt))
	if ll != n {
		panic("mt should be len of n")
	}
	n := make([]uint32, ll)
	copy(n, mt)
	return &Source{n, ll}
}
