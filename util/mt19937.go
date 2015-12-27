package util

type MT19937 struct {
	index uint64
	mt    [624]uint64
}

func lsb32(n uint64) uint64 {
	return 0xFFFFFFFF & n
}

func NewMT19337(seed uint64) *MT19937 {
	m := MT19937{index: 624}
	m.mt[0] = seed
	for i := 1; i < 624; i++ {
		m.mt[i] = lsb32(1812433253*(m.mt[i-1]^(m.mt[i-1]>>30)) + uint64(i))
		// fmt.Println(i, 1812433253*(m.mt[i-1]^(m.mt[i-1]>>30))+uint64(i), m.mt[i])
	}
	return &m
}

func (m *MT19937) Next() uint64 {
	if m.index >= 624 {
		m.Twist()
	}
	y := m.mt[m.index]

	y = y ^ y>>11
	y = y ^ y<<7&2636928640
	y = y ^ y<<15&4022730752
	y = y ^ y>>18
	m.index++

	return lsb32(y)
}

func (m *MT19937) Twist() {
	var i uint64
	for i = 0; i < 624; i++ {
		y := lsb32(m.mt[i]&0x80000000 + m.mt[(i+1)%624]&0x7fffffff)
		m.mt[i] = m.mt[(i+397)%624] ^ y>>1
		if y%2 != 0 {
			m.mt[i] = m.mt[i] ^ 0x9908b0df
		}
	}
	m.index = 0
}

func (m *MT19937) SetIndex(i uint64) {
	m.index = i
}

func (m *MT19937) SetMT(i, value uint64) {
	m.mt[i] = value
}
