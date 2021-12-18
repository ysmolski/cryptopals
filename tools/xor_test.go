package tools

import (
	"bytes"
	"testing"
)

func TestTransposeByN(t *testing.T) {
	a := "01234567"
	exp := [][]byte{
		{'0', '3', '6'},
		{'1', '4', '7'},
		{'2', '5'},
	}
	got := TransposeByN([]byte(a), 3)
	if len(got) != len(exp) {
		t.Errorf("TransposeByN(%v, %v) = %v; want %v", a, 3, got, exp)
	}
	for i := range got {
		if bytes.Compare(got[i], exp[i]) != 0 {
			t.Errorf("TransposeByN(%v, %v) = %v; want %v", a, 3, got, exp)
			break
		}
	}
}
