package tools

import (
	"bytes"
	"fmt"
	"testing"
)

func TestUnpadPKCS7(t *testing.T) {
	tests := []struct {
		in, out []byte
		err     error
	}{
		{
			in:  []byte("ICE ICE BABY\x04\x04\x04\x04"),
			out: []byte("ICE ICE BABY"),
			err: nil,
		},
		{
			in:  []byte("ICE ICE BABY\x05\x05\x05\x05"),
			out: nil,
			err: fmt.Errorf("bad padding"),
		},
		{
			in:  []byte("ICE ICE BABY\x01\x02\x03\x04"),
			out: nil,
			err: fmt.Errorf("bad padding"),
		},
		{
			in:  []byte("ICE ICE BABY\x04"),
			out: nil,
			err: fmt.Errorf("bad padding"),
		},
		{
			in:  []byte("ICE ICE BABY\x00"),
			out: nil,
			err: fmt.Errorf("bad padding"),
		},
	}

	for _, test := range tests {
		got, err := UnpadPKCS7(test.in)
		if !bytes.Equal(got, test.out) || (err == nil && test.err != nil) || (err != nil && test.err == nil) {
			t.Errorf("UnpadPKCS7(%#v) = %#v, %#v; want %#v, %#v", string(test.in), string(got), err, string(test.out), test.err)
		}
	}
}
