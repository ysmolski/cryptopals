package tools

import "testing"

func TestEditDistance(t *testing.T) {
	a := "this is a test"
	b := "wokka wokka!!!"
	got := EditDistance([]byte(a), []byte(b))
	if got != 37 {
		t.Errorf("EditDistance(%s, %s) = %d; want 37", a, b, got)
	}
}
