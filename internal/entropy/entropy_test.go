package entropy

import "testing"

func TestShannon(t *testing.T) {
	if got := Shannon(nil); got != 0 {
		t.Fatalf("Shannon(nil) = %v", got)
	}
	if got := Shannon([]byte{1, 1, 1, 1}); got != 0 {
		t.Fatalf("constant entropy = %v", got)
	}
	if got := Shannon([]byte{0, 1}); got != 1 {
		t.Fatalf("balanced entropy = %v", got)
	}
}
