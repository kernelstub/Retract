package strings

import "testing"

func TestExtractCategorizesASCIIAndUTF16(t *testing.T) {
	data := append([]byte("http://example.com\x00cmd.exe\x00"), []byte{'H', 0, 'K', 0, 'C', 0, 'U', 0, '\\', 0, 'S', 0, 'o', 0, 'f', 0, 't', 0, 0, 0}...)
	hits := Extract(data, 4)
	if len(hits) < 3 {
		t.Fatalf("hits = %#v", hits)
	}
	var sawURL, sawCommand, sawUnicode bool
	for _, h := range hits {
		for _, tag := range h.Tags {
			if tag == "url" {
				sawURL = true
			}
			if tag == "command" {
				sawCommand = true
			}
		}
		if h.Encoding == "utf-16le" {
			sawUnicode = true
		}
	}
	if !sawURL || !sawCommand || !sawUnicode {
		t.Fatalf("missing categories: url=%v command=%v unicode=%v hits=%#v", sawURL, sawCommand, sawUnicode, hits)
	}
}
