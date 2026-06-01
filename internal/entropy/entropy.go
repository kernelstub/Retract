package entropy

import "math"

type Window struct {
	Offset  int     `json:"offset"`
	Size    int     `json:"size"`
	Entropy float64 `json:"entropy"`
	High    bool    `json:"high"`
}

func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var e float64
	n := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func Sliding(data []byte, size, step int) []Window {
	if size <= 0 {
		size = 4096
	}
	if step <= 0 {
		step = size
	}
	out := []Window{}
	for off := 0; off < len(data); off += step {
		end := off + size
		if end > len(data) {
			end = len(data)
		}
		if end <= off {
			break
		}
		e := Shannon(data[off:end])
		out = append(out, Window{Offset: off, Size: end - off, Entropy: e, High: e >= 7.2})
		if end == len(data) {
			break
		}
	}
	return out
}
