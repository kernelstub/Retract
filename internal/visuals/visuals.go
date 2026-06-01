package visuals

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"

	"retract/internal/entropy"
	"retract/internal/utils"
	"retract/pkg/api"
)

var (
	bg       = color.RGBA{18, 22, 27, 255}
	panel    = color.RGBA{27, 33, 40, 255}
	grid     = color.RGBA{55, 64, 74, 255}
	text     = color.RGBA{218, 225, 232, 255}
	accent   = color.RGBA{76, 201, 240, 255}
	warn     = color.RGBA{255, 183, 77, 255}
	danger   = color.RGBA{239, 83, 80, 255}
	soft     = color.RGBA{123, 220, 181, 255}
	muted    = color.RGBA{114, 124, 136, 255}
	readCol  = color.RGBA{97, 170, 255, 255}
	writeCol = color.RGBA{255, 193, 7, 255}
	execCol  = color.RGBA{239, 83, 80, 255}
)

func ByteHistogram(data []byte) []int {
	h := make([]int, 256)
	for _, b := range data {
		h[int(b)]++
	}
	return h
}

func WriteAll(root string, data []byte, sections []api.Section, windows []entropy.Window) error {
	dir, err := utils.SafeJoin(root, "visuals")
	if err != nil {
		return err
	}
	if err := utils.EnsureDir(dir); err != nil {
		return err
	}
	h := ByteHistogram(data)
	if err := writePNG(filepath.Join(dir, "entropy_timeline.png"), entropyTimeline(windows, 1200, 360)); err != nil {
		return err
	}
	if err := writePNG(filepath.Join(dir, "byte_histogram.png"), histogram(h, 1200, 360)); err != nil {
		return err
	}
	if err := writePNG(filepath.Join(dir, "section_map.png"), sectionMap(sections, len(data), 1200, 260)); err != nil {
		return err
	}
	return nil
}

func entropyTimeline(windows []entropy.Window, w, h int) image.Image {
	img := canvas(w, h)
	plot := rect{60, 32, w - 32, h - 48}
	fill(img, plot, panel)
	axes(img, plot, 8)
	if len(windows) == 0 {
		label(img, 72, 52, "no entropy windows", muted)
		return img
	}
	prevX, prevY := 0, 0
	for i, win := range windows {
		x := plot.x0 + int(float64(i)/float64(max(1, len(windows)-1))*float64(plot.w()))
		y := plot.y1 - int((win.Entropy/8.0)*float64(plot.h()))
		c := accent
		if win.Entropy >= 7.2 {
			c = danger
		} else if win.Entropy >= 6.4 {
			c = warn
		}
		if i > 0 {
			line(img, prevX, prevY, x, y, c)
		}
		dot(img, x, y, 2, c)
		prevX, prevY = x, y
	}
	label(img, 60, 18, "entropy timeline", text)
	label(img, plot.x1-150, 18, "0.0 - 8.0 bits/byte", muted)
	return img
}

func histogram(hist []int, w, h int) image.Image {
	img := canvas(w, h)
	plot := rect{60, 32, w - 32, h - 48}
	fill(img, plot, panel)
	axes(img, plot, 4)
	maxCount := 1
	for _, v := range hist {
		if v > maxCount {
			maxCount = v
		}
	}
	barW := math.Max(1, float64(plot.w())/256.0)
	for i, v := range hist {
		x0 := plot.x0 + int(float64(i)*barW)
		x1 := plot.x0 + int(float64(i+1)*barW)
		if x1 <= x0 {
			x1 = x0 + 1
		}
		y0 := plot.y1 - int(float64(v)/float64(maxCount)*float64(plot.h()))
		c := accent
		if i == 0 || i == 255 {
			c = warn
		}
		fill(img, rect{x0, y0, x1, plot.y1}, c)
	}
	label(img, 60, 18, "byte histogram", text)
	label(img, plot.x1-160, 18, fmt.Sprintf("max bucket %d", maxCount), muted)
	return img
}

func sectionMap(sections []api.Section, fileSize, w, h int) image.Image {
	img := canvas(w, h)
	plot := rect{60, 58, w - 32, h - 60}
	fill(img, plot, panel)
	label(img, 60, 22, "section map", text)
	if fileSize <= 0 {
		label(img, 72, 84, "empty file", muted)
		return img
	}
	for i, s := range sections {
		x0 := plot.x0 + int(float64(s.RawOffset)/float64(fileSize)*float64(plot.w()))
		x1 := plot.x0 + int(float64(s.RawOffset+s.RawSize)/float64(fileSize)*float64(plot.w()))
		if x1 <= x0 {
			x1 = x0 + 2
		}
		y0 := plot.y0 + 22 + (i%5)*24
		y1 := y0 + 16
		c := sectionColor(s.Permissions)
		fill(img, rect{x0, y0, x1, y1}, c)
		label(img, max(plot.x0, min(x0, plot.x1-120)), y0-12, s.Name, text)
	}
	label(img, 60, h-28, "blue=read  amber=write  red=execute  green=mixed/other", muted)
	return img
}

func sectionColor(perms string) color.RGBA {
	if contains(perms, 'x') {
		return execCol
	}
	if contains(perms, 'w') {
		return writeCol
	}
	if contains(perms, 'r') {
		return readCol
	}
	return soft
}

func canvas(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)
	return img
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

type rect struct{ x0, y0, x1, y1 int }

func (r rect) w() int { return r.x1 - r.x0 }
func (r rect) h() int { return r.y1 - r.y0 }

func fill(img *image.RGBA, r rect, c color.Color) {
	draw.Draw(img, image.Rect(r.x0, r.y0, r.x1, r.y1), &image.Uniform{c}, image.Point{}, draw.Src)
}

func axes(img *image.RGBA, r rect, divisions int) {
	for i := 0; i <= divisions; i++ {
		y := r.y0 + int(float64(i)/float64(divisions)*float64(r.h()))
		line(img, r.x0, y, r.x1, y, grid)
	}
	line(img, r.x0, r.y0, r.x0, r.y1, muted)
	line(img, r.x0, r.y1, r.x1, r.y1, muted)
}

func line(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	dx := abs(x1 - x0)
	sx := -1
	if x0 < x1 {
		sx = 1
	}
	dy := -abs(y1 - y0)
	sy := -1
	if y0 < y1 {
		sy = 1
	}
	err := dx + dy
	for {
		if image.Pt(x0, y0).In(img.Bounds()) {
			img.Set(x0, y0, c)
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func dot(img *image.RGBA, x, y, radius int, c color.Color) {
	for yy := y - radius; yy <= y+radius; yy++ {
		for xx := x - radius; xx <= x+radius; xx++ {
			if (xx-x)*(xx-x)+(yy-y)*(yy-y) <= radius*radius && image.Pt(xx, yy).In(img.Bounds()) {
				img.Set(xx, yy, c)
			}
		}
	}
}

// Tiny block text: enough for labels without pulling a font dependency.
func label(img *image.RGBA, x, y int, s string, c color.Color) {
	for i, r := range s {
		glyph(img, x+i*6, y, byte(r), c)
	}
}

func glyph(img *image.RGBA, x, y int, ch byte, c color.Color) {
	pattern := font[ch]
	if pattern == nil {
		pattern = font['?']
	}
	for row, bits := range pattern {
		for col := 0; col < 5; col++ {
			if bits&(1<<(4-col)) != 0 {
				px, py := x+col, y+row
				if image.Pt(px, py).In(img.Bounds()) {
					img.Set(px, py, c)
				}
			}
		}
	}
}

func contains(s string, r rune) bool {
	for _, v := range s {
		if v == r {
			return true
		}
	}
	return false
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var font = map[byte][]byte{
	' ': {0, 0, 0, 0, 0, 0, 0},
	'?': {0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
	'-': {0, 0, 0, 0x1f, 0, 0, 0},
	'.': {0, 0, 0, 0, 0, 0x0c, 0x0c},
	'/': {0x01, 0x02, 0x04, 0x08, 0x10, 0, 0},
	'=': {0, 0x1f, 0, 0x1f, 0, 0, 0},
	'_': {0, 0, 0, 0, 0, 0, 0x1f},
	':': {0, 0x0c, 0x0c, 0, 0x0c, 0x0c, 0},
}

func init() {
	add := func(ch byte, rows ...byte) { font[ch] = rows }
	add('0', 0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e)
	add('1', 0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e)
	add('2', 0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f)
	add('3', 0x1e, 0x01, 0x01, 0x0e, 0x01, 0x01, 0x1e)
	add('4', 0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02)
	add('5', 0x1f, 0x10, 0x1e, 0x01, 0x01, 0x11, 0x0e)
	add('6', 0x06, 0x08, 0x10, 0x1e, 0x11, 0x11, 0x0e)
	add('7', 0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08)
	add('8', 0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e)
	add('9', 0x0e, 0x11, 0x11, 0x0f, 0x01, 0x02, 0x0c)
	for ch := byte('a'); ch <= 'z'; ch++ {
		font[ch-'a'+'A'] = font[ch]
	}
	add('a', 0, 0x0e, 0x01, 0x0f, 0x11, 0x13, 0x0d)
	add('b', 0x10, 0x10, 0x16, 0x19, 0x11, 0x19, 0x16)
	add('c', 0, 0x0e, 0x10, 0x10, 0x10, 0x11, 0x0e)
	add('d', 0x01, 0x01, 0x0d, 0x13, 0x11, 0x13, 0x0d)
	add('e', 0, 0x0e, 0x11, 0x1f, 0x10, 0x11, 0x0e)
	add('f', 0x06, 0x08, 0x1e, 0x08, 0x08, 0x08, 0x08)
	add('g', 0, 0x0d, 0x13, 0x13, 0x0d, 0x01, 0x0e)
	add('h', 0x10, 0x10, 0x16, 0x19, 0x11, 0x11, 0x11)
	add('i', 0x04, 0, 0x0c, 0x04, 0x04, 0x04, 0x0e)
	add('j', 0x02, 0, 0x06, 0x02, 0x02, 0x12, 0x0c)
	add('k', 0x10, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11)
	add('l', 0x0c, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e)
	add('m', 0, 0x1a, 0x15, 0x15, 0x15, 0x15, 0x15)
	add('n', 0, 0x16, 0x19, 0x11, 0x11, 0x11, 0x11)
	add('o', 0, 0x0e, 0x11, 0x11, 0x11, 0x11, 0x0e)
	add('p', 0, 0x16, 0x19, 0x19, 0x16, 0x10, 0x10)
	add('q', 0, 0x0d, 0x13, 0x13, 0x0d, 0x01, 0x01)
	add('r', 0, 0x16, 0x19, 0x10, 0x10, 0x10, 0x10)
	add('s', 0, 0x0f, 0x10, 0x0e, 0x01, 0x01, 0x1e)
	add('t', 0x08, 0x08, 0x1e, 0x08, 0x08, 0x09, 0x06)
	add('u', 0, 0x11, 0x11, 0x11, 0x11, 0x13, 0x0d)
	add('v', 0, 0x11, 0x11, 0x11, 0x0a, 0x0a, 0x04)
	add('w', 0, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a)
	add('x', 0, 0x11, 0x0a, 0x04, 0x04, 0x0a, 0x11)
	add('y', 0, 0x11, 0x11, 0x13, 0x0d, 0x01, 0x0e)
	add('z', 0, 0x1f, 0x02, 0x04, 0x08, 0x10, 0x1f)
	for ch := byte('a'); ch <= 'z'; ch++ {
		font[ch-'a'+'A'] = font[ch]
	}
}
