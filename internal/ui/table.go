package ui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// column describes one table column.
type column struct {
	title string
	max   int  // 0 = unbounded (flexible)
	right bool // right-align
}

// renderTable lays out rows into fixed-width columns that fit the width.
// It returns the header line and the rendered rows.
func renderTable(width int, cols []column, rows [][]string) (string, []string) {
	n := len(cols)
	widths := make([]int, n)
	for i, c := range cols {
		widths[i] = ansi.StringWidth(c.title)
	}
	for _, r := range rows {
		for i := 0; i < n && i < len(r); i++ {
			if w := ansi.StringWidth(r[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	for i, c := range cols {
		if c.max > 0 && widths[i] > c.max {
			widths[i] = c.max
		}
	}
	gap := 2
	total := func() int {
		t := gap * (n - 1)
		for _, w := range widths {
			t += w
		}
		return t
	}
	// shrink the widest columns until it fits
	for total() > width {
		wi := -1
		for i := range widths {
			if widths[i] > 8 && (wi < 0 || widths[i] > widths[wi]) {
				wi = i
			}
		}
		if wi < 0 {
			break
		}
		widths[wi]--
	}
	format := func(cells []string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			cell := ""
			if i < len(cells) {
				cell = cells[i]
			}
			if cols[i].right {
				b.WriteString(padLeft(cell, widths[i]))
			} else {
				b.WriteString(pad(cell, widths[i]))
			}
			if i < n-1 {
				b.WriteString(strings.Repeat(" ", gap))
			}
		}
		return strings.TrimRight(b.String(), " ")
	}
	titles := make([]string, n)
	for i, c := range cols {
		titles[i] = c.title
	}
	header := styleHeader.Render(format(titles))
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, format(r))
	}
	return header, out
}

// wrap splits text into lines no wider than width (ANSI-unaware, for plain text).
func wrap(s string, width int) []string {
	if width < 10 {
		width = 10
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		for len(line) > width {
			cut := strings.LastIndex(line[:width], " ")
			if cut < width/2 {
				cut = width
			}
			out = append(out, line[:cut])
			line = strings.TrimLeft(line[cut:], " ")
		}
		out = append(out, line)
	}
	return out
}

// kv renders "key: value" with a dim key.
func kv(k, v string) string { return styleDim.Render(k+": ") + v }
