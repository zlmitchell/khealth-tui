package ui

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// ---- history (ring buffers for sparklines) ----

const histLen = 90

type series struct {
	vals []float64
}

func (s *series) push(v float64) {
	s.vals = append(s.vals, v)
	if len(s.vals) > histLen {
		s.vals = s.vals[len(s.vals)-histLen:]
	}
}

func (s *series) last() float64 {
	if s == nil || len(s.vals) == 0 {
		return math.NaN()
	}
	return s.vals[len(s.vals)-1]
}

func (a *App) record(key string, v float64) {
	if a.hist == nil {
		a.hist = map[string]*series{}
	}
	s, ok := a.hist[key]
	if !ok {
		s = &series{}
		a.hist[key] = s
	}
	s.push(v)
}

func (a *App) values(key string) []float64 {
	if s, ok := a.hist[key]; ok {
		return s.vals
	}
	return nil
}

// ---- widgets ----

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// sparkline renders values as block characters; max<=0 scales to the data.
func sparkline(vals []float64, width int, max float64) string {
	if width <= 0 {
		return ""
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	if max <= 0 {
		min := math.Inf(1)
		for _, v := range vals {
			if v > max {
				max = v
			}
			if v < min {
				min = v
			}
		}
		if max > 0 && min == max {
			// flat series: draw at mid height instead of a solid bar
			max *= 2
		}
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", width-len(vals)))
	for _, v := range vals {
		if math.IsNaN(v) || v < 0 {
			b.WriteRune('·')
			continue
		}
		idx := 0
		if max > 0 {
			idx = int(math.Round(v / max * float64(len(sparkRunes)-1)))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	return b.String()
}

// sparkStyled colours the sparkline by its latest value against thresholds.
func sparkStyled(vals []float64, width int, max float64, warn, crit int) string {
	last := math.NaN()
	if len(vals) > 0 {
		last = vals[len(vals)-1]
	}
	return pctStyle(last, warn, crit).Render(sparkline(vals, width, max))
}

// bar renders a filled/unfilled bar of the given fraction (0..1).
func bar(frac float64, width int, st lipgloss.Style) string {
	if width <= 0 {
		return ""
	}
	if math.IsNaN(frac) || frac < 0 {
		return styleDim.Render(strings.Repeat("░", width))
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(math.Round(frac * float64(width)))
	if frac > 0 && filled == 0 {
		filled = 1
	}
	return st.Render(strings.Repeat("█", filled)) + styleDim.Render(strings.Repeat("░", width-filled))
}

// gauge renders a percentage bar coloured by thresholds, followed by the value.
func gauge(pct float64, width int, warn, crit int) string {
	if math.IsNaN(pct) || pct < 0 {
		return bar(-1, width, styleDim) + styleDim.Render("   -")
	}
	return bar(pct/100, width, pctStyle(pct, warn, crit)) + pctStyle(pct, warn, crit).Render(fmt.Sprintf("%4.0f%%", pct))
}

// seg is one segment of a stacked bar.
type seg struct {
	n     float64
	st    lipgloss.Style
	label string
}

// stacked renders proportional segments across width; zero segments get no space.
func stacked(width int, segs []seg) string {
	var total float64
	for _, s := range segs {
		total += s.n
	}
	if total <= 0 || width <= 0 {
		return styleDim.Render(strings.Repeat("░", width))
	}
	cells := make([]int, len(segs))
	used := 0
	for i, s := range segs {
		cells[i] = int(math.Floor(s.n / total * float64(width)))
		if s.n > 0 && cells[i] == 0 {
			cells[i] = 1
		}
		used += cells[i]
	}
	// distribute rounding remainder to the largest segment
	if used != width {
		big := 0
		for i := range segs {
			if segs[i].n > segs[big].n {
				big = i
			}
		}
		cells[big] += width - used
		if cells[big] < 0 {
			cells[big] = 0
		}
	}
	var b strings.Builder
	for i, s := range segs {
		b.WriteString(s.st.Render(strings.Repeat("█", cells[i])))
	}
	return b.String()
}

// legend renders "▇ label n" entries for a stacked bar.
func legend(segs []seg) string {
	var parts []string
	for _, s := range segs {
		if s.label == "" {
			continue
		}
		parts = append(parts, s.st.Render("▇ ")+fmt.Sprintf("%s %.0f", s.label, s.n))
	}
	return strings.Join(parts, "  ")
}

// tile renders a bordered box with a title and body lines at a fixed width.
func tile(width int, title string, lines ...string) string {
	inner := width - 4
	if inner < 4 {
		inner = 4
	}
	body := []string{styleTitle.Render(trunc(title, inner))}
	for _, l := range lines {
		body = append(body, pad(trunc(l, inner), inner))
	}
	// lipgloss Width covers content + padding; the border adds 2 on top
	return styleBox.Width(width - 2).Render(strings.Join(body, "\n"))
}

// tileRow lays tiles out side by side and returns the rendered lines.
func tileRow(tiles []string) []string {
	if len(tiles) == 0 {
		return nil
	}
	joined := lipgloss.JoinHorizontal(lipgloss.Top, tiles...)
	return strings.Split(joined, "\n")
}

// tileWidths splits the available width evenly across n tiles (min 18 each).
func tileWidths(total, n int) (int, int) {
	if n <= 0 {
		return 0, 0
	}
	w := total / n
	for w < 18 && n > 1 {
		n--
		w = total / n
	}
	return w, n
}

func avg(vals []float64) float64 {
	if len(vals) == 0 {
		return math.NaN()
	}
	var s float64
	for _, v := range vals {
		s += v
	}
	return s / float64(len(vals))
}

func maxOf(vals []float64) float64 {
	if len(vals) == 0 {
		return math.NaN()
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func nan() float64 { return math.NaN() }

var _ = ansi.StringWidth
