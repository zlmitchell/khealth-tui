package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// In-page find for the detail overlay and the inspector: / types a query
// (case-insensitive substring, hits update as you type), n/N jump between
// hits, esc clears. Matches are highlighted on top of whatever styling the
// line already has (YAML colors survive), the current hit stands out.

var (
	styleFind    = lipgloss.NewStyle().Background(lipgloss.AdaptiveColor{Light: "#ffe58a", Dark: "#4d4000"})
	styleFindCur = lipgloss.NewStyle().Background(colorWarn).Foreground(lipgloss.AdaptiveColor{Light: "#ffffff", Dark: "#000000"}).Bold(true)
)

// textFind is the find state for one page of lines.
type textFind struct {
	query   string
	typing  bool  // the query is being edited: keys go to it
	hits    []int // indices of the lines that match, ascending
	cur     int   // index into hits of the current one
	scanned int   // lines already scanned (a stream appends; see extend)
}

func (f *textFind) active() bool { return f.query != "" || f.typing }

// run recomputes the hits for lines and keeps the current hit on the same
// line when it still matches, else on the first hit at or after `near`.
func (f *textFind) run(lines []string, near int) {
	prev := -1
	if f.cur < len(f.hits) {
		prev = f.hits[f.cur]
	}
	f.hits, f.scanned = f.hits[:0], 0
	if f.query == "" {
		f.cur = 0
		return
	}
	f.extend(lines)
	f.cur = 0
	for i, h := range f.hits {
		if h == prev {
			f.cur = i
			return
		}
	}
	for i, h := range f.hits {
		if h >= near {
			f.cur = i
			return
		}
	}
}

// extend scans the lines appended since the last run/extend (a log stream
// grows; the earlier hits and the current one stay put).
func (f *textFind) extend(lines []string) {
	if f.query == "" {
		return
	}
	q := strings.ToLower(f.query)
	for i := f.scanned; i < len(lines); i++ {
		if strings.Contains(strings.ToLower(ansi.Strip(lines[i])), q) {
			f.hits = append(f.hits, i)
		}
	}
	f.scanned = len(lines)
}

// current returns the line of the current hit.
func (f *textFind) current() (int, bool) {
	if f.cur < len(f.hits) {
		return f.hits[f.cur], true
	}
	return 0, false
}

// step moves to the next (+1) or previous (-1) hit, wrapping around.
func (f *textFind) step(d int) (int, bool) {
	if len(f.hits) == 0 {
		return 0, false
	}
	f.cur = ((f.cur+d)%len(f.hits) + len(f.hits)) % len(f.hits)
	return f.hits[f.cur], true
}

func (f *textFind) clear() { *f = textFind{} }

// handleKey consumes a key while the query is being typed. It reports
// whether the key was taken and whether the query changed.
func (f *textFind) handleKey(key string) (consumed, changed bool) {
	if !f.typing {
		return false, false
	}
	switch key {
	case "enter":
		f.typing = false
		if f.query == "" {
			f.clear()
		}
		return true, false
	case "esc":
		f.clear()
		return true, true
	case "backspace":
		if f.query != "" {
			r := []rune(f.query)
			f.query = string(r[:len(r)-1])
		}
		return true, true
	case " ":
		f.query += " "
		return true, true
	}
	if r := []rune(key); len(r) == 1 && r[0] >= 0x20 {
		f.query += key
		return true, true
	}
	return true, false // other keys (arrows etc.) are swallowed while typing
}

// status is the footer fragment: the prompt while typing, the hit count
// afterwards.
func (f *textFind) status() string {
	if f.typing {
		return styleKey.Render("/") + f.query + styleWarn.Render("▏") + styleDim.Render(fmt.Sprintf(" %d hits · enter keeps, esc cancels", len(f.hits)))
	}
	if f.query == "" {
		return ""
	}
	if len(f.hits) == 0 {
		return styleKey.Render("/"+f.query) + styleCrit.Render(" no match") + styleDim.Render(" · esc clears")
	}
	return styleKey.Render("/"+f.query) + styleDim.Render(fmt.Sprintf(" %d/%d · n/N next/prev · esc clears", f.cur+1, len(f.hits)))
}

// hasHit reports whether line i matches.
func (f *textFind) hasHit(i int) bool {
	k := sort.SearchInts(f.hits, i)
	return k < len(f.hits) && f.hits[k] == i
}

// render highlights the matches in line i (unchanged when it has none).
func (f *textFind) render(line string, i int) string {
	if f.query == "" || !f.hasHit(i) {
		return line
	}
	st := styleFind
	if c, ok := f.current(); ok && c == i {
		st = styleFindCur
	}
	return highlightMatches(line, f.query, st)
}

// jumpScroll returns the scroll offset that puts line hit a third of the
// way down a window of visible lines, clamped to [0, max].
func jumpScroll(hit, visible, max int) int {
	s := hit - visible/3
	if s > max {
		s = max
	}
	if s < 0 {
		s = 0
	}
	return s
}

// highlightMatches wraps every case-insensitive occurrence of needle in a
// styled line with st, leaving the escape sequences already in the line in
// place and restoring the style that was open where a match ends.
func highlightMatches(line, needle string, st lipgloss.Style) string {
	if needle == "" || line == "" {
		return line
	}
	// walk the line: plain bytes with, for each, its offset in the output
	// and the SGR sequence in effect there
	var plain strings.Builder
	starts := make([]int, 0, len(line))
	opens := make([]string, 0, len(line))
	open := ""
	for i := 0; i < len(line); {
		if line[i] == 0x1b {
			if m := reSGR.FindStringIndex(line[i:]); m != nil && m[0] == 0 {
				seq := line[i : i+m[1]]
				if seq == "\x1b[0m" || seq == "\x1b[m" {
					open = ""
				} else {
					open += seq
				}
				i += m[1]
				continue
			}
		}
		starts = append(starts, i)
		opens = append(opens, open)
		plain.WriteByte(line[i])
		i++
	}
	p := plain.String()
	lp, ln := strings.ToLower(p), strings.ToLower(needle)
	if len(lp) != len(p) || len(ln) != len(needle) {
		lp, ln = p, needle // non-ASCII case folding changed lengths: match exactly
	}
	type span struct{ s, e int }
	var spans []span
	for from := 0; ; {
		k := strings.Index(lp[from:], ln)
		if k < 0 {
			break
		}
		spans = append(spans, span{from + k, from + k + len(ln)})
		from += k + len(ln)
	}
	if len(spans) == 0 {
		return line
	}
	var out strings.Builder
	pos := 0 // offset in line
	for _, sp := range spans {
		start := starts[sp.s]
		end := len(line)
		if sp.e < len(p) {
			end = starts[sp.e]
		}
		out.WriteString(line[pos:start])
		// the match keeps the colors open before it (the highlight only adds
		// a background) and re-opens what was in effect at its end
		out.WriteString(st.Render(p[sp.s:sp.e]))
		if sp.e < len(p) && opens[sp.e] != "" {
			out.WriteString(opens[sp.e])
		}
		pos = end
	}
	out.WriteString(line[pos:])
	return out.String()
}
