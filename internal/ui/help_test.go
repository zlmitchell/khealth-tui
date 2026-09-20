package ui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// TestHelpLinesFitWidth: every help line fits the width it was rendered for
// (nothing relies on the overlay's truncation) and the author line is there.
func TestHelpLinesFitWidth(t *testing.T) {
	for _, w := range []int{60, 80, 120, 200} {
		lines := helpLines(w)
		for i, l := range lines {
			if ansi.StringWidth(l) > w {
				t.Errorf("width %d: line %d is %d wide: %q", w, i, ansi.StringWidth(l), ansi.Strip(l))
			}
		}
		if !strings.Contains(ansi.Strip(lines[len(lines)-1]), "created by Zach Mitchell") {
			t.Errorf("width %d: author line missing", w)
		}
	}
	if os.Getenv("KHEALTH_HELP_PREVIEW") != "" {
		t.Log("\n" + ansi.Strip(strings.Join(helpLines(116), "\n")))
	}
}

// TestDetailWrap: w in the detail overlay wraps long lines and is
// remembered for the next detail; a resize re-lays them out.
func TestDetailWrap(t *testing.T) {
	a := testApp()
	a.width = 60
	long := strings.Repeat("word ", 40)
	a.setDetail("t", []string{"short", long})
	if a.overlay != ovDetail || len(a.detailLines) != 2 {
		t.Fatalf("detail not opened unwrapped: overlay=%v lines=%d", a.overlay, len(a.detailLines))
	}
	v := ansi.Strip(a.View())
	if strings.Count(v, "word") > 12 {
		t.Errorf("unwrapped detail shows the whole long line:\n%s", v)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if !a.detailWrap || len(a.detailLines) < 4 {
		t.Fatalf("w did not wrap: wrap=%v lines=%d", a.detailWrap, len(a.detailLines))
	}
	if v := ansi.Strip(a.View()); strings.Count(v, "word") != 40 || !strings.Contains(v, "w wrap") {
		t.Errorf("wrapped detail must show every word and the hint:\n%s", v)
	}
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if n := len(a.detailLines); n >= 4 || n < 2 {
		t.Errorf("resize did not re-layout: %d lines", n)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	a.setDetail("t2", []string{long})
	if !a.detailWrap || len(a.detailLines) < 2 {
		t.Errorf("wrap not remembered for the next detail: wrap=%v lines=%d", a.detailWrap, len(a.detailLines))
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if a.detailWrap || len(a.detailLines) != 1 {
		t.Errorf("w did not unwrap: wrap=%v lines=%d", a.detailWrap, len(a.detailLines))
	}
}
