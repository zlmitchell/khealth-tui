package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/zlmitchell/khealth-tui/internal/logs"
)

// w on a node's lines wraps the message column: a long message shows whole
// over several lines, j steps entry by entry and a filter keeps an entry's
// continuation lines with it.
func TestLogsLinesWrap(t *testing.T) {
	a := testApp()
	a.width, a.height = 100, 30
	tail := strings.Repeat("word ", 40)
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, fmt.Sprintf("2024-09-18T10:%02d:00+00:00 cp-1 rke2[1]: level=error msg=\"boom %d %sEND%d\"", i, i, tail, i))
	}
	a.nodes["cp-1"].Journal = lines
	a.logSum["cp-1"] = logs.Classify(lines, a.lastRefresh)
	a.tab = tabLogs
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.logsNode != "cp-1" {
		t.Fatalf("not in lines view")
	}
	if containsPlain(a.View(), "END0") {
		t.Fatalf("message not cut before wrapping")
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("w")})
	if !a.logsWrap {
		t.Fatalf("w did not turn wrapping on")
	}
	c := a.currentContent()
	if len(c.rows) <= 5 || !c.rows[1].cont {
		t.Fatalf("wrapped rows = %d, second cont=%v", len(c.rows), len(c.rows) > 1 && c.rows[1].cont)
	}
	if v := a.View(); !containsPlain(v, "END0") {
		t.Errorf("wrapped message not shown whole:\n%s", v)
	}
	first := a.selectedID()
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	rows := a.filteredRows(c)
	if cur := a.cursor[tabLogs]; rows[cur].cont || a.selectedID() == first {
		t.Errorf("j landed on a continuation line or the same entry: cursor=%d", cur)
	}
	a.filters[tabLogs] = "end3"
	got := a.filteredRows(a.currentContent())
	if len(got) < 2 || got[0].cont || !got[1].cont {
		t.Errorf("filter on the wrapped tail did not keep the whole entry: %d rows", len(got))
	}
}
