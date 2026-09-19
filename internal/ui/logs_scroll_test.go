package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/charmbracelet/x/ansi"

	"k8s-health-tui/internal/logs"
)

func containsPlain(v, sub string) bool { return strings.Contains(ansi.Strip(v), sub) }

func TestLogsLinesScrollProbe(t *testing.T) {
	a := testApp()
	a.height = 20
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, fmt.Sprintf("2024-09-18T10:%02d:00+00:00 cp-1 rke2[1]: level=error msg=\"boom %d\"", i%60, i))
	}
	a.nodes["cp-1"].Journal = lines
	a.recompute()
	a.logSum["cp-1"] = logs.Classify(lines, a.lastRefresh)
	a.tab = tabLogs
	a.cursor[tabLogs] = 0
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.logsNode != "cp-1" {
		t.Fatalf("not in lines view")
	}
	c := a.currentContent()
	t.Logf("rows=%d header=%d selectable=%v bodyH=%d", len(c.rows), len(c.header), c.selectable, a.bodyHeight())
	for i := 0; i < 30; i++ {
		a.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	}
	t.Logf("after 30 downs: cursor=%d scroll=%d", a.cursor[tabLogs], a.scroll[tabLogs])
	if a.cursor[tabLogs] != 30 || a.scroll[tabLogs] == 0 {
		t.Errorf("cursor/scroll did not advance: cursor=%d scroll=%d", a.cursor[tabLogs], a.scroll[tabLogs])
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyPgDown})
	t.Logf("after pgdown: cursor=%d scroll=%d", a.cursor[tabLogs], a.scroll[tabLogs])
}

func TestLogsLinesScrollRender(t *testing.T) {
	a := testApp()
	a.height = 20
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, fmt.Sprintf("2024-09-18T10:%02d:00+00:00 cp-1 rke2[1]: level=error msg=\"boom %d\"", i%60, i))
	}
	a.nodes["cp-1"].Journal = lines
	a.logSum["cp-1"] = logs.Classify(lines, a.lastRefresh)
	a.tab = tabLogs
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	for i := 0; i < 30; i++ {
		a.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	}
	v := a.View()
	t.Logf("view has boom 30: %v ; boom 0: %v", containsPlain(v, "boom 30"), containsPlain(v, "boom 0\""))
	if !containsPlain(v, "boom 30") {
		t.Errorf("selected row not visible after scrolling")
	}
}
