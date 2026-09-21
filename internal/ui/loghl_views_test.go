package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/zlmitchell/khealth-tui/internal/logs"
)

// TestLogDetailHighlighting: every log view colors lines through the same
// highlighter - the lines table, the line detail (subject and context) and
// the node detail - with the journal prefix stripped first so the format
// detection sees the message; wrapping keeps the colors on every fragment.
func TestLogDetailHighlighting(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	a := testApp()
	a.width, a.height = 100, 40
	var lines []string
	for i := 0; i < 8; i++ {
		lines = append(lines, fmt.Sprintf(`2024-09-18T10:%02d:00+00:00 cp-1 rke2[1]: time="2024-09-18T10:%02d:00Z" level=error msg="Failed to connect to proxy. Empty dialer response" error="dial tcp 10.0.0.5:9345: connect: connection refused" attempt=%d`, i, i, i))
	}
	a.nodes["cp-1"].Journal = lines
	a.logSum["cp-1"] = logs.Classify(lines, a.lastRefresh)
	a.tab = tabLogs
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter}) // node -> its lines
	// logfmt keys are colored: "level" carries a color, the value "error" the crit color
	levelKey := strings.Contains(highlightLog(`level=error msg="x"`), "m"+"level"+"\x1b[0m")
	if !levelKey {
		t.Fatalf("highlighter does not color logfmt keys: %q", highlightLog(`level=error msg="x"`))
	}
	colored := func(s string) bool {
		return strings.Contains(s, "mlevel\x1b[0m") && strings.Contains(s, "merror\x1b[0m")
	}
	// the table row
	c := a.currentContent()
	if len(c.rows) == 0 || !colored(c.rows[0].text) {
		t.Errorf("lines table row not highlighted")
	}
	// the line detail: subject and context lines, prefix dim
	a.cursor[tabLogs] = 3
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != ovDetail {
		t.Fatalf("detail not opened")
	}
	subject, context := 0, 0
	for _, l := range a.detailRaw {
		switch p := ansi.Strip(l); {
		case strings.Contains(p, "cp-1 rke2[1]:") && colored(l):
			context++
		case strings.Contains(p, "proxy") && !strings.Contains(p, "cp-1") && strings.Contains(l, "["):
			subject++ // the subject is pre-wrapped: a colored fragment is enough
		}
	}
	if subject == 0 || context < 4 {
		t.Errorf("line detail: subject colored lines=%d, context colored lines=%d", subject, context)
	}
	// wrapped: every fragment of the subject keeps its colors
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	frags := 0
	for _, l := range a.detailLines {
		p := ansi.Strip(l)
		if strings.Contains(p, "Empty dialer") || strings.Contains(p, "refused") {
			frags++
			if !strings.Contains(l, "\x1b[") {
				t.Errorf("wrapped fragment lost its color: %q", l)
			}
		}
	}
	if frags < 2 {
		t.Errorf("subject not wrapped into colored fragments: %d", frags)
	}
	// the node detail's Lines section
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape}) // back to the node list
	a.cursor[tabLogs] = 0
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	n := 0
	for _, l := range a.detailRaw {
		if colored(l) {
			n++
		}
	}
	if n < 8 {
		t.Errorf("node detail lines not highlighted: %d of 8", n)
	}
}

// TestKlogLinesColoredAndVerdict: a header-stripped klog line with a single
// key=value pair is still colored in the table (structured message bold,
// pair colored); the detail keeps the klog header with its severity letter
// colored; an unmatched error gets a verdict, and one inside the startup
// window that never recurs reads as a startup race.
func TestKlogLinesColoredAndVerdict(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	a := testApp()
	a.width, a.height = 160, 40
	a.lastRefresh = time.Date(2026, 9, 20, 18, 0, 0, 0, time.UTC)
	kubelet := []string{
		`I0920 12:02:40.000000  887086 kubelet.go:100] "Starting kubelet"`,
		`I0920 12:02:42.265094  887086 reconciler_common.go:251] "operationExecutor.VerifyControllerAttachedVolume started for volume \"policysync\" (UniqueName: \"kubernetes.io/host-path/9597-policysync\") pod \"rke2-canal-zjhmb\" (UID: \"9597\") " pod="kube-system/rke2-canal-zjhmb"`,
		`E0920 12:03:50.000000  887086 something.go:10] "Widget reconcile failed" err="widget \"a\" is on fire" widget="a"`,
		`E0920 12:40:00.000000  887086 other.go:10] "Gadget reconcile failed" err="gadget \"c\" is on fire" gadget="c"`,
	}
	a.nodes["cp-1"].LogFiles = nil
	a.logSum["cp-1"] = logs.ClassifySources([]logs.Source{{Unit: "kubelet", Lines: kubelet}}, a.lastRefresh)
	a.logsAll = true
	a.tab = tabLogs
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	c := a.currentContent()
	var info string
	for _, r := range c.rows {
		if strings.Contains(ansi.Strip(r.text), "VerifyControllerAttachedVolume") {
			info = r.text
		}
	}
	if info == "" || !strings.Contains(info, "\x1b[1m\"operationExecutor") {
		t.Errorf("single-pair klog line not colored in the table: %q", info)
	}
	// the pair sits past the table's width: check the highlighter's output itself
	if hl := highlightLog(logMessage(kubelet[1])); !strings.Contains(hl, "mpod\x1b[0m") || !strings.Contains(hl, "mreconciler_common.go:251] ") {
		t.Errorf("single-pair klog line: pair or location not colored: %q", hl)
	}
	// the detail of the startup-window error
	for i, r := range c.rows {
		if strings.Contains(ansi.Strip(r.text), "Widget reconcile") {
			a.cursor[tabLogs] = i
		}
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	v := ansi.Strip(strings.Join(a.detailRaw, "\n"))
	if !strings.Contains(v, "Pattern: startup-unmatched") || !strings.Contains(v, "Startup race, not a fault") || !strings.Contains(v, "Nothing to fix") {
		t.Errorf("startup race verdict missing:\n%s", v)
	}
	if !strings.Contains(strings.Join(a.detailRaw, "\n"), "mE\x1b[0m") {
		t.Errorf("detail lost the colored klog severity letter")
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	for i, r := range c.rows {
		if strings.Contains(ansi.Strip(r.text), "Gadget reconcile") {
			a.cursor[tabLogs] = i
		}
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	v = ansi.Strip(strings.Join(a.detailRaw, "\n"))
	if !strings.Contains(v, "Pattern: generic-error") || !strings.Contains(v, "Verdict") || !strings.Contains(v, "Past incident") {
		t.Errorf("generic error verdict missing:\n%s", v)
	}
}
