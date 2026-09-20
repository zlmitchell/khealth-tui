package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// TestLoadingStateCentered: before the first snapshot the body shows the
// loading message in the middle of the viewport, and the frame keeps its
// exact height.
func TestLoadingStateCentered(t *testing.T) {
	a := testApp()
	a.snap = nil
	a.width, a.height = 100, 30
	frame := ansi.Strip(a.View())
	lines := strings.Split(frame, "\n")
	if len(lines) != a.height {
		t.Fatalf("frame has %d lines, want %d", len(lines), a.height)
	}
	idx := -1
	for i, l := range lines {
		if strings.Contains(l, "loading cluster state") {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("loading message missing:\n%s", frame)
	}
	if idx < a.height/3 || idx > 2*a.height/3 {
		t.Errorf("loading message on line %d of %d: not vertically centered", idx, a.height)
	}
	l := lines[idx]
	lead := len(l) - len(strings.TrimLeft(l, " "))
	if lead < a.width/4 {
		t.Errorf("loading message starts at column %d of %d: not horizontally centered:\n%q", lead, a.width, l)
	}
	if !strings.Contains(frame, "https://10.0.0.1:6443") {
		t.Errorf("server not shown under the loading message")
	}
}

// TestSecurityOptIn: the Security tab shows only the opt-in notice until
// Shift+S; started without an SSH user it says so before and after the scan,
// and nothing anywhere still says "press S".
func TestSecurityOptIn(t *testing.T) {
	a := testApp()
	a.runner, a.sshEnabled, a.sshErr = nil, false, "ssh user is not set (ssh.user / --ssh-user)"
	a.recompute()
	if len(a.stigRes) != 0 {
		t.Fatalf("STIG rules evaluated before the scan: %d", len(a.stigRes))
	}
	a.tab = tabSecurity
	for sub := 0; sub < 3; sub++ {
		a.sub[tabSecurity] = sub
		v := ansi.Strip(a.View())
		if !strings.Contains(v, "Security scan not run yet") || !strings.Contains(v, "Shift+S") || strings.Contains(v, "STIG / CIS checks") {
			t.Errorf("sub-tab %d before the scan: opt-in notice missing or rules shown:\n%s", sub, v)
		}
		if !strings.Contains(v, "SSH disabled: ssh user is not set") {
			t.Errorf("sub-tab %d: no SSH-disabled line:\n%s", sub, v)
		}
	}
	if v := ansi.Strip(a.View()); !strings.Contains(v, "ssh: disabled") {
		t.Errorf("header does not say ssh: disabled")
	}
	// Shift+S without SSH: API-side rules only, each view says SSH is disabled
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	if !a.secScanned || len(a.stigRes) == 0 {
		t.Fatalf("scan did not run: scanned=%v rules=%d", a.secScanned, len(a.stigRes))
	}
	for sub := 0; sub < 3; sub++ {
		a.sub[tabSecurity] = sub
		v := ansi.Strip(a.View())
		if !strings.Contains(v, "SSH disabled: ssh user is not set") {
			t.Errorf("sub-tab %d after the scan: no SSH-disabled line:\n%s", sub, v)
		}
		if strings.Contains(v, "press S") || strings.Contains(v, "Press S") {
			t.Errorf("sub-tab %d still says press S", sub)
		}
	}
	if v := ansi.Strip(strings.Join(helpLines(120), "\n")); strings.Contains(v, "press S") {
		t.Errorf("help still says press S")
	}
}
