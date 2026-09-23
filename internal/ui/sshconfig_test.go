package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
)

// With no usable login, s used to print "SSH unavailable: ..." and stop:
// the only way to change the user or the host key policy was to quit and
// start again, during whatever outage brought you there.
func TestSSHConfigOpensWhenNoRunner(t *testing.T) {
	a := testApp()
	a.runner, a.sshErr = nil, "no SSH auth method available (no agent, no key)"

	a.handleKey(runes("s"))
	if a.overlay != ovSSH || a.sshEdit == nil {
		t.Fatalf("s with no runner should open the settings: overlay %v status %q", a.overlay, a.status)
	}
	v := ansi.Strip(a.View())
	for _, want := range []string{"SSH settings", "no SSH auth method available", "become", "host keys", "Apply and reconnect", "Disable SSH collection"} {
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(v, want) {
				t.Errorf("dialog should show %q:\n%s", want, v)
			}
		})
	}
}

// A working runner keeps the old meaning of s, so the muscle memory for
// turning collection off is unchanged.
func TestSSHConfigKeepsToggleWhenConnected(t *testing.T) {
	a := testApp()
	a.sshEnabled = true
	// sshrun.New only checks that a login is possible; it opens nothing
	r, err := sshrun.New(config.SSH{User: "ops", Password: "pw", Port: 22, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a.runner = r
	a.handleKey(runes("s"))
	if a.overlay == ovSSH {
		t.Errorf("s with a runner should toggle, not open the dialog")
	}
	if a.sshEnabled {
		t.Errorf("s should have disabled collection")
	}
}

func TestSSHConfigEditing(t *testing.T) {
	a := testApp()
	a.runner, a.sshErr = nil, "connection refused"
	a.handleKey(runes("s"))
	e := a.sshEdit
	if e == nil {
		t.Fatal("no editor")
	}

	// become and host keys cycle in place rather than opening an input
	e.cursor = sshBecome
	before := e.draft.Become
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRight})
	if e.draft.Become == before || e.typing {
		t.Errorf("become should cycle without typing: %q -> %q", before, e.draft.Become)
	}
	if e.draft.Become == "none" && e.draft.Sudo {
		t.Errorf("become none should clear Sudo")
	}

	e.cursor = sshHostKey
	setHostKeyMode(&e.draft, hostKeyStrict)
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRight})
	if got := hostKeyMode(e.draft); got != hostKeyAcceptNew {
		t.Errorf("host keys should cycle strict -> accept-new, got %q", got)
	}
	// ignore is called out rather than listed as a neutral peer
	setHostKeyMode(&e.draft, hostKeyIgnore)
	if v := ansi.Strip(a.View()); !strings.Contains(v, "verifies nothing for the rest of the session") {
		t.Errorf("ignore should be flagged:\n%s", v)
	}

	// a typed user is only stored on enter
	e.cursor = sshUser
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !e.typing {
		t.Fatal("enter on the user row should start typing")
	}
	e.input.SetValue("ubuntu")
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if e.draft.User == "ubuntu" {
		t.Errorf("esc should discard the edit")
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	e.input.SetValue("ubuntu")
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if e.draft.User != "ubuntu" {
		t.Errorf("enter should store the user, got %q", e.draft.User)
	}

	// a bad port is refused with a reason instead of being stored
	e.cursor = sshPort
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	e.input.SetValue("70000")
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if e.draft.Port == 70000 || e.note == "" {
		t.Errorf("port 70000 should be refused: port %d note %q", e.draft.Port, e.note)
	}
}

// A draft that cannot build a runner leaves the session alone: the dialog
// stays open with the reason rather than dropping the working settings.
func TestSSHConfigApplyFailureKeepsDialog(t *testing.T) {
	a := testApp()
	a.runner, a.sshErr = nil, "x"
	a.handleKey(runes("s"))
	e := a.sshEdit
	e.draft.User = "" // sshrun.New refuses an empty user
	e.cursor = sshApply
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != ovSSH || a.sshEdit == nil {
		t.Fatalf("a failed apply should keep the dialog open, overlay %v", a.overlay)
	}
	if a.sshEdit.err == "" {
		t.Errorf("the failure should be shown in the dialog")
	}
	if a.runner != nil {
		t.Errorf("a failed apply must not install a runner")
	}
}

// Disable is an entry in the dialog, so the one key still reaches every
// outcome without becoming a hidden multi-state cycle.
func TestSSHConfigDisable(t *testing.T) {
	a := testApp()
	a.runner, a.sshErr = nil, "x"
	a.sshEnabled = true
	a.handleKey(runes("s"))
	a.sshEdit.cursor = sshDisable
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != ovNone || a.sshEnabled {
		t.Errorf("disable should close the dialog and stop collection: overlay %v enabled %v", a.overlay, a.sshEnabled)
	}
}
