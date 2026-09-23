package ui

// SSH settings dialog (s when SSH is not usable). A node that refuses the
// login - wrong user, no escalation, a host key that changed - used to mean
// quitting, changing a flag and starting again, which on a cluster that is
// already in trouble is the worst moment to lose the session. The dialog
// edits a copy of the SSH config, rebuilds the runner and re-collects.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
)

// sshField is one row of the dialog.
type sshField int

const (
	sshUser sshField = iota
	sshPort
	sshKey
	sshPassword
	sshBecome
	sshHostKey
	sshApply
	sshDisable
	sshFieldCount
)

// becomeOptions and hostKeyOptions are the values their rows cycle through.
var becomeOptions = []string{"auto", "sudo", "dzdo", "doas", "none"}

const (
	hostKeyStrict    = "strict"
	hostKeyAcceptNew = "accept-new"
	hostKeyIgnore    = "ignore"
)

var hostKeyOptions = []string{hostKeyStrict, hostKeyAcceptNew, hostKeyIgnore}

// sshEditor is the dialog's state: a draft of the SSH config that only
// reaches a.cfg when it connects.
type sshEditor struct {
	draft  config.SSH
	cursor sshField
	input  textinput.Model
	typing bool
	err    string // why the last apply failed
	note   string
}

// hostKeyMode renders the two host key booleans as one setting.
func hostKeyMode(s config.SSH) string {
	switch {
	case !s.StrictHostKey:
		return hostKeyIgnore
	case s.AcceptNewHostKeys:
		return hostKeyAcceptNew
	}
	return hostKeyStrict
}

func setHostKeyMode(s *config.SSH, mode string) {
	switch mode {
	case hostKeyIgnore:
		s.StrictHostKey, s.AcceptNewHostKeys = false, false
	case hostKeyAcceptNew:
		s.StrictHostKey, s.AcceptNewHostKeys = true, true
	default:
		s.StrictHostKey, s.AcceptNewHostKeys = true, false
	}
}

// openSSHConfig opens the dialog with the settings in force.
func (a *App) openSSHConfig() {
	e := &sshEditor{draft: a.cfg.SSH, err: a.sshErr}
	e.input = textinput.New()
	e.input.CharLimit = 256
	e.input.Width = 48
	a.sshEdit = e
	a.overlay = ovSSH
}

// sshRows describes the dialog: label, value and what the row explains.
func (e *sshEditor) rows() [][3]string {
	d := e.draft
	port := strconv.Itoa(d.Port)
	if d.Port == 0 {
		port = "22"
	}
	pass := "(none)"
	if d.Password != "" {
		pass = strings.Repeat("*", 8)
	}
	key := d.Key
	if key == "" {
		key = "(agent / default keys)"
	}
	hk := map[string]string{
		hostKeyStrict:    "refuse a host that is not in known_hosts",
		hostKeyAcceptNew: "record an unknown host on first contact; a changed key still fails",
		hostKeyIgnore:    "verify nothing - anything answering the address is trusted",
	}
	return [][3]string{
		sshUser:     {"user", d.User, "the login khealth opens on every node"},
		sshPort:     {"port", port, ""},
		sshKey:      {"key file", key, "empty uses ssh-agent and ~/.ssh/id_*"},
		sshPassword: {"password", pass, "used when the key fails, and for sudo unless become_password is set"},
		sshBecome:   {"become", d.Become, "how the probes run as root: auto tries sudo, dzdo, doas"},
		sshHostKey:  {"host keys", hostKeyMode(d), hk[hostKeyMode(d)]},
		sshApply:    {"", "", ""},
		sshDisable:  {"", "", ""},
	}
}

// handleSSHKey drives the dialog.
func (a *App) handleSSHKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	e := a.sshEdit
	if e == nil {
		a.overlay = ovNone
		return a, nil
	}
	key := m.String()
	if e.typing {
		switch key {
		case "esc":
			e.typing = false
			e.input.Blur()
			return a, nil
		case "enter":
			e.commit()
			return a, nil
		}
		var cmd tea.Cmd
		e.input, cmd = e.input.Update(m)
		return a, cmd
	}

	switch key {
	case "esc", "q":
		a.overlay = ovNone
		a.sshEdit = nil
	case "j", "down":
		if e.cursor < sshFieldCount-1 {
			e.cursor++
		}
	case "k", "up":
		if e.cursor > 0 {
			e.cursor--
		}
	case "left", "h":
		e.cycle(-1)
	case "right", "l", " ":
		e.cycle(1)
	case "enter":
		switch e.cursor {
		case sshApply:
			return a, a.applySSHConfig()
		case sshDisable:
			a.overlay, a.sshEdit = ovNone, nil
			a.sshEnabled = false
			a.setStatus("SSH collection disabled (s re-opens these settings)")
		case sshBecome, sshHostKey:
			e.cycle(1)
		default:
			e.edit()
		}
	}
	return a, nil
}

// edit starts typing into the selected row.
func (e *sshEditor) edit() {
	d := e.draft
	switch e.cursor {
	case sshUser:
		e.input.SetValue(d.User)
		e.input.EchoMode = textinput.EchoNormal
		e.input.Prompt = "user> "
	case sshPort:
		e.input.SetValue(strconv.Itoa(d.Port))
		e.input.EchoMode = textinput.EchoNormal
		e.input.Prompt = "port> "
	case sshKey:
		e.input.SetValue(d.Key)
		e.input.EchoMode = textinput.EchoNormal
		e.input.Prompt = "key file> "
	case sshPassword:
		e.input.SetValue("")
		e.input.EchoMode = textinput.EchoPassword
		e.input.Prompt = "password> "
	default:
		return
	}
	e.typing = true
	e.input.CursorEnd()
	e.input.Focus()
}

// commit stores what was typed into the draft.
func (e *sshEditor) commit() {
	v := strings.TrimSpace(e.input.Value())
	switch e.cursor {
	case sshUser:
		e.draft.User = v
	case sshPort:
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			e.draft.Port = n
		} else if v != "" {
			e.note = "port must be a number between 1 and 65535"
		}
	case sshKey:
		e.draft.Key = v
	case sshPassword:
		e.draft.Password = e.input.Value() // not trimmed: a password may end in a space
	}
	e.typing = false
	e.input.Blur()
}

// cycle moves an enum row by one.
func (e *sshEditor) cycle(by int) {
	move := func(opts []string, cur string) string {
		i := 0
		for j, o := range opts {
			if o == cur {
				i = j
			}
		}
		return opts[((i+by)%len(opts)+len(opts))%len(opts)]
	}
	switch e.cursor {
	case sshBecome:
		cur := e.draft.Become
		if cur == "" {
			cur = "auto"
		}
		e.draft.Become = move(becomeOptions, cur)
		e.draft.Sudo = e.draft.Become != "none"
	case sshHostKey:
		setHostKeyMode(&e.draft, move(hostKeyOptions, hostKeyMode(e.draft)))
	}
}

// applySSHConfig rebuilds the runner from the draft. The settings are kept
// only when a runner can be built; the dialog stays open with the error
// otherwise, so a typo does not cost the session.
func (a *App) applySSHConfig() tea.Cmd {
	e := a.sshEdit
	if e == nil {
		return nil
	}
	draft := e.draft
	draft.Enabled = true
	if draft.Port == 0 {
		draft.Port = 22
	}
	draft.NormalizeUser() // typing root@node in the user field is the same mistake
	r, err := sshrun.New(draft)
	if err != nil {
		e.err, e.note = err.Error(), ""
		return nil
	}
	if a.runner != nil {
		a.runner.Close() // the old runner holds connections opened as the old user
	}
	a.runner, a.sshEnabled, a.sshErr = r, true, ""
	a.cfg.SSH = draft
	a.overlay, a.sshEdit = ovNone, nil

	// everything collected over SSH was collected as the previous login
	a.nodes, a.pending = map[string]*nodeinfo.Info{}, map[string]bool{}
	a.etcd, a.etcdPend, a.etcdExec = map[string]*etcd.Probe{}, map[string]bool{}, nil
	a.gen++ // answers still in flight were asked under the old settings
	a.heavyNext = true
	a.setStatus(fmt.Sprintf("reconnecting as %s (become %s, host keys %s)", draft.User, draft.Become, hostKeyMode(draft)))
	return a.collectCmds(a.snap)
}

// renderSSHConfig draws the dialog.
func (a *App) renderSSHConfig() (string, []string) {
	e := a.sshEdit
	if e == nil {
		return "", nil
	}
	var lines []string
	add := func(s ...string) { lines = append(lines, s...) }

	add(styleDim.Render("These apply to every node. Nothing is written to the config file: they last for this session."), "")
	if e.err != "" {
		add("  "+styleCrit.Render("SSH is not usable: ")+trunc(e.err, a.width-24), "")
	}

	rows := e.rows()
	for f := sshUser; f <= sshHostKey; f++ {
		r := rows[f]
		line := fmt.Sprintf("  %-12s %s", r[0], styleBold.Render(r[1]))
		if r[2] != "" {
			line += styleDim.Render("   " + r[2])
		}
		if f == e.cursor {
			if e.typing {
				add("  " + e.input.View())
				continue
			}
			add(selectRow("> "+strings.TrimPrefix(line, "  "), a.width-8))
			continue
		}
		add(line)
	}

	add("")
	actions := []struct {
		f     sshField
		label string
		note  string
	}{
		{sshApply, "Apply and reconnect", "rebuild the SSH runner and collect again"},
		{sshDisable, "Disable SSH collection", "run on the API alone; s re-opens this"},
	}
	for _, act := range actions {
		line := "  " + styleBold.Render(act.label) + styleDim.Render("   "+act.note)
		if act.f == e.cursor {
			line = selectRow("> "+styleBold.Render(act.label)+styleDim.Render("   "+act.note), a.width-8)
		}
		add(line)
	}
	if e.note != "" {
		add("", "  "+styleWarn.Render(e.note))
	}
	add("", styleDim.Render("j/k choose, enter edits or runs, left/right cycles become and host keys, esc closes"))
	if hostKeyMode(e.draft) == hostKeyIgnore {
		add(styleWarn.Render("  host keys: ignore verifies nothing for the rest of the session - a machine answering the address is trusted, including one that is not yours"))
	}
	return "SSH settings", lines
}
