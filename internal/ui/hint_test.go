package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// The tab hints mark their key names in the text (§enter§) and render them
// bold. Two things a plain string assertion would miss: the marker leaking
// onto the screen, and the bold not being turned off again, which would run
// the rest of the header in bold.
func TestHintKeys(t *testing.T) {
	prev := lipgloss.ColorProfile()
	defer lipgloss.SetColorProfile(prev)

	for _, prof := range []termenv.Profile{termenv.TrueColor, termenv.ANSI256, termenv.ANSI, termenv.Ascii} {
		lipgloss.SetColorProfile(prof)
		out := hint("§X§ = rescue")

		if strings.Contains(out, hintKeyMark) {
			t.Errorf("profile %v: key marker leaked into the output: %q", prof, out)
		}
		if got := ansi.Strip(out); got != "X = rescue" {
			t.Errorf("profile %v: renders as %q, want %q", prof, got, "X = rescue")
		}
		if prof == termenv.Ascii {
			continue // no attributes or color to check
		}

		// the key is bold and the text after it is not
		bold, rest, ok := strings.Cut(out, "X")
		if !ok || !hasParam(lastSGR(bold), "1") {
			t.Errorf("profile %v: the key is not bold: %q", prof, out)
		}
		if hasParam(lastSGR(rest), "1") {
			t.Errorf("profile %v: the text after the key stayed bold: %q", prof, out)
		}
		// teal foreground, and no background band: that was tried and was
		// heavier than the header needed
		if !strings.Contains(out, "\x1b[") {
			t.Errorf("profile %v: hint is not styled at all: %q", prof, out)
		}
		if bg := backgroundSGR(out); bg != "" {
			t.Errorf("profile %v: hint should have no background, got %q", prof, bg)
		}
	}
}

// hasParam reports whether an SGR parameter list contains p exactly.
func hasParam(sgr, p string) bool {
	for _, got := range strings.Split(sgr, ";") {
		if got == p {
			return true
		}
	}
	return false
}

// lastSGR returns the parameters of the final SGR sequence in s, which is
// the styling in force where s stops.
func lastSGR(s string) string {
	i := strings.LastIndex(s, "\x1b[")
	if i < 0 {
		return ""
	}
	end := strings.Index(s[i:], "m")
	if end < 0 {
		return ""
	}
	return s[i+2 : i+end]
}

// backgroundSGR returns the background parameters of the first SGR sequence,
// or "" when nothing sets a background.
func backgroundSGR(s string) string {
	start := strings.Index(s, "\x1b[")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start:], "m")
	if end < 0 {
		return ""
	}
	var out []string
	params := strings.Split(s[start+2:start+end], ";")
	for i := 0; i < len(params); i++ {
		p := params[i]
		if p == "48" { // extended background: 5;<n> or 2;<r>;<g>;<b>
			n := 2
			if i+1 < len(params) && params[i+1] == "2" {
				n = 4
			}
			if i+n < len(params) {
				out = append(out, strings.Join(params[i:i+n+1], ";"))
				i += n
			}
			continue
		}
		if p == "38" { // extended foreground: skip its parameters
			n := 2
			if i+1 < len(params) && params[i+1] == "2" {
				n = 4
			}
			i += n
			continue
		}
		if len(p) == 2 && p[0] == '4' { // 40-47
			out = append(out, p)
		}
		if len(p) == 3 && p[0] == '1' { // 100-107
			out = append(out, p)
		}
	}
	return strings.Join(out, ";")
}
