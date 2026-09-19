package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func TestSelectRowKeepsColours(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)

	red := styleCrit.Render("100 err")
	row := "node  " + red + "  " + styleWarn.Render("5 warn")
	out := selectRow(row, 40)
	if ansi.Strip(out) != pad(ansi.Strip(row), 40) {
		t.Errorf("text changed: %q", ansi.Strip(out))
	}
	on, _, _ := strings.Cut(styleSel.Render("|"), "|")
	if on == "" {
		t.Fatal("selection style emitted no escape codes")
	}
	// the red cell survives and the band is re-applied after its reset
	if !strings.Contains(out, red) {
		t.Errorf("inner colour lost: %q", out)
	}
	if !strings.Contains(out, "\x1b[0m"+on) {
		t.Errorf("selection band not re-applied after an inner reset: %q", out)
	}
	if !strings.HasPrefix(out, on) {
		t.Errorf("row should start with the selection band: %q", out)
	}
}
