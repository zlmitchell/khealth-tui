package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestWrapStyledCarriesStyle(t *testing.T) {
	// a bold msg value that spans the break (escape codes written by hand:
	// lipgloss emits none without a TTY)
	in := "\x1b[1;38;2;1;2;3m\"msg\"\x1b[0m:\x1b[1m\"" + strings.Repeat("word ", 12) + "end\"\x1b[0m,\"k\":1"
	frags := wrapStyled(in, 30)
	if len(frags) < 2 {
		t.Fatalf("expected a wrap, got %d fragments", len(frags))
	}
	if !strings.HasSuffix(frags[0], "\x1b[0m") {
		t.Errorf("first fragment should close the open style: %q", frags[0])
	}
	if !strings.HasPrefix(frags[1], "\x1b[1m") {
		t.Errorf("continuation should reopen the bold: %q", frags[1])
	}
	joined := strings.Join(frags, " ") // the wrap eats the space at each break
	if got := strings.Join(strings.Fields(ansi.Strip(joined)), " "); got != strings.Join(strings.Fields(ansi.Strip(in)), " ") {
		t.Errorf("text changed by wrapping: %q", got)
	}
	for _, f := range frags {
		if ansi.StringWidth(f) > 30 {
			t.Errorf("fragment wider than limit: %q", f)
		}
	}
	// a fragment that ends after a reset must not reopen anything
	plain := wrapStyled("\x1b[31mred\x1b[0m plain "+strings.Repeat("x", 40), 20)
	if strings.HasPrefix(plain[1], "\x1b[") {
		t.Errorf("no style should carry after a reset: %q", plain[1])
	}
}
