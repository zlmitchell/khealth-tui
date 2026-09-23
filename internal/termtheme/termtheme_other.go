//go:build !windows

package termtheme

import "github.com/charmbracelet/lipgloss"

// Dark reports whether the terminal background is dark. termenv asks the
// terminal (OSC 11, then COLORFGBG) on these platforms. Call it before
// bubbletea reads stdin, or the reply races the TUI's own input reader.
func Dark() bool {
	return lipgloss.HasDarkBackground()
}
