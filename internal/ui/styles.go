package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/stig"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

var (
	colorOK     = lipgloss.AdaptiveColor{Light: "#1a7f37", Dark: "#3fb950"}
	colorWarn   = lipgloss.AdaptiveColor{Light: "#9a6700", Dark: "#d29922"}
	colorCrit   = lipgloss.AdaptiveColor{Light: "#cf222e", Dark: "#f85149"}
	colorInfo   = lipgloss.AdaptiveColor{Light: "#0969da", Dark: "#58a6ff"}
	colorDim    = lipgloss.AdaptiveColor{Light: "#6e7781", Dark: "#8b949e"}
	colorAccent = lipgloss.AdaptiveColor{Light: "#8250df", Dark: "#bc8cff"}

	styleOK     = lipgloss.NewStyle().Foreground(colorOK)
	styleWarn   = lipgloss.NewStyle().Foreground(colorWarn)
	styleCrit   = lipgloss.NewStyle().Foreground(colorCrit).Bold(true)
	styleInfo   = lipgloss.NewStyle().Foreground(colorInfo)
	styleDim    = lipgloss.NewStyle().Foreground(colorDim)
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleTitle  = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(colorDim).Underline(true)
	// selection: a background band rather than reverse video so colored cells
	// (severity text, bars, sparklines) keep their colors on the selected row
	colorSelBg  = lipgloss.AdaptiveColor{Light: "#d0d7de", Dark: "#30363d"}
	styleSel    = lipgloss.NewStyle().Background(colorSelBg).Bold(true)
	colorTabBar = lipgloss.AdaptiveColor{Light: "#e4e6ea", Dark: "#21262d"}
	colorTabTxt = lipgloss.AdaptiveColor{Light: "#24292f", Dark: "#c9d1d9"}

	// tab strip: a full-width band; active tab is an inverted accent block
	styleTabBar = lipgloss.NewStyle().Background(colorTabBar)
	styleTabOn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#ffffff", Dark: "#000000"}).Background(colorAccent).Padding(0, 1)
	styleTabOff = lipgloss.NewStyle().Foreground(colorTabTxt).Background(colorTabBar)
	styleTabKey = lipgloss.NewStyle().Bold(true).Foreground(colorAccent).Background(colorTabBar)
	// sub-tab strip: same band treatment as the main strip, one shade lighter,
	// active item inverted in the info color so the two levels read differently
	colorSubBar    = lipgloss.AdaptiveColor{Light: "#f0f2f5", Dark: "#161b22"}
	styleSubBar    = lipgloss.NewStyle().Background(colorSubBar)
	styleSubOn     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#ffffff", Dark: "#000000"}).Background(colorInfo).Padding(0, 1)
	styleSubOff    = lipgloss.NewStyle().Foreground(colorTabTxt).Background(colorSubBar)
	styleRule      = lipgloss.NewStyle().Foreground(colorAccent)
	styleRuleTitle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleKey       = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	// tab hints: the extra keys a tab offers ("X = rescue") sat in the dim
	// text of the header and read as a footnote. They are teal - the one
	// bright color nothing else here uses, so it lifts them out without
	// borrowing a meaning: info blue inverted is an active sub-tab, amber is
	// WARN, green is OK, violet is the active tab and every title.
	//
	// No background: a band turned out to be heavier than the header needs.
	// Only the key names are bold (styleHintKey), so the keys carry the
	// emphasis instead of the whole sentence.
	colorHint    = lipgloss.AdaptiveColor{Light: "#0f766e", Dark: "#2dd4bf"}
	styleHint    = lipgloss.NewStyle().Foreground(colorHint)
	styleHintKey = lipgloss.NewStyle().Bold(true).Foreground(colorHint)
	styleBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorAccent).Padding(0, 1)
)

// hintKeyMark wraps a key name in a hint so it comes out bold: it has to be
// a character no hint text contains, and the text is written with the keys
// in place rather than passed separately, so a call site reads as the line
// it draws.
const hintKeyMark = "§"

// hint renders the extra keys a tab offers. Key names marked with
// hintKeyMark come out bold; the rest is plain teal. Callers keep their own
// separator in front of it.
func hint(s string) string {
	var b strings.Builder
	for i, part := range strings.Split(s, hintKeyMark) {
		if part == "" {
			continue
		}
		if i%2 == 1 {
			b.WriteString(styleHintKey.Render(part))
		} else {
			b.WriteString(styleHint.Render(part))
		}
	}
	return b.String()
}

func sevStyle(s checks.Severity) lipgloss.Style {
	switch s {
	case checks.SevCrit:
		return styleCrit
	case checks.SevWarn:
		return styleWarn
	}
	return styleInfo
}

func sevText(s checks.Severity) string {
	return sevStyle(s).Render(fmt.Sprintf("%-4s", s.String()))
}

func stigStyle(s stig.Status) lipgloss.Style {
	switch s {
	case stig.Pass:
		return styleOK
	case stig.Fail:
		return styleCrit
	case stig.Manual:
		return styleWarn
	case stig.NA:
		return styleDim
	}
	return styleInfo
}

func okText(ok bool, yes, no string) string {
	if ok {
		return styleOK.Render(yes)
	}
	return styleCrit.Render(no)
}

func pctStyle(p float64, warn, crit int) lipgloss.Style {
	switch {
	case p < 0:
		return styleDim
	case p >= float64(crit):
		return styleCrit
	case p >= float64(warn):
		return styleWarn
	}
	return styleOK
}

func pctText(p float64, warn, crit int) string {
	if p < 0 {
		return styleDim.Render("-")
	}
	return pctStyle(p, warn, crit).Render(fmt.Sprintf("%3.0f%%", p))
}

func humanBytes(b float64) string {
	units := []string{"B", "Ki", "Mi", "Gi", "Ti"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f%s", b, units[i])
	}
	if b >= 100 {
		return fmt.Sprintf("%.0f%s", b, units[i])
	}
	return fmt.Sprintf("%.1f%s", b, units[i])
}

func humanKB(kb int64) string { return humanBytes(float64(kb) * 1024) }

func age(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return strutil.HumanDur(time.Since(t))
}

func trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	// control characters make the terminal wrap or move the cursor
	if strings.ContainsAny(s, "\t\r\n") {
		s = strings.NewReplacer("\t", "    ", "\r", "", "\n", " ").Replace(s)
	}
	if ansi.StringWidth(s) <= w {
		return s
	}
	if w <= 1 {
		return ansi.Truncate(s, w, "")
	}
	return ansi.Truncate(s, w, "…")
}

func pad(s string, w int) string {
	sw := ansi.StringWidth(s)
	if sw >= w {
		return trunc(s, w)
	}
	return s + strings.Repeat(" ", w-sw)
}

// selectRow highlights a (possibly colored) row end to end. Inner color
// resets would cancel the selection band part way through, so the band is
// re-applied after each one.
func selectRow(s string, width int) string {
	s = pad(s, width)
	on, off, _ := strings.Cut(styleSel.Render("|"), "|")
	if on == "" {
		return s
	}
	return on + strings.ReplaceAll(s, "\x1b[0m", "\x1b[0m"+on) + off
}

func padLeft(s string, w int) string {
	sw := ansi.StringWidth(s)
	if sw >= w {
		return trunc(s, w)
	}
	return strings.Repeat(" ", w-sw) + s
}
