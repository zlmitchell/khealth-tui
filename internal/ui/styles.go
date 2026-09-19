package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/stig"
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
	styleSel    = lipgloss.NewStyle().Reverse(true)
	styleTabOn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#ffffff", Dark: "#000000"}).Background(colorAccent).Padding(0, 1)
	styleTabOff = lipgloss.NewStyle().Foreground(colorDim).Padding(0, 1)
	styleBar    = lipgloss.NewStyle().Foreground(colorDim)
	styleKey    = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	styleBox    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorAccent).Padding(0, 1)
)

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

func humanDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d.Hours()/24), int(d.Hours())%24)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func age(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanDur(time.Since(t))
}

func trunc(s string, w int) string {
	if w <= 0 {
		return ""
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

func padLeft(s string, w int) string {
	sw := ansi.StringWidth(s)
	if sw >= w {
		return trunc(s, w)
	}
	return strings.Repeat(" ", w-sw) + s
}

func plural(n int, s string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, s)
	}
	return fmt.Sprintf("%d %ss", n, s)
}
