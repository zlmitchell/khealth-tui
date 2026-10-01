package rca

import "github.com/zlmitchell/khealth-tui/internal/logs"

// Color turns on ANSI colors in the text reports (WriteReport,
// WriteIncidents, WriteContext). Off by default: the caller sets it for a
// terminal only, so a pipe or a file gets plain text. The 16 base colors
// follow the terminal's own theme, light or dark.
var Color bool

const (
	cBold    = "1"
	cDim     = "2"
	cRed     = "31"
	cBoldRed = "1;31"
	cYellow  = "33"
	cCyan    = "36"
)

func paint(code, s string) string {
	if !Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// confColor: how strongly the evidence backs a hypothesis.
func confColor(conf string) string {
	switch conf {
	case "high":
		return cBoldRed
	case "medium":
		return cYellow
	}
	return cCyan
}

func classColor(c logs.Class) string {
	switch c {
	case logs.ClassError:
		return cRed
	case logs.ClassWarn:
		return cYellow
	}
	return cDim
}

// kindColor matches the Incidents tab: what took a node or a container
// down in red, what held a workload back in yellow.
func kindColor(k Kind) string {
	switch k {
	case KindAPI, KindReboot, KindOOM, KindNodeOOM, KindEviction, KindNotReady, KindSSH:
		return cBoldRed
	case KindRestart, KindProbe, KindPull, KindSchedule, KindPressure, KindRejected, KindDrain:
		return cYellow
	}
	return cCyan
}

func scoreColor(s float64) string {
	switch {
	case s >= 0.7:
		return cBoldRed
	case s >= 0.4:
		return cYellow
	}
	return cDim
}
