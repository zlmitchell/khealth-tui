package ui

import (
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Log line highlighting: JSON, logfmt (key=value), klog and plain lines get
// keys dimmed, level tokens coloured by severity and messages emphasised.

var (
	styleLogKey   = lipgloss.NewStyle().Foreground(colorDim)
	styleLogStr   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#0a7f5a", Dark: "#7ee787"})
	styleLogNum   = lipgloss.NewStyle().Foreground(colorInfo)
	styleLogBool  = lipgloss.NewStyle().Foreground(colorAccent)
	styleLogMsg   = lipgloss.NewStyle().Bold(true)
	styleLogDebug = lipgloss.NewStyle().Foreground(colorDim)

	reLogfmtTok = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.\-/]*)=("(?:[^"\\]|\\.)*"|\S+)`)
	reJSONKey   = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*`)
	reJSONVal   = regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?|true|false|null)`)
	reKlog      = regexp.MustCompile(`^([IWEF])(\d{4} \d\d:\d\d:\d\d\.\d+)\s+(\d+)\s+([A-Za-z0-9_./\-]+:\d+)\]\s?`)
	reLevelWord = regexp.MustCompile(`(?i)\b(FATAL|PANIC|ERROR|ERR|WARNING|WARN|INFO|DEBUG|TRACE)\b`)
)

func levelStyle(v string) (lipgloss.Style, bool) {
	switch strings.ToLower(strings.Trim(v, `"`)) {
	case "fatal", "panic", "critical", "crit", "error", "err", "e", "f":
		return styleCrit, true
	case "warn", "warning", "w":
		return styleWarn, true
	case "info", "i", "notice":
		return styleOK, true
	case "debug", "trace", "d", "t":
		return styleLogDebug, true
	}
	return lipgloss.Style{}, false
}

func isLevelKey(k string) bool {
	switch strings.ToLower(k) {
	case "level", "lvl", "severity", "loglevel", "log.level", "l":
		return true
	}
	return false
}

func isMsgKey(k string) bool {
	switch strings.ToLower(k) {
	case "msg", "message", "m", "event", "error", "err":
		return true
	}
	return false
}

// highlightLog colours one (unwrapped, timestamp-stripped) log line.
func highlightLog(l string) string {
	t := strings.TrimLeft(l, " ")
	pad := l[:len(l)-len(t)]
	switch {
	case strings.HasPrefix(t, "{") && strings.HasSuffix(strings.TrimRight(t, " "), "}"):
		return pad + highlightJSON(t)
	case reKlog.MatchString(t):
		return pad + highlightKlog(t)
	case strings.Count(t, "=") >= 2 && reLogfmtTok.MatchString(t):
		return pad + highlightLogfmt(t)
	}
	return pad + highlightPlain(t)
}

// highlightJSON walks the text once: keys dim, level values by severity,
// msg values bold, numbers/bools tinted. Structure is not validated, so a
// truncated line still renders.
func highlightJSON(s string) string {
	var b strings.Builder
	i := 0
	lastKey := ""
	for i < len(s) {
		if m := reJSONKey.FindStringSubmatchIndex(s[i:]); m != nil && m[0] == 0 {
			key := s[i+m[2] : i+m[3]]
			b.WriteString(styleLogKey.Render(s[i : i+m[1]]))
			lastKey = key
			i += m[1]
			if v := reJSONVal.FindStringIndex(s[i:]); v != nil {
				val := s[i : i+v[1]]
				b.WriteString(jsonValueStyle(lastKey, val))
				i += v[1]
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func jsonValueStyle(key, val string) string {
	if isLevelKey(key) {
		if st, ok := levelStyle(val); ok {
			return st.Bold(true).Render(val)
		}
	}
	if isMsgKey(key) {
		if strings.EqualFold(key, "error") || strings.EqualFold(key, "err") {
			return styleCrit.Render(val)
		}
		return styleLogMsg.Render(val)
	}
	switch {
	case strings.HasPrefix(val, `"`):
		return styleLogStr.Render(val)
	case val == "true" || val == "false" || val == "null":
		return styleLogBool.Render(val)
	}
	return styleLogNum.Render(val)
}

func highlightLogfmt(s string) string {
	return reLogfmtTok.ReplaceAllStringFunc(s, func(tok string) string {
		m := reLogfmtTok.FindStringSubmatch(tok)
		key, val := m[1], m[2]
		if isLevelKey(key) {
			if st, ok := levelStyle(val); ok {
				return styleLogKey.Render(key+"=") + st.Bold(true).Render(val)
			}
		}
		if isMsgKey(key) {
			if strings.EqualFold(key, "error") || strings.EqualFold(key, "err") {
				return styleLogKey.Render(key+"=") + styleCrit.Render(val)
			}
			return styleLogKey.Render(key+"=") + styleLogMsg.Render(val)
		}
		switch {
		case strings.HasPrefix(val, `"`):
			return styleLogKey.Render(key+"=") + styleLogStr.Render(val)
		case val == "true" || val == "false":
			return styleLogKey.Render(key+"=") + styleLogBool.Render(val)
		case isNumber(val):
			return styleLogKey.Render(key+"=") + styleLogNum.Render(val)
		}
		return styleLogKey.Render(key+"=") + val
	})
}

func highlightKlog(s string) string {
	m := reKlog.FindStringSubmatch(s)
	st, _ := levelStyle(m[1])
	// keep the original spacing: colour the severity letter, dim the rest of the header
	head := st.Bold(true).Render(m[1]) + styleLogKey.Render(m[0][1:])
	rest := s[len(m[0]):]
	if strings.Contains(rest, "=") {
		rest = highlightLogfmt(rest)
	} else if m[1] == "E" || m[1] == "F" {
		rest = styleCrit.Render(rest)
	}
	return head + rest
}

func highlightPlain(s string) string {
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "panic") || strings.Contains(low, "fatal") || strings.Contains(low, "error") || strings.Contains(low, "exception") || strings.Contains(low, "traceback"):
		return styleCrit.Render(s)
	case strings.Contains(low, "warn"):
		return styleWarn.Render(s)
	}
	return reLevelWord.ReplaceAllStringFunc(s, func(w string) string {
		if st, ok := levelStyle(w); ok {
			return st.Render(w)
		}
		return w
	})
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	dot := false
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r == '.' && !dot:
			dot = true
		case r == '-' && i == 0:
		default:
			return false
		}
	}
	return true
}

// splitTimestamp separates a leading kubelet RFC3339 timestamp.
func splitTimestamp(l string) (time.Time, string, bool) {
	ts, rest, ok := strings.Cut(l, " ")
	if !ok || len(ts) < 20 || ts[4] != '-' || ts[10] != 'T' {
		return time.Time{}, l, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, l, false
	}
	return t, rest, true
}
