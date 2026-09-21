// Package strutil holds the small formatting helpers that every package
// used to carry its own copy of: first-line extraction, truncation, byte
// and duration rendering, and a few slice/map conveniences. No imports
// outside the standard library so anything can use it.
package strutil

import (
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// FirstLine is the trimmed first line of s, cut to 200 bytes with "..."
// so a multi-line error or event message fits a one-line finding.
func FirstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return TruncStr(s, 200)
}

// TruncStr cuts s to n bytes, marking the cut with "...".
func TruncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// TruncList joins up to n items and counts the rest: "a, b, c (+4 more)".
func TruncList(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" (+%d more)", len(l)-n)
}

// FirstNonEmpty returns the first non-empty string, or "".
func FirstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// PrefixIf prepends prefix when s is not empty.
func PrefixIf(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// Uniq drops repeated items, keeping first-seen order.
func Uniq[T comparable](l []T) []T {
	seen := make(map[T]bool, len(l))
	var out []T
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// SortedKeys is the map's keys in sorted order.
func SortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

// AtoiOr parses a trimmed integer, or returns def.
func AtoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

// HumanBytes renders a byte count in binary units: "512B", "1.5KiB".
func HumanBytes(b float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f%s", b, units[i])
	}
	return fmt.Sprintf("%.1f%s", b, units[i])
}

// HumanDur renders a duration at the precision people read it: "45s",
// "3m", "2h05m", "3d4h", "40d". Negative durations are shown as their
// magnitude.
func HumanDur(d time.Duration) string {
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

// URLHost is the host of a URL without its port ("https://[fd00::1]:2380"
// gives "fd00::1"), or "" when raw does not parse.
func URLHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(u.Host); err == nil {
		return h
	}
	return u.Host
}
