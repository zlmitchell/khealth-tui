package logs

import (
	"regexp/syntax"
	"strings"
)

// A log bundle holds hundreds of thousands of journal lines per node, and
// running every line through every knowledge-base regexp cost ~260 us per
// line (Go's regexp has no literal prefilter for unanchored alternations);
// with the prefilter it is ~24 us (100k kubelet/rke2 lines, 2026-09-26).
// Each pattern therefore carries the literals one of which any match must
// contain (the codesearch / RE2 prefilter idea): a line containing none of
// them cannot match and skips the regexp. The set is derived from the
// regexp itself, so the two cannot drift apart; a pattern with no usable
// literal (a set with one shorter than minNeed) always runs its regexp.

const minNeed = 3

func init() {
	for i := range patterns {
		p := &patterns[i]
		p.need = needLiterals(p.Re.String())
		// the catch-alls have no literal to key on (\bE[0-9]{4} is a klog
		// marker) and run on every line no other pattern claimed: scan for
		// what they match by hand, then confirm with the regexp
		switch p.Name {
		case "generic-error":
			p.pre = func(line, lower string) bool {
				return strings.Contains(lower, "level=error") || strings.Contains(lower, "error=") || klogMark(line, 'E')
			}
		case "generic-warn":
			p.pre = func(line, lower string) bool {
				return strings.Contains(lower, "level=warn") || klogMark(line, 'W')
			}
		}
	}
}

// klogMark reports whether line holds \b<sev>[0-9]{4}<space> (a klog
// header such as "E0926 ").
func klogMark(line string, sev byte) bool {
	for i := 0; i+5 < len(line); i++ {
		if line[i] != sev || (i > 0 && isWord(line[i-1])) {
			continue
		}
		if isDigit(line[i+1]) && isDigit(line[i+2]) && isDigit(line[i+3]) && isDigit(line[i+4]) && line[i+5] == ' ' {
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isWord(c byte) bool {
	return isDigit(c) || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// needLiterals returns the lower-cased literals a match of expr must
// contain one of, or nil when there is no such set worth checking.
func needLiterals(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	set, ok := required(re.Simplify())
	if !ok {
		return nil
	}
	for _, s := range set {
		if len(s) < minNeed {
			return nil
		}
	}
	return set
}

// required computes the literal set for one node of the parsed regexp.
func required(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}, true
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false
	case syntax.OpAlternate:
		var out []string
		for _, s := range re.Sub {
			set, ok := required(s)
			if !ok {
				return nil, false
			}
			out = append(out, set...)
		}
		return out, true
	case syntax.OpConcat:
		// any child's set is required; keep the most selective one: the
		// longest shortest literal, then the fewest literals
		var best []string
		found := false
		for _, s := range re.Sub {
			set, ok := required(s)
			if !ok {
				continue
			}
			if !found || better(set, best) {
				best, found = set, true
			}
		}
		return best, found
	}
	return nil, false
}

func better(a, b []string) bool {
	ma, mb := shortest(a), shortest(b)
	if ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func shortest(set []string) int {
	m := -1
	for _, s := range set {
		if m < 0 || len(s) < m {
			m = len(s)
		}
	}
	return m
}

// matches runs the pattern on a trimmed line; lower is the same line
// lower-cased (computed once per line by the caller).
func (p *Pattern) matches(line, lower string) bool {
	if p.pre != nil && !p.pre(line, lower) {
		return false
	}
	if p.need != nil {
		hit := false
		for _, n := range p.need {
			if strings.Contains(lower, n) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return p.Re.MatchString(line)
}
