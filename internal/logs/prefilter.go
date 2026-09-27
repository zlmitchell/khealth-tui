package logs

import (
	"regexp/syntax"
	"strings"
	"unsafe"
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
	set := needOf(literals(re.Simplify()))
	for _, s := range set {
		if len(s) < minNeed {
			return nil
		}
	}
	return set
}

// litInfo is what the prefilter knows about a sub-expression: every
// string it can match, when that is a short list (exact), and a set one of
// which every match contains (need). Adjacent exact parts are joined, so
// Start(ing|ed) rke2 yields "starting rke2" / "started rke2" rather than
// the shared prefix "start" alone (Go's parser factors such prefixes out).
type litInfo struct {
	exact []string // nil: unbounded
	need  []string // nil: nothing known
}

const maxExact = 32

func literals(re *syntax.Regexp) litInfo {
	switch re.Op {
	case syntax.OpLiteral:
		s := strings.ToLower(string(re.Rune))
		return litInfo{exact: []string{s}, need: []string{s}}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return litInfo{exact: []string{""}} // zero width
	case syntax.OpCapture:
		return literals(re.Sub[0])
	case syntax.OpQuest:
		if c := literals(re.Sub[0]); c.exact != nil && len(c.exact) < maxExact {
			return litInfo{exact: append([]string{""}, c.exact...)}
		}
		return litInfo{}
	case syntax.OpPlus:
		return litInfo{need: needOf(literals(re.Sub[0]))}
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return litInfo{need: needOf(literals(re.Sub[0]))}
		}
		return litInfo{}
	case syntax.OpAlternate:
		var ex, nd []string
		exOK, ndOK := true, true
		for _, sub := range re.Sub {
			c := literals(sub)
			if c.exact == nil {
				exOK = false
			} else {
				ex = append(ex, c.exact...)
			}
			if n := needOf(c); n == nil {
				ndOK = false
			} else {
				nd = append(nd, n...)
			}
		}
		out := litInfo{}
		if exOK && len(ex) <= maxExact {
			out.exact = ex
		}
		if ndOK {
			out.need = nd
		}
		return out
	case syntax.OpConcat:
		// any run of exact parts, joined, is required; so is any part's
		// need: keep the most selective of them
		var best []string
		consider := func(set []string) {
			if usable(set) && (best == nil || better(set, best)) {
				best = set
			}
		}
		cur, allExact := []string{""}, true
		for _, sub := range re.Sub {
			c := literals(sub)
			if c.exact != nil && len(cur)*len(c.exact) <= maxExact {
				cur = cross(cur, c.exact)
				continue
			}
			allExact = false
			consider(cur)
			consider(needOf(c))
			cur = []string{""}
			if c.exact != nil {
				cur = c.exact
			}
		}
		consider(cur)
		if allExact {
			return litInfo{exact: cur, need: best}
		}
		return litInfo{need: best}
	}
	return litInfo{} // character classes, any char, star
}

// needOf is the required set of a node: its need, or its exact strings
// when none of them is empty.
func needOf(c litInfo) []string {
	if c.need != nil {
		return c.need
	}
	if usable(c.exact) {
		return c.exact
	}
	return nil
}

func usable(set []string) bool {
	if len(set) == 0 {
		return false
	}
	for _, s := range set {
		if s == "" {
			return false
		}
	}
	return true
}

func cross(a, b []string) []string {
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out
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

// MayMatch reports whether any knowledge-base pattern could match the line
// (its prefilter passes). A line it rejects classifies as an unmatched info
// line, so a caller reading a large log can keep only these.
func MayMatch(line string) bool {
	t := strings.TrimSpace(line)
	return mayMatch(t, strings.ToLower(t))
}

// MayMatchBytes is MayMatch without allocating: the line is ASCII
// lower-cased into scratch (every pattern literal is ASCII, so that finds
// whatever strings.ToLower would) and looked at in place. For readers
// streaming large files, who make a string only of the lines that pass.
func MayMatchBytes(line []byte, scratch *[]byte) bool {
	if len(line) == 0 {
		return false
	}
	low := append((*scratch)[:0], line...)
	for i, c := range low {
		if c >= 'A' && c <= 'Z' {
			low[i] = c + 'a' - 'A'
		}
	}
	*scratch = low
	return mayMatch(unsafe.String(&line[0], len(line)), unsafe.String(&low[0], len(low)))
}

func mayMatch(t, lower string) bool {
	for i := range patterns {
		p := &patterns[i]
		if p.pre != nil {
			if p.pre(t, lower) {
				return true
			}
			continue
		}
		if p.need == nil {
			return true
		}
		for _, n := range p.need {
			if strings.Contains(lower, n) {
				return true
			}
		}
	}
	return false
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
