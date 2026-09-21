package ui

import (
	"path"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// YAML / TOML highlighting for the config and manifest dumps: keys, the
// sequence dash, quoted strings, numbers, booleans/null, anchors and
// comments. It is line-based and stateless on purpose: block scalars that
// themselves hold YAML (HelmChart valuesContent, kubeadm ClusterConfiguration
// inside a ConfigMap) get highlighted too, and a script line inside one at
// worst gets a key color on its first word.

var (
	styleYAMLKey   = lipgloss.NewStyle().Foreground(colorInfo).Bold(true)
	styleYAMLDash  = lipgloss.NewStyle().Foreground(colorAccent)
	styleYAMLDoc   = lipgloss.NewStyle().Foreground(colorDim).Bold(true)
	styleYAMLAnch  = lipgloss.NewStyle().Foreground(colorWarn)
	styleYAMLBlock = lipgloss.NewStyle().Foreground(colorDim)
	styleTOMLSect  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)

	// indent, "- " markers, key (bare or quoted), the colon, then the rest
	reYAMLKey = regexp.MustCompile(`^(\s*)((?:- )*)("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[A-Za-z0-9_.$/@?][A-Za-z0-9_.$/@ \-()]*?)(:)(\s+|$)(.*)$`)
	reYAMLNum = regexp.MustCompile(`^[-+]?(?:\d[\d_]*(?:\.\d*)?(?:[eE][-+]?\d+)?|\.\d+|0x[0-9a-fA-F]+|0o[0-7]+|\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	reTOMLKey = regexp.MustCompile(`^(\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.\-]+)(\s*=\s*)(.*)$`)
)

// fileLines renders a collected file for a detail view, highlighted by its
// extension and wrapped to width.
func fileLines(p, content string, width int) []string {
	switch strings.ToLower(path.Ext(p)) {
	case ".yaml", ".yml", ".json":
		return yamlLines(content, width)
	case ".toml":
		return hlLines(content, width, hlTOML)
	}
	// rke2's config.yaml.d drop-ins are yaml whatever they are called
	if strings.Contains(p, "config.yaml") {
		return yamlLines(content, width)
	}
	return wrap(content, width)
}

// yamlLines highlights YAML text and wraps it to width.
func yamlLines(content string, width int) []string {
	return hlLines(content, width, hlYAML)
}

func hlLines(content string, width int, hl func(string) string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		out = append(out, wrapStyled(hl(l), width)...)
	}
	return out
}

// hlYAML colors one line of YAML.
func hlYAML(line string) string {
	if strings.TrimSpace(line) == "" {
		return line
	}
	t := strings.TrimLeft(line, " ")
	indent := line[:len(line)-len(t)]
	switch {
	case strings.HasPrefix(t, "#"):
		return indent + styleDim.Render(t)
	case t == "---" || t == "..." || strings.HasPrefix(t, "--- ") || strings.HasPrefix(t, "%YAML") || strings.HasPrefix(t, "%TAG"):
		return indent + styleYAMLDoc.Render(t)
	}
	if m := reYAMLKey.FindStringSubmatch(line); m != nil {
		dash := m[2]
		if dash != "" {
			dash = styleYAMLDash.Render(dash)
		}
		return m[1] + dash + styleYAMLKey.Render(m[3]) + styleLogSep.Render(m[4]) + m[5] + hlYAMLValue(m[6])
	}
	// a bare sequence item: "- value", "- - value"
	rest := t
	dashes := ""
	for strings.HasPrefix(rest, "- ") || rest == "-" {
		if rest == "-" {
			dashes += "-"
			rest = ""
			break
		}
		dashes += "- "
		rest = rest[2:]
	}
	if dashes != "" {
		return indent + styleYAMLDash.Render(dashes) + hlYAMLValue(rest)
	}
	// a plain continuation / block scalar line: only a trailing comment
	v, c := splitYAMLComment(line)
	if c == "" {
		return line
	}
	return v + styleDim.Render(c)
}

// hlYAMLValue colors a scalar (what follows "key: " or "- "), keeping a
// trailing comment dim.
func hlYAMLValue(v string) string {
	v, comment := splitYAMLComment(v)
	if comment != "" {
		comment = styleDim.Render(comment)
	}
	s := strings.TrimRight(v, " ")
	pad := v[len(s):]
	if s == "" {
		return pad + comment
	}
	// anchors, aliases and tags prefix the real value
	pre := ""
	for {
		if s == "" || !(s[0] == '&' || s[0] == '*' || s[0] == '!') {
			break
		}
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			pre += styleYAMLAnch.Render(s)
			s = ""
			break
		}
		pre += styleYAMLAnch.Render(s[:i]) + " "
		s = strings.TrimLeft(s[i:], " ")
	}
	if s == "" {
		return pre + pad + comment
	}
	lower := strings.ToLower(s)
	switch {
	case s[0] == '"' || s[0] == '\'':
		return pre + styleLogStr.Render(s) + pad + comment
	case s[0] == '|' || s[0] == '>':
		return pre + styleYAMLBlock.Render(s) + pad + comment
	case lower == "true" || lower == "false" || lower == "yes" || lower == "no" || lower == "on" || lower == "off" || lower == "null" || s == "~":
		return pre + styleLogBool.Render(s) + pad + comment
	case reYAMLNum.MatchString(s):
		return pre + styleLogNum.Render(s) + pad + comment
	case s == "{}" || s == "[]":
		return pre + styleDim.Render(s) + pad + comment
	}
	return pre + s + pad + comment
}

// splitYAMLComment separates a trailing " # comment" that is not inside
// quotes.
func splitYAMLComment(s string) (value, comment string) {
	if !strings.Contains(s, "#") {
		return s, ""
	}
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS && (i == 0 || s[i-1] != '\\'):
			inD = !inD
		case c == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// hlTOML colors one line of TOML (containerd config.toml, hosts.toml).
func hlTOML(line string) string {
	t := strings.TrimSpace(line)
	if t == "" {
		return line
	}
	indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	switch {
	case strings.HasPrefix(t, "#"):
		return indent + styleDim.Render(t)
	case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
		return indent + styleTOMLSect.Render(t)
	}
	if m := reTOMLKey.FindStringSubmatch(line); m != nil {
		return m[1] + styleYAMLKey.Render(m[2]) + styleLogSep.Render(m[3]) + hlYAMLValue(m[4])
	}
	v, c := splitYAMLComment(line)
	if c == "" {
		return line
	}
	return v + styleDim.Render(c)
}
