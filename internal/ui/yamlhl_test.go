package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func TestHlYAML(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	cases := []struct {
		line       string
		wantStyled []string // fragments that must be inside an SGR span
		wantPlain  []string // fragments that must remain unstyled
	}{
		{"apiVersion: v1", []string{"apiVersion", ":"}, []string{"v1"}},
		{"  - name: web", []string{"- ", "name"}, []string{"web"}},
		{"replicas: 3", []string{"3"}, nil},
		{"enabled: true # comment", []string{"true", "# comment"}, nil},
		{`image: "nginx:1.25"`, []string{`"nginx:1.25"`}, nil},
		{"image: nginx:1.25", []string{"image"}, []string{"nginx:1.25"}},
		{"url: http://x/y#z", []string{"url"}, []string{"http://x/y#z"}},
		{"# only a comment", []string{"# only a comment"}, nil},
		{"---", []string{"---"}, nil},
		{"script: |-", []string{"|-"}, nil},
		{"base: &b {}", []string{"&b", "{}"}, nil},
		{"- 42", []string{"- ", "42"}, nil},
		{"    echo hello", nil, []string{"    echo hello"}},
		{"", nil, nil},
	}
	for _, c := range cases {
		got := hlYAML(c.line)
		if ansi.Strip(got) != c.line {
			t.Errorf("%q: text changed: %q", c.line, ansi.Strip(got))
		}
		for _, w := range c.wantStyled {
			if !strings.Contains(got, w+"\x1b[") && !strings.Contains(got, w+"\x1b[0m") {
				t.Errorf("%q: %q should be styled: %q", c.line, w, got)
			}
		}
		for _, w := range c.wantPlain {
			if !strings.Contains(got, w) || strings.Contains(got, "m"+w+"\x1b") {
				t.Errorf("%q: %q should be plain: %q", c.line, w, got)
			}
		}
	}
	// TOML: section, key = value, comment
	for _, l := range []string{`[host."https://mirror"]`, `capabilities = ["pull", "resolve"] # x`, `# c`} {
		if got := hlTOML(l); ansi.Strip(got) != l || got == l {
			t.Errorf("toml %q: %q", l, got)
		}
	}
	// dispatch by extension; wrapping keeps every fragment's text
	yaml := "a:\n  b: " + strings.Repeat("x", 120) + "\n"
	lines := fileLines("/etc/rancher/rke2/config.yaml.d/50-rancher.yaml", yaml, 60)
	var plain []string
	for _, l := range lines {
		plain = append(plain, ansi.Strip(l))
	}
	if len(lines) < 3 || plain[0] != "a:" || !strings.HasPrefix(plain[1], "  b:") || strings.Count(strings.Join(plain, ""), "x") != 120 {
		t.Errorf("fileLines: %q", plain)
	}
	if strings.Contains(lines[0], "m[0m") {
		t.Errorf("empty SGR span in %q", lines[0])
	}
	if got := fileLines("/var/log/x.log", "plain: text\n", 60); got[0] != "plain: text" {
		t.Errorf("a .log file must not be highlighted: %q", got[0])
	}
	if got := fileLines("/x/config.toml", "a = 1\n", 60); got[0] == "a = 1" {
		t.Errorf("toml should be highlighted: %q", got[0])
	}
}
