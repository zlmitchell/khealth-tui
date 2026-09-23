package termtheme

import "testing"

func TestParseReply(t *testing.T) {
	const da1 = "\x1b[?61;4;6;7;14;21;22;23;24;28;32;42;52c"
	for _, c := range []struct {
		name, reply string
		dark, ok    bool
	}{
		// Windows Terminal through ConPTY, three color schemes
		{"white", "\x1b]11;rgb:f8f8/f8f8/f8f8\x1b\\\x1b]10;rgb:1212/1212/1212\x1b\\" + da1, false, true},
		{"powershell blue", "\x1b]11;rgb:0101/2424/5656\x1b\\\x1b]10;rgb:cccc/cccc/cccc\x1b\\" + da1, true, true},
		{"dark", "\x1b]11;rgb:1e1e/1e1e/1e1e\x1b\\\x1b]10;rgb:cccc/cccc/cccc\x1b\\" + da1, true, true},
		// BEL-terminated, two-digit channels
		{"bel", "\x1b]11;rgb:ff/ff/ff\a" + da1, false, true},
		// only the text color: dark text means a light background
		{"text only", "\x1b]10;rgb:1212/1212/1212\x1b\\" + da1, false, true},
		{"no colors", da1, false, false},
		{"nothing", "", false, false},
	} {
		dark, ok := parseReply([]byte(c.reply))
		if dark != c.dark || ok != c.ok {
			t.Errorf("%s: dark=%v ok=%v, want %v %v", c.name, dark, ok, c.dark, c.ok)
		}
	}
}
