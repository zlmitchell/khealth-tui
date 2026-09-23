// Package termtheme decides whether the terminal has a dark background, so
// the UI can pick the light or dark variant of its colors (theme: auto).
package termtheme

import (
	"regexp"
	"strconv"
)

// queries asks for the background (OSC 11) and text color (OSC 10), then
// DA1: every terminal answers DA1, and answers in order, so its reply
// arriving without the color replies means they are not supported - no
// need to wait out the timeout.
const queries = "\x1b]11;?\x1b\\\x1b]10;?\x1b\\\x1b[c"

var (
	reColor = regexp.MustCompile(`\x1b\](1[01]);rgb:([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})`)
	reDA1   = regexp.MustCompile(`\x1b\[\?[0-9;]*c`)
)

// parseReply reads the terminal's answers to queries. The background
// decides; a terminal that reports only its text color gets the opposite
// of that. ok is false when neither came back.
func parseReply(b []byte) (dark, ok bool) {
	fg := -1.0
	for _, m := range reColor.FindAllSubmatch(b, -1) {
		l := luminance(string(m[2]), string(m[3]), string(m[4]))
		if string(m[1]) == "11" {
			return l < 0.5, true
		}
		fg = l
	}
	if fg >= 0 {
		return fg >= 0.5, true
	}
	return false, false
}

// luminance of an xterm rgb: reply, whose channels are 1-4 hex digits each
// (scaled to that many digits' maximum).
func luminance(r, g, b string) float64 {
	ch := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 16)
		return float64(v) / float64(uint64(1)<<(4*len(s))-1)
	}
	return 0.2126*ch(r) + 0.7152*ch(g) + 0.0722*ch(b)
}
