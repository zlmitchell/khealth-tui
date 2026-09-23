// Command themeprobe asks the terminal it runs in for its colors and prints
// what came back, to find out which terminals khealth can detect light or
// dark in (termenv never asks on Windows). It sends OSC 11 (background),
// OSC 10 (foreground) and DA1 - a query every terminal answers, so a reply
// to DA1 without the color replies means the terminal does not support
// them, rather than that it is slow.
//
// Usage: run it in each terminal to check, then paste the output.
//
//	themeprobe [-timeout 1s]
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var (
	reColor = regexp.MustCompile(`\x1b\](1[01]);rgb:([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})/([0-9a-fA-F]{1,4})`)
	reDA1   = regexp.MustCompile(`\x1b\[\?[0-9;]*c`)
)

func main() {
	timeout := flag.Duration("timeout", time.Second, "how long to wait for the replies")
	flag.Parse()

	fmt.Println("environment:")
	for _, k := range []string{"TERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "WT_SESSION", "COLORTERM", "COLORFGBG", "SSH_TTY", "TMUX"} {
		if v, ok := os.LookupEnv(k); ok {
			fmt.Printf("  %s=%s\n", k, v)
		}
	}
	platformInfo()

	in, out := int(os.Stdin.Fd()), os.Stdout
	if !term.IsTerminal(in) {
		fmt.Println("stdin is not a terminal; run it directly in the terminal to check")
		os.Exit(1)
	}
	restoreOut := enableVTOutput()
	state, err := term.MakeRaw(in) // on Windows this also turns on VT input
	if err != nil {
		fmt.Println("raw mode:", err)
		os.Exit(1)
	}
	start := time.Now()
	fmt.Fprint(out, "\x1b]11;?\x1b\\\x1b]10;?\x1b\\\x1b[c")

	got := make(chan []byte)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				got <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	var reply []byte
	deadline := time.After(*timeout)
	var tookDA1 time.Duration
wait:
	for {
		select {
		case b := <-got:
			reply = append(reply, b...)
			if reDA1.Match(reply) {
				tookDA1 = time.Since(start)
				break wait
			}
		case <-deadline:
			break wait
		}
	}
	_ = term.Restore(in, state)
	restoreOut()

	fmt.Printf("\nraw reply (%d bytes): %s\n", len(reply), strconv.Quote(string(reply)))
	if tookDA1 > 0 {
		fmt.Printf("DA1 answered after %s\n", tookDA1.Round(time.Millisecond))
	} else {
		fmt.Printf("no DA1 reply within %s: the queries did not reach the terminal, or its replies did not come back\n", *timeout)
	}
	var bg, fg float64 = -1, -1
	for _, m := range reColor.FindAllStringSubmatch(string(reply), -1) {
		l := luminance(m[2], m[3], m[4])
		name := "background"
		if m[1] == "10" {
			name, fg = "foreground", l
		} else {
			bg = l
		}
		fmt.Printf("%s: rgb:%s/%s/%s  luminance %.2f\n", name, m[2], m[3], m[4], l)
	}
	switch {
	case bg >= 0:
		fmt.Println("verdict:", verdict(bg < 0.5), "(from the background)")
	case fg >= 0:
		fmt.Println("verdict:", verdict(fg >= 0.5), "(from the text color; no background reply)")
	default:
		fmt.Println("verdict: unknown - no color reply")
	}
	fmt.Println("lipgloss says:", verdict(lipgloss.HasDarkBackground()))
}

func verdict(dark bool) string {
	if dark {
		return "dark"
	}
	return "light"
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

// hexRGB formats a COLORREF-style 0x00BBGGRR value.
func hexRGB(c uint32) string {
	return fmt.Sprintf("#%02x%02x%02x", c&0xff, c>>8&0xff, c>>16&0xff)
}
