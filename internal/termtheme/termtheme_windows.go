package termtheme

import (
	"os"
	"time"

	"github.com/muesli/cancelreader"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

// Dark reports whether the terminal background is dark. termenv never asks
// on Windows and always answers dark, so the terminal is asked here:
// Windows Terminal and VS Code answer through ConPTY within a few ms. The
// console color table and the Windows app theme are no help - the first
// holds ConPTY's defaults, not the terminal's scheme, the second is a
// separate setting. No answer means dark. Call it before bubbletea reads
// stdin.
func Dark() bool {
	if dark, ok := query(300 * time.Millisecond); ok {
		return dark
	}
	return true
}

func query(timeout time.Duration) (dark, ok bool) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return false, false
	}
	out := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(out, &mode) != nil || windows.SetConsoleMode(out, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		return false, false
	}
	defer windows.SetConsoleMode(out, mode)
	// the reader bubbletea uses: it switches the input to VT (so the replies
	// arrive as bytes) and can interrupt a read, restoring the mode on Close
	r, err := cancelreader.NewReader(os.Stdin)
	if err != nil {
		return false, false
	}
	if _, err := os.Stdout.WriteString(queries); err != nil {
		r.Close()
		return false, false
	}
	// The reader stops by itself after DA1, so no read is left pending to
	// swallow the first key meant for the TUI.
	done := make(chan []byte, 1)
	go func() {
		var reply []byte
		buf := make([]byte, 256)
		for !reDA1.Match(reply) {
			n, err := r.Read(buf)
			reply = append(reply, buf[:n]...)
			if err != nil {
				break
			}
		}
		done <- reply
	}()
	select {
	case reply := <-done:
		r.Close()
		return parseReply(reply)
	case <-time.After(timeout):
		// a read Cancel cannot interrupt is left to finish on its own;
		// closing the handle under it would be worse than the lost key
		if r.Cancel() {
			<-done
			r.Close()
		}
		return false, false
	}
}
