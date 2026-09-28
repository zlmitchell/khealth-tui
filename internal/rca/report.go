package rca

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/logs"
)

// Group is a run of timeline entries with the same node, unit, pattern and
// message shape, collapsed for reading.
type Group struct {
	First, Last time.Time
	Count       int
	Entry       Entry // the first one
}

// Collapse keeps the entries worth reading - warnings, errors, start and
// up markers - and folds repeats of the same message on the same node and
// unit into one line.
func Collapse(es []Entry) []Group {
	idx := map[string]int{}
	var out []Group
	for _, e := range es {
		if e.Class < logs.ClassWarn && e.Pattern != "rke2-start" && e.Pattern != "rke2-up" && e.Pattern != "kubelet-started" {
			continue
		}
		k := e.Node + "\x00" + e.Unit + "\x00" + e.Pattern + "\x00" + logs.Signature(e.Text)
		if i, ok := idx[k]; ok {
			out[i].Count++
			out[i].Last = e.Time
			continue
		}
		idx[k] = len(out)
		out = append(out, Group{First: e.Time, Last: e.Time, Count: 1, Entry: e})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].First.Before(out[j].First) })
	return out
}

// WriteReport prints the hypotheses and the collapsed timeline (the last
// maxGroups groups).
func WriteReport(w io.Writer, hs []Hypothesis, tl *Timeline, maxGroups int) {
	fmt.Fprintf(w, "%s (%d log lines read, %d timeline entries)\n", paint(cBold, "Root-cause analysis"), tl.Lines, len(tl.Entries))
	for node, fix := range tl.ClockFix {
		fmt.Fprintf(w, "  %s %s runs %s off; its log times are corrected for it\n", paint(cYellow, "clock:"), node, fix.Round(time.Second))
	}
	if len(hs) == 0 {
		fmt.Fprintln(w, "\nNo known failure pattern in the bundle. The findings below and the timeline are what there is to go on.")
	}
	for i, h := range hs {
		fmt.Fprintf(w, "\n%d. %s %s\n", i+1, paint(confColor(h.Confidence()), "["+h.Confidence()+"]"), paint(cBold, h.Title))
		fmt.Fprintf(w, "   %s    %s\n", paint(cCyan, "cause:"), clean(h.Cause))
		for _, e := range h.Effects {
			fmt.Fprintf(w, "   %s     %s\n", paint(cCyan, "then:"), clean(e))
		}
		for j, e := range h.Evidence {
			label := paint(cCyan, "evidence:")
			if j > 0 {
				label = "         "
			}
			fmt.Fprintf(w, "   %s %s  %s\n", label, stamp(e.Time), paint(classColor(e.Class), clip(oneLine(e.Text), 140)))
			fmt.Fprintf(w, "             %s  %s\n", "", paint(cDim, "("+where1(e)+")"))
		}
		for _, n := range h.Next {
			fmt.Fprintf(w, "   %s     %s\n", paint(cCyan, "next:"), clean(n))
		}
	}
	groups := Collapse(tl.Entries)
	if len(groups) == 0 {
		return
	}
	skipped := 0
	if maxGroups > 0 && len(groups) > maxGroups {
		skipped = len(groups) - maxGroups
		groups = groups[skipped:]
	}
	fmt.Fprintf(w, "\n%s (warnings, errors, restarts; repeats folded", paint(cBold, "Timeline"))
	if skipped > 0 {
		fmt.Fprintf(w, "; %d earlier groups left out, --timeline FILE writes everything", skipped)
	}
	fmt.Fprintln(w, ")")
	for _, g := range groups {
		when := stamp(g.First)
		if g.Count > 1 {
			when += " .. " + g.Last.Local().Format("15:04:05") + fmt.Sprintf(" x%d", g.Count)
		}
		who := g.Entry.Node
		if who == "" {
			who = "cluster"
		}
		// pad before painting: the escape codes would count as width
		fmt.Fprintf(w, "  %-34s %s %-14s %-22s %-32s %s\n", when, paint(classColor(g.Entry.Class), fmt.Sprintf("%-5s", g.Entry.Class)), clip(who, 14), clip(g.Entry.Pattern, 22), clip(g.Entry.Unit, 32), clip(oneLine(g.Entry.Text), 90))
	}
}

// WriteTimeline writes every entry: JSON lines when jsonl, else one text
// line per entry with its bundle reference.
func WriteTimeline(w io.Writer, tl *Timeline, jsonl bool) error {
	enc := json.NewEncoder(w)
	for _, e := range tl.Entries {
		if jsonl {
			if err := enc.Encode(e); err != nil {
				return err
			}
			continue
		}
		node := e.Node
		if node == "" {
			node = "cluster"
		}
		if _, err := fmt.Fprintf(w, "%s  %-7s %-5s %-14s %-24s %-22s %s  [%s]\n", e.Time.UTC().Format("2006-01-02T15:04:05.000Z"), e.Kind, e.Class, node, clip(e.Unit, 24), e.Pattern, oneLine(e.Text), e.Ref); err != nil {
			return err
		}
	}
	return nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "--"
	}
	return t.Local().Format("Jan 02 15:04:05")
}

func where1(e Entry) string {
	s := e.Ref.String()
	if e.Node != "" && !strings.Contains(s, "nodes/") {
		s = e.Node + ", " + s
	}
	return s
}

func oneLine(s string) string { return strings.Join(strings.Fields(clean(s)), " ") }

// escapes are the terminal control sequences log lines carry (colored app
// logs): printed raw they would recolor or garble the report.
var escapes = regexp.MustCompile(`\x1b(\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|[@-Z\\-_])`)

// clean drops the escape sequences and other control characters (tabs and
// newlines stay) from text a log supplied.
func clean(s string) string {
	s = escapes.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' && r != '\n' || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
