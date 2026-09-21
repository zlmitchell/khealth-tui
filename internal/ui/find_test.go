package ui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

func TestHighlightMatches(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	// a highlighted yaml line: the match spans the key color and the colon
	line := hlYAML("  replicaCount: 3 # two")
	out := highlightMatches(line, "count: 3", styleFindCur)
	if ansi.Strip(out) != "  replicaCount: 3 # two" {
		t.Errorf("text changed: %q", ansi.Strip(out))
	}
	if !strings.Contains(out, "Count: 3\x1b[0m") {
		t.Errorf("match should be one styled run: %q", out)
	}
	// case-insensitive, several matches, style re-opened after each
	out = highlightMatches(styleDim.Render("abcABCabc"), "abc", styleFind)
	if strings.Count(out, "abc\x1b[0m")+strings.Count(out, "ABC\x1b[0m") != 3 || ansi.Strip(out) != "abcABCabc" {
		t.Errorf("three matches expected: %q", out)
	}
	if highlightMatches("plain", "zzz", styleFind) != "plain" || highlightMatches("", "a", styleFind) != "" {
		t.Errorf("no-match lines must come back untouched")
	}
}

func TestTextFindKeysAndHits(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	lines := []string{"apiVersion: v1", "kind: Pod", "metadata:", "  name: web", "spec:", "  image: nginx", "  name: c"}
	var f textFind
	if c, _ := f.handleKey("x"); c {
		t.Fatal("keys are not consumed until / starts a query")
	}
	f = textFind{typing: true}
	for _, k := range []string{"n", "a", "m", "e"} {
		f.handleKey(k)
		f.run(lines, 0)
	}
	if f.query != "name" || len(f.hits) != 2 || f.hits[0] != 3 || f.hits[1] != 6 {
		t.Fatalf("typing name: %+v", f)
	}
	if h, _ := f.step(1); h != 6 {
		t.Errorf("n should go to line 6, got %d", h)
	}
	if h, _ := f.step(1); h != 3 {
		t.Errorf("n should wrap to line 3, got %d", h)
	}
	f.handleKey("backspace")
	f.run(lines, 0)
	if f.query != "nam" || len(f.hits) != 2 || f.hits[f.cur] != 3 {
		t.Errorf("backspace keeps the current hit when it still matches: %+v", f)
	}
	f.handleKey("enter")
	if f.typing || !f.active() || !strings.Contains(ansi.Strip(f.status()), "1/2") {
		t.Errorf("enter keeps the query: %+v %q", f, f.status())
	}
	if f.render("plain", 0) != "plain" || f.render(lines[3], 3) == lines[3] {
		t.Errorf("only hit lines get highlighted")
	}
	f.typing = true
	f.handleKey("esc")
	if f.active() || len(f.hits) != 0 {
		t.Errorf("esc while typing clears: %+v", f)
	}
	if jumpScroll(30, 12, 100) != 26 || jumpScroll(2, 12, 100) != 0 || jumpScroll(99, 12, 50) != 50 {
		t.Errorf("jumpScroll")
	}
}

// TestFindInDetailAndInspector: / in the detail overlay and in the
// inspector types a query, hits are highlighted and n/N scroll to them; esc
// clears the query before it closes the view.
func TestFindInDetailAndInspector(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	a := testApp()
	a.height = 20
	var raw []string
	for i := 0; i < 60; i++ {
		raw = append(raw, "line")
	}
	raw[40] = "needle here"
	raw[55] = "another NEEDLE"
	a.setDetail("t", raw)
	for _, k := range []string{"/", "n", "e", "e", "d"} {
		a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	}
	if !a.detailFind.typing || a.detailFind.query != "need" || len(a.detailFind.hits) != 2 || a.detailScroll == 0 {
		t.Fatalf("typing in the detail overlay: %+v scroll %d", a.detailFind, a.detailScroll)
	}
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "needle here") || !strings.Contains(v, "/need") || !strings.Contains(v, "2 hits") {
		t.Errorf("view should show the hit and the prompt:\n%s", v)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if h, _ := a.detailFind.current(); h != 55 || a.detailScroll < 40 {
		t.Errorf("n should move to line 55: hit %d scroll %d", h, a.detailScroll)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovDetail || a.detailFind.active() {
		t.Errorf("first esc clears the find, the view stays: %v %+v", a.overlay, a.detailFind)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovNone {
		t.Errorf("second esc closes")
	}

	// inspector: a level with a long YAML dump
	a.tab = tabWorkloads
	lvl := inspectLevel{title: "Deployment default/web"}
	for i := 0; i < 80; i++ {
		lvl.dump = append(lvl.dump, hlYAML("key: value"))
	}
	lvl.dump[70] = hlYAML("image: nginx:1.25")
	a.inspect = append(a.inspect, lvl)
	a.showInspect()
	if !a.inInspect() {
		t.Fatalf("expected the inspector sub-tab")
	}
	for _, k := range []string{"/", "n", "g", "i", "n", "x"} {
		a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	}
	if a.filterOn {
		t.Fatalf("/ in the inspector must not start the tab filter")
	}
	top := &a.inspect[len(a.inspect)-1]
	if a.inspectFind.query != "nginx" || len(a.inspectFind.hits) != 1 || top.scroll == 0 {
		t.Fatalf("inspector find: %+v scroll %d", a.inspectFind, top.scroll)
	}
	v = ansi.Strip(a.View())
	if !strings.Contains(v, "nginx:1.25") || !strings.Contains(v, "/nginx") {
		t.Errorf("inspector view should show the hit:\n%s", v)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter}) // keeps the query, does not drill down while typing
	if a.inspectFind.typing || len(a.inspect) != 1 {
		t.Errorf("enter ends typing: %+v levels %d", a.inspectFind, len(a.inspect))
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.inspectFind.active() || len(a.inspect) != 1 {
		t.Errorf("esc clears the find first: %+v levels %d", a.inspectFind, len(a.inspect))
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if len(a.inspect) != 0 {
		t.Errorf("second esc leaves the inspector")
	}
}

// TestFindInPodLogs: / in the log tailer finds as you type, n/N jump, &
// narrows the view to the hits, lines that arrive later join the hits, and
// esc clears before it closes the viewer.
func TestFindInPodLogs(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(prev)
	a := testApp()
	a.width, a.height = 120, 24
	var lines []string
	for i := 0; i < 60; i++ {
		msg := "steady"
		if i == 10 || i == 45 {
			msg = "connection refused"
		}
		lines = append(lines, fmt.Sprintf("2024-09-18T10:00:%02dZ level=info msg=%q n=%d", i%60, msg, i))
	}
	lv := &logView{ns: "default", pod: "p", containers: []string{"c"}, lines: lines}
	a.logs = lv
	a.overlay = ovPodLogs
	key := func(k string) { a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}) }
	for _, k := range []string{"/", "r", "e", "f", "u", "s"} {
		key(k)
	}
	if lv.find.query != "refus" || len(lv.find.hits) != 2 || lv.find.hits[0] != 10 || lv.scroll == 0 {
		t.Fatalf("typing in the tailer: %+v scroll %d", lv.find, lv.scroll)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	key("n")
	if h, _ := lv.find.current(); h != 45 || lv.scroll < 30 {
		t.Errorf("n should jump to line 45: hit %d scroll %d", h, lv.scroll)
	}
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "connection refused") || !strings.Contains(v, "/refus") || !strings.Contains(v, "2/2") {
		t.Errorf("view should show the hit and the status:\n%s", v)
	}
	// a new chunk with a hit joins the hits without a rescan of the old ones
	lv.lines = append(lv.lines, "2024-09-18T10:01:00Z level=error msg=\"refused again\"")
	a.logVisibleLines()
	if len(lv.find.hits) != 3 || lv.find.hits[2] != 60 || lv.find.scanned != 61 {
		t.Errorf("streamed line should join the hits: %+v", lv.find)
	}
	// & narrows to the hits, indices re-computed on the narrowed view
	key("&")
	if !lv.only || lv.filter != "refus" || len(a.logVisibleLines()) != 3 || len(lv.find.hits) != 3 || lv.find.hits[0] != 0 {
		t.Errorf("& should show only the 3 matching lines: only=%v filter=%q vis=%d hits=%v", lv.only, lv.filter, len(a.logVisibleLines()), lv.find.hits)
	}
	if v := ansi.Strip(a.View()); !strings.Contains(v, "only matching lines") || strings.Contains(v, "steady") {
		t.Errorf("narrowed view:\n%s", v)
	}
	key("&")
	if lv.only || lv.filter != "" || len(a.logVisibleLines()) != 61 {
		t.Errorf("& again shows everything: only=%v filter=%q vis=%d", lv.only, lv.filter, len(a.logVisibleLines()))
	}
	key("G")
	if v := ansi.Strip(a.View()); !strings.Contains(v, "refused again") || !strings.Contains(v, "of 61 --") {
		t.Errorf("at the end the newest line and the status line must be on screen: %s", v)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovPodLogs || lv.find.active() {
		t.Errorf("first esc clears the find: overlay %v %+v", a.overlay, lv.find)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovNone {
		t.Errorf("second esc closes the viewer")
	}
}

// TestFindAcceptsDigits: digits (and - =) are tab-switch keys elsewhere; in
// a find query they are text, in every view that has a find.
func TestFindAcceptsDigits(t *testing.T) {
	a := testApp()
	a.setDetail("t", []string{"port 8443", "x"})
	for _, k := range []string{"/", "8", "4", "4", "3"} {
		a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	}
	if a.detailFind.query != "8443" || a.overlay != ovDetail {
		t.Errorf("detail find: query %q overlay %v status %q", a.detailFind.query, a.overlay, a.status)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})

	a.tab = tabWorkloads
	a.inspect = append(a.inspect, inspectLevel{title: "Pod default/p", dump: []string{"containerPort: 8443"}})
	a.showInspect()
	for _, k := range []string{"/", "8", "4", "-", "1", "="} {
		a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	}
	if a.inspectFind.query != "84-1=" || a.tab != tabWorkloads || !a.inInspect() {
		t.Errorf("inspector find: query %q tab %v", a.inspectFind.query, a.tab)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	a.handleKey(tea.KeyMsg{Type: tea.KeyEsc})

	a.logs = &logView{ns: "default", pod: "p", containers: []string{"c"}, lines: []string{"2024-09-18T10:00:00Z status 403"}}
	a.overlay = ovPodLogs
	for _, k := range []string{"/", "4", "0", "3"} {
		a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
	}
	if a.logs.find.query != "403" || len(a.logs.find.hits) != 1 {
		t.Errorf("log find: %+v", a.logs.find)
	}
}
