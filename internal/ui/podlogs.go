package ui

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

const logBufferLines = 5000

func ansiWidth(s string) int { return ansi.StringWidth(s) }

// logView is the streaming pod log viewer state.
type logView struct {
	ns, pod    string
	pods       []string // sibling pods of the same controller (cycle with { })
	podIdx     int
	containers []string
	idx        int
	previous   bool
	follow     bool
	wrap       bool
	tsMode     int      // 0 short HH:MM:SS, 1 hidden, 2 full RFC3339
	plain      bool     // no syntax highlighting
	filter     string   // only lines containing this are rendered (& with a find query)
	find       textFind // / find; n/N jump; & narrows the view to the hits
	only       bool
	lines      []string
	scroll     int
	err        string
	streaming  bool
	seq        int
	cancel     context.CancelFunc
	rendered   logRender // display cache, see logVisibleLines
	ch         chan logChunk
}

type logChunk struct {
	lines []string
	err   error
	done  bool
}

type logMsg struct {
	seq   int
	chunk logChunk
}

// openPodLogs starts the viewer for a pod (optionally with sibling pods).
func (a *App) openPodLogs(ns, pod string, siblings []string) tea.Cmd {
	a.closePodLogs()
	var p *corev1.Pod
	for i := range a.snap.Pods {
		if a.snap.Pods[i].Namespace == ns && a.snap.Pods[i].Name == pod {
			p = &a.snap.Pods[i]
		}
	}
	if p == nil {
		a.setStatus("pod not found in the snapshot: " + ns + "/" + pod)
		return nil
	}
	lv := &logView{ns: ns, pod: pod, pods: siblings, follow: true, wrap: false}
	for i, s := range siblings {
		if s == pod {
			lv.podIdx = i
		}
	}
	for _, c := range p.Spec.InitContainers {
		lv.containers = append(lv.containers, c.Name)
	}
	for _, c := range p.Spec.Containers {
		lv.containers = append(lv.containers, c.Name)
	}
	// start on the first regular (non-init) container
	lv.idx = len(p.Spec.InitContainers)
	if lv.idx >= len(lv.containers) {
		lv.idx = 0
	}
	a.logs = lv
	a.overlay = ovPodLogs
	return a.startLogStream()
}

func (a *App) closePodLogs() {
	if a.logs != nil && a.logs.cancel != nil {
		a.logs.cancel()
	}
	a.logs = nil
}

// startLogStream (re)opens the log stream for the current container.
func (a *App) startLogStream() tea.Cmd {
	lv := a.logs
	if lv == nil || len(lv.containers) == 0 {
		return nil
	}
	if lv.cancel != nil {
		lv.cancel()
	}
	lv.lines = nil
	lv.scroll = 0
	lv.err = ""
	lv.seq++
	seq := lv.seq
	ctx, cancel := context.WithCancel(context.Background())
	lv.cancel = cancel
	ch := make(chan logChunk, 64)
	lv.ch = ch
	lv.streaming = true
	container := lv.containers[lv.idx]
	tail := int64(500)
	opts := &corev1.PodLogOptions{Container: container, TailLines: &tail, Follow: lv.follow, Previous: lv.previous, Timestamps: true}
	req := a.client.CS.CoreV1().Pods(lv.ns).GetLogs(lv.pod, opts)
	go func() {
		rc, err := req.Stream(ctx)
		if err != nil {
			ch <- logChunk{err: err, done: true}
			return
		}
		defer rc.Close()
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		batch := make([]string, 0, 64)
		flush := func() {
			if len(batch) > 0 {
				ch <- logChunk{lines: batch}
				batch = make([]string, 0, 64)
			}
		}
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		lines := make(chan string, 256)
		go func() {
			for sc.Scan() {
				lines <- sc.Text()
			}
			close(lines)
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case l, ok := <-lines:
				if !ok {
					flush()
					ch <- logChunk{done: true, err: sc.Err()}
					return
				}
				batch = append(batch, l)
				if len(batch) >= 64 {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()
	return waitLogs(ch, seq)
}

func waitLogs(ch chan logChunk, seq int) tea.Cmd {
	return func() tea.Msg {
		c, ok := <-ch
		if !ok {
			return nil
		}
		return logMsg{seq: seq, chunk: c}
	}
}

func (a *App) handleLogMsg(m logMsg) tea.Cmd {
	lv := a.logs
	if lv == nil || m.seq != lv.seq {
		return nil
	}
	atEnd := lv.scroll >= a.logMaxScroll()-1
	if len(m.chunk.lines) > 0 {
		lv.lines = append(lv.lines, m.chunk.lines...)
		if len(lv.lines) > logBufferLines {
			lv.lines = lv.lines[len(lv.lines)-logBufferLines:]
		}
		if lv.follow && atEnd {
			lv.scroll = a.logMaxScroll()
		}
	}
	if m.chunk.err != nil {
		lv.err = m.chunk.err.Error()
	}
	if m.chunk.done {
		lv.streaming = false
		return nil
	}
	return waitLogs(lv.ch, lv.seq)
}

// logVisibleLines is the buffer rendered for display: filtered, with the
// timestamp mode, highlighting and wrap applied. Rendering is cached on
// the viewer and extended incrementally as chunks arrive: the stream
// appends, and View runs on every spinner tick, so re-highlighting 5,000
// lines per frame is what made the viewer lag on a busy pod. A change of
// filter, timestamps, highlighting, wrap or width re-renders from scratch.
func (a *App) logVisibleLines() []string {
	lv := a.logs
	if lv == nil {
		return nil
	}
	key := fmt.Sprintf("%s|%d|%v|%v|%d", lv.filter, lv.tsMode, lv.plain, lv.wrap, a.width)
	rc := &lv.rendered
	if rc.key != key || rc.n > len(lv.lines) || (rc.n > 0 && rc.first != lv.lines[0]) {
		// settings changed, or the buffer was trimmed at the head
		rc.key, rc.n, rc.out = key, 0, nil
		lv.find.hits, lv.find.scanned = nil, 0
	}
	for _, l := range lv.lines[rc.n:] {
		rc.out = append(rc.out, a.renderPodLogLine(lv, l)...)
	}
	rc.n = len(lv.lines)
	if rc.n > 0 {
		rc.first = lv.lines[0]
	}
	lv.find.extend(rc.out) // new lines of the stream join the hits
	return rc.out
}

// renderPodLogLine renders one streamed line: nothing when the filter
// drops it, one line, or several when wrapping.
func (a *App) renderPodLogLine(lv *logView, l string) []string {
	if f := strings.ToLower(lv.filter); f != "" && !strings.Contains(strings.ToLower(l), f) {
		return nil
	}
	w := a.width - 6
	t, rest, hasTS := splitTimestamp(l)
	prefix := ""
	if hasTS {
		switch lv.tsMode {
		case 0:
			prefix = styleDim.Render(t.Local().Format("15:04:05")) + " "
		case 2:
			prefix = styleDim.Render(l[:len(l)-len(rest)-1]) + " "
		}
	}
	hl := func(frag string) string {
		if lv.plain {
			return frag
		}
		return highlightLog(frag)
	}
	if !lv.wrap {
		return []string{prefix + hl(rest)}
	}
	// color the whole line (so JSON/logfmt detection sees it intact),
	// then wrap with an escape-sequence-aware wrapper
	indent := strings.Repeat(" ", ansiWidth(prefix))
	width := w - ansiWidth(prefix)
	if width < 20 {
		width = 20
	}
	frags := wrapStyled(hl(rest), width)
	out := make([]string, 0, len(frags))
	for i, fr := range frags {
		if i == 0 {
			out = append(out, prefix+fr)
		} else {
			out = append(out, indent+fr)
		}
	}
	return out
}

// wrapStyled wraps a colored line and carries the open SGR style over the
// break: ansi.Wrap keeps escape codes in place, but a color opened on one
// fragment would otherwise stop at the newline and not resume on the next.
func wrapStyled(s string, width int) []string {
	frags := strings.Split(ansi.Wrap(s, width, ""), "\n")
	open := ""
	for i, fr := range frags {
		if open != "" {
			fr = open + fr
		}
		for _, m := range reSGR.FindAllString(fr, -1) {
			if m == "\x1b[0m" || m == "\x1b[m" {
				open = ""
			} else {
				open = m
			}
		}
		if open != "" {
			fr += "\x1b[0m"
		}
		frags[i] = fr
	}
	return frags
}

var reSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// logPageLines is how many log lines fit in the overlay: the box (title
// and border) plus the viewer's own header and status lines come off the
// body height.
func (a *App) logPageLines() int {
	n := a.bodyHeight() + 1 - 7
	if lv := a.logs; lv != nil && lv.err != "" {
		n--
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (a *App) logMaxScroll() int {
	n := len(a.logVisibleLines()) - a.logPageLines()
	if n < 0 {
		return 0
	}
	return n
}

func (a *App) handleLogKey(key string) (tea.Model, tea.Cmd) {
	lv := a.logs
	if lv == nil {
		a.overlay = ovNone
		return a, nil
	}
	visible := a.logPageLines()
	page := visible - 2
	if page < 1 {
		page = 1
	}
	jump := func(h int) { lv.scroll = jumpScroll(h, visible, a.logMaxScroll()) }
	if consumed, changed := lv.find.handleKey(key); consumed {
		if changed {
			a.logFindChanged()
			if h, ok := lv.find.current(); ok {
				jump(h)
			}
		}
		return a, nil
	}
	switch key {
	case "/":
		lv.find = textFind{typing: true}
		a.logFindChanged()
		return a, nil
	case "n", "N":
		d := 1
		if key == "N" {
			d = -1
		}
		if h, ok := lv.find.step(d); ok {
			jump(h)
		} else if lv.find.query == "" {
			a.setStatus("/ finds text in the log first; n/N then jump between the hits, & shows only the hits")
		}
		return a, nil
	case "&":
		lv.only = !lv.only
		a.logFindChanged()
		if lv.only && lv.find.query == "" {
			a.setStatus("& shows only the lines a / find matches: type a query first")
		}
		lv.scroll = a.logMaxScroll()
	case "esc", "q":
		if key == "esc" && lv.find.active() {
			lv.find.clear()
			lv.only = false
			a.logFindChanged()
			return a, nil
		}
		a.closePodLogs()
		a.overlay = ovNone
	case "]", "c", "tab":
		if len(lv.containers) > 1 {
			lv.idx = (lv.idx + 1) % len(lv.containers)
			return a, a.startLogStream()
		}
	case "[", "shift+tab":
		if len(lv.containers) > 1 {
			lv.idx = (lv.idx + len(lv.containers) - 1) % len(lv.containers)
			return a, a.startLogStream()
		}
	case "}":
		if len(lv.pods) > 1 {
			next := lv.pods[(lv.podIdx+1)%len(lv.pods)]
			return a, a.openPodLogs(lv.ns, next, lv.pods)
		}
	case "{":
		if len(lv.pods) > 1 {
			prev := lv.pods[(lv.podIdx+len(lv.pods)-1)%len(lv.pods)]
			return a, a.openPodLogs(lv.ns, prev, lv.pods)
		}
	case "p":
		lv.previous = !lv.previous
		return a, a.startLogStream()
	case "f":
		lv.follow = !lv.follow
		if lv.follow {
			lv.scroll = a.logMaxScroll()
		}
		return a, a.startLogStream()
	case "w":
		lv.wrap = !lv.wrap
		lv.scroll = a.logMaxScroll()
	case "T":
		lv.tsMode = (lv.tsMode + 1) % 3
	case "H":
		lv.plain = !lv.plain
	case "r":
		return a, a.startLogStream()
	case "j", "down":
		lv.scroll++
	case "k", "up":
		lv.scroll--
	case "pgdown", " ", "ctrl+d", "J":
		lv.scroll += page
	case "pgup", "ctrl+u", "K":
		lv.scroll -= page
	case "g", "home":
		lv.scroll = 0
	case "G", "end":
		lv.scroll = a.logMaxScroll()
	}
	if lv.scroll > a.logMaxScroll() {
		lv.scroll = a.logMaxScroll()
	}
	if lv.scroll < 0 {
		lv.scroll = 0
	}
	return a, nil
}

// logFindChanged applies the find query to the view: with & on, only the
// matching lines are rendered (the render cache re-keys on lv.filter),
// then the hits are recomputed over what is displayed.
func (a *App) logFindChanged() {
	lv := a.logs
	if lv == nil {
		return
	}
	lv.filter = ""
	if lv.only {
		lv.filter = lv.find.query
	}
	vis := a.logVisibleLines()
	lv.find.run(vis, lv.scroll)
}

// renderPodLogs draws the log viewer overlay.
func (a *App) renderPodLogs() (string, []string) {
	lv := a.logs
	if lv == nil {
		return "", nil
	}
	title := fmt.Sprintf("Logs %s/%s", lv.ns, lv.pod)
	var ctrs []string
	for i, c := range lv.containers {
		if i == lv.idx {
			ctrs = append(ctrs, styleTabOn.Render(c))
		} else {
			ctrs = append(ctrs, styleDim.Render(c))
		}
	}
	mode := []string{}
	if lv.previous {
		mode = append(mode, styleWarn.Render("previous (last terminated instance)"))
	}
	if lv.follow && lv.streaming {
		mode = append(mode, styleOK.Render(a.spinner.View()+" following"))
	} else if lv.streaming {
		mode = append(mode, styleDim.Render("loading"))
	} else {
		mode = append(mode, styleDim.Render("stream ended"))
	}
	if lv.wrap {
		mode = append(mode, styleDim.Render("wrap"))
	}
	lines := []string{
		kv("containers", strings.Join(ctrs, " ")) + "   " + strings.Join(mode, "  "),
		styleDim.Render("[ ] or tab switch container · { } next/prev pod of the same controller · p previous · f follow · w wrap · T timestamps (short/off/full) · H highlighting on/off · r reload · / find, n/N next/prev, & only hits · j/k G g scroll · esc close"),
	}
	if len(lv.pods) > 1 {
		lines[0] += "   " + kv("pod", fmt.Sprintf("%d/%d", lv.podIdx+1, len(lv.pods)))
	}
	lines = append(lines, "")
	if lv.err != "" {
		lines = append(lines, styleCrit.Render(lv.err))
	}
	vis := a.logVisibleLines()
	visible := a.logPageLines()
	end := lv.scroll + visible
	if end > len(vis) {
		end = len(vis)
	}
	if lv.scroll > end {
		lv.scroll = end
	}
	for i := lv.scroll; i < end; i++ {
		lines = append(lines, lv.find.render(vis[i], i))
	}
	if len(vis) == 0 && lv.err == "" && !lv.streaming {
		lines = append(lines, styleDim.Render("(no output)"))
	}
	status := styleDim.Render(fmt.Sprintf("-- lines %d-%d of %d --", lv.scroll+1, end, len(vis)))
	if lv.only && lv.find.query != "" {
		status += "  " + styleWarn.Render("only matching lines (& shows all)")
	}
	if f := lv.find.status(); f != "" {
		status += "  " + f
	}
	lines = append(lines, status)
	return title, lines
}

// podForLogs resolves the selected Inspect row to a pod and its siblings.
func (a *App) podForLogs() (ns, pod string, siblings []string, ok bool) {
	if a.inInspect() && len(a.inspect) > 0 {
		top := a.inspect[len(a.inspect)-1]
		// "Pod ns/name" title from levelFromObject
		if strings.HasPrefix(top.title, "Pod ") {
			ns, name, found := strings.Cut(strings.TrimPrefix(top.title, "Pod "), "/")
			if found {
				return ns, name, nil, true
			}
		}
		if top.cursor < len(top.refs) && top.refs[top.cursor].Kind == "Pod" {
			r := top.refs[top.cursor]
			return r.Namespace, r.Name, nil, true
		}
		return "", "", nil, false
	}
	kind, ns, name, parsed := parseWLID(a.selectedID())
	if !parsed {
		return "", "", nil, false
	}
	if kind == "Pod" {
		return ns, name, nil, true
	}
	_, _, selector, found := a.workloadObject(a.selectedID())
	if !found || selector == nil {
		return "", "", nil, false
	}
	var pods []string
	for _, p := range podsMatching(a.snap, ns, selector) {
		if p.Status.Phase == corev1.PodRunning || p.Status.Phase == corev1.PodPending {
			pods = append(pods, p.Name)
		}
	}
	if len(pods) == 0 {
		return "", "", nil, false
	}
	return ns, pods[0], pods, true
}

var _ = k8s.PodStatus

// logRender is the viewer's rendered buffer: the lines of lv.lines[:n]
// under the settings in key, first being lv.lines[0] when it was rendered
// (a trimmed buffer starts elsewhere and is re-rendered).
type logRender struct {
	key   string
	n     int
	first string
	out   []string
}
