package rca

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// Restart is one restart of a node, told in phases: what asked for it, the
// old boot's last sign of life, the boot, and the node coming back until
// its pods were Ready again. Its span (Start to End) is the window in
// which the node's restarts, NotReady and scheduling failures are the
// restart's effects rather than causes of their own.
type Restart struct {
	Node string `json:"node"`
	How  string `json:"how"` // reboot | runtime (containers lost, no new boot) | unknown (no boot time to tell)
	// Requested is when something asked the node to stop, By what.
	Requested time.Time `json:"requested,omitzero"`
	By        string    `json:"by,omitempty"`
	// Clean: the old boot logged the last steps of its shutdown.
	Clean bool `json:"clean"`
	// LastLine is the old boot's last log line: where it went silent.
	LastLine time.Time `json:"last_line,omitzero"`
	LastText string    `json:"last_text,omitempty"`
	Boot     time.Time `json:"boot"`
	Up       time.Time `json:"up,omitzero"`       // rke2/k3s up and running
	Ready    time.Time `json:"ready,omitzero"`    // the node Ready again
	Settled  time.Time `json:"settled,omitzero"`  // the last pod that lived through it Ready again
	Waiting  []string  `json:"waiting,omitempty"` // pods not Ready again
	Lost     []string  `json:"lost,omitempty"`    // ns/pod/container it ended (Unknown, exit 255)
	Evidence []Entry   `json:"evidence,omitempty"`
}

// settleCap: a pod that turned Ready later than this after the boot did so
// for another reason (a rollout, a probe that flapped since).
const settleCap = time.Hour

// Start is where the restart began: the request, else the old boot's last
// line, else just before the boot.
func (r Restart) Start() time.Time {
	switch {
	case !r.Requested.IsZero():
		return r.Requested
	case !r.LastLine.IsZero():
		return r.LastLine
	}
	return r.Boot.Add(-2 * time.Minute)
}

// End is where the node had settled: its pods Ready again, else the
// bootstrap window after the boot (or the node's Ready, if later).
func (r Restart) End() time.Time {
	if !r.Settled.IsZero() {
		return r.Settled
	}
	end := r.Boot.Add(bootstrapWindow)
	if r.Ready.After(end) {
		end = r.Ready
	}
	return end
}

// Covers: t falls inside the restart.
func (r Restart) Covers(t time.Time) bool { return !t.Before(r.Start()) && !t.After(r.End()) }

// Hung: a shutdown was asked for, never finished, and the node stayed
// silent for minutes before it booted - a hang ended by a reset, or a
// machine left powered off.
func (r Restart) Hung() bool {
	if r.Requested.IsZero() || r.Clean || r.How != "reboot" {
		return false
	}
	silent := r.Requested
	if r.LastLine.After(silent) {
		silent = r.LastLine
	}
	return r.Boot.Sub(silent) > 5*time.Minute
}

// Headline says what kind of restart it was.
func (r Restart) Headline() string {
	switch {
	case r.How == "runtime":
		return "its containers all stopped without the node rebooting (rke2-killall.sh, or the container runtime restarted with its shims)"
	case r.How == "unknown":
		return "its containers all stopped at once (a reboot or a container runtime restart; no boot time to tell which)"
	case r.Hung():
		return fmt.Sprintf("%s asked for it at %s; the shutdown hung - nothing logged for %s until the boot",
			r.By, clock(r.Requested), strutil.HumanDur(r.Boot.Sub(latest(r.Requested, r.LastLine))))
	case !r.Requested.IsZero():
		return fmt.Sprintf("planned: %s asked for it at %s, down for %s", r.By, clock(r.Requested), strutil.HumanDur(r.Boot.Sub(r.Requested)))
	case !r.LastLine.IsZero():
		return fmt.Sprintf("unplanned: nothing asked for a shutdown - the old boot's last line is at %s, %s before the boot: a crash, a hard reset or power loss",
			clock(r.LastLine), strutil.HumanDur(r.Boot.Sub(r.LastLine)))
	}
	return "no record of how the old boot ended"
}

// Phases lists the restart's moments with the time each took from the boot.
func (r Restart) Phases() []string {
	var ps []string
	since := func(t time.Time) string {
		if d := t.Sub(r.Boot); d >= 0 {
			return " (+" + strutil.HumanDur(d) + ")"
		}
		return ""
	}
	if !r.Requested.IsZero() {
		ps = append(ps, "requested "+clock(r.Requested)+" by "+r.By)
	}
	if !r.LastLine.IsZero() {
		how := ", the shutdown never finished"
		if r.Clean {
			how = ", after a clean shutdown"
		}
		ps = append(ps, "last line "+clock(r.LastLine)+how+": "+clip(r.LastText, 120))
	}
	if r.How == "reboot" {
		ps = append(ps, "booted "+clock(r.Boot))
	}
	if !r.Up.IsZero() {
		ps = append(ps, "rke2/k3s up "+clock(r.Up)+since(r.Up))
	}
	if !r.Ready.IsZero() {
		ps = append(ps, "node Ready "+clock(r.Ready)+since(r.Ready))
	}
	if !r.Settled.IsZero() {
		p := "settled " + clock(r.Settled) + since(r.Settled) + ": the pods that lived through it Ready again"
		if !r.Requested.IsZero() {
			p += ", " + strutil.HumanDur(r.Settled.Sub(r.Requested)) + " after the request"
		}
		ps = append(ps, p)
	}
	if len(r.Waiting) > 0 {
		ps = append(ps, fmt.Sprintf("%d pod(s) never Ready again: %s", len(r.Waiting), strutil.TruncList(r.Waiting, 4)))
	}
	return ps
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Restarts finds every node restart the bundle shows: boots (the kernel's
// first line, the probe's uptime) and moments a node's containers all
// ended together, with the phases around each.
func Restarts(tl *Timeline, snap *k8s.Snapshot) []Restart {
	marks := map[string][]Entry{}
	var earliest time.Time
	for _, e := range tl.Entries {
		if earliest.IsZero() || (!e.Time.IsZero() && e.Time.Before(earliest)) {
			earliest = e.Time
		}
		switch e.Pattern {
		case "kernel-boot", "boot-last-line", "shutdown-requested", "shutdown-clean", "rke2-up", "NodeReady":
			if e.Node != "" {
				marks[e.Node] = append(marks[e.Node], e)
			}
		}
	}
	born, _ := nodeBirths(snap)
	boots := map[string][]time.Time{}
	addBoot := func(node string, t time.Time) {
		if b, ok := born[node]; ok && t.Before(b) {
			return // the node's first boot, before it joined: not a restart
		}
		for _, b := range boots[node] {
			if absDur(b.Sub(t)) < 3*time.Minute {
				return
			}
		}
		boots[node] = append(boots[node], t)
	}
	for node, es := range marks {
		for _, e := range es {
			if e.Pattern == "kernel-boot" {
				addBoot(node, e.Time)
			}
		}
	}
	for node, t := range tl.Boots {
		if !earliest.IsZero() && !t.Before(earliest) {
			addBoot(node, t)
		}
	}
	var out []Restart
	for node, bs := range boots {
		sort.Slice(bs, func(i, j int) bool { return bs[i].Before(bs[j]) })
		for i, b := range bs {
			var prev time.Time
			if i > 0 {
				prev = bs[i-1]
			}
			r := Restart{Node: node, How: "reboot", Boot: b}
			r.phases(marks[node], prev)
			if i == len(bs)-1 {
				r.settle(snap)
			}
			out = append(out, r)
		}
	}
	// containers lost together: the restart of their node's boot, or one of
	// their own when no boot explains them
	for _, ep := range lostEpisodes(snap) {
		found := false
		for i := range out {
			if r := &out[i]; r.Node == ep.node && !ep.at.Before(r.Boot.Add(-2*time.Minute)) && ep.at.Before(r.Boot.Add(bootstrapWindow)) {
				r.Lost = append(r.Lost, ep.units...)
				found = true
				break
			}
		}
		if !found {
			how := "unknown"
			if _, ok := tl.Boots[ep.node]; ok {
				how = "runtime" // the probe saw the boot, and it is not this
			}
			r := Restart{Node: ep.node, How: how, Boot: ep.at, Lost: ep.units}
			r.settle(snap)
			out = append(out, r)
		}
	}
	for i := range out {
		out[i].evidence(tl)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Boot.Equal(out[j].Boot) {
			return out[i].Boot.Before(out[j].Boot)
		}
		return out[i].Node < out[j].Node
	})
	return out
}

// phases reads the request, the old boot's end and rke2's start from the
// node's marks between the previous boot and this one.
func (r *Restart) phases(marks []Entry, prev time.Time) {
	var reqs []Entry
	for _, e := range marks {
		inOld := e.Time.After(prev) && !e.Time.After(r.Boot)
		switch {
		case e.Pattern == "shutdown-requested" && inOld:
			reqs = append(reqs, e)
		case e.Pattern == "boot-last-line" && inOld && e.Time.After(r.LastLine):
			r.LastLine, r.LastText = e.Time, e.Text
		case e.Pattern == "rke2-up" && !e.Time.Before(r.Boot) && e.Time.Before(r.Boot.Add(settleCap)) && (r.Up.IsZero() || e.Time.Before(r.Up)):
			r.Up = e.Time
		case e.Pattern == "NodeReady" && !e.Time.Before(r.Boot) && e.Time.Before(r.Boot.Add(settleCap)) && (r.Ready.IsZero() || e.Time.Before(r.Ready)):
			r.Ready = e.Time
		}
	}
	if len(reqs) > 0 {
		sort.Slice(reqs, func(i, j int) bool { return reqs[i].Time.Before(reqs[j].Time) })
		// the last request, from its first line (the guest agent logs before logind)
		last := reqs[len(reqs)-1].Time
		first := reqs[len(reqs)-1]
		for _, e := range reqs {
			if !e.Time.Before(last.Add(-2 * time.Minute)) {
				first = e
				break
			}
		}
		r.Requested, r.By = first.Time, requester(reqs, last)
	}
	for _, e := range marks {
		if e.Pattern == "shutdown-clean" && !e.Time.Before(latest(prev, r.Requested.Add(-time.Minute))) && !e.Time.After(r.Boot) {
			r.Clean = true
		}
	}
}

var (
	guestMode  = regexp.MustCompile(`guest-shutdown called, mode: (\w+)`)
	logindWhy  = regexp.MustCompile(`System is (rebooting|powering down|powering off|halting)(?: \(([^)]*)\))?`)
	syslogProg = regexp.MustCompile(`^([^\[:\s]+)`)
	// the kernel's first lines: rsyslog can miss the very first one
	bootLine    = regexp.MustCompile(`^kernel: (Linux version [0-9]|Command line: |BIOS-provided physical RAM map|The list of certified hardware)`)
	syslogStamp = regexp.MustCompile(`^(?:([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z))) \S+ (.*)$`)
)

// requester names what asked for the shutdown, from the request lines
// logged within two minutes before the last one.
func requester(reqs []Entry, last time.Time) string {
	by := ""
	for _, e := range reqs {
		if e.Time.Before(last.Add(-2 * time.Minute)) {
			continue
		}
		switch {
		case guestMode.MatchString(e.Text):
			return "the hypervisor through the QEMU guest agent (mode " + guestMode.FindStringSubmatch(e.Text)[1] + ")"
		case strings.Contains(e.Text, "Power key pressed"):
			by = "the power button (ACPI power key)"
		case logindWhy.MatchString(e.Text) && by == "":
			m := logindWhy.FindStringSubmatch(e.Text)
			by = "a " + map[string]string{"rebooting": "reboot", "powering down": "power-off", "powering off": "power-off", "halting": "halt"}[m[1]] + " command"
			if m[2] != "" {
				by += " (" + m[2] + ")"
			}
		case by == "":
			by = "a shutdown command"
		}
	}
	return by
}

// settle reads the node's Ready and its pods' return from the snapshot:
// valid for the node's latest restart only (a pod's condition keeps its
// last transition).
func (r *Restart) settle(snap *k8s.Snapshot) {
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if n.Name != r.Node {
			continue
		}
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue && !c.LastTransitionTime.Time.Before(r.Boot) && r.Ready.IsZero() {
				r.Ready = c.LastTransitionTime.Time
			}
		}
	}
	var last time.Time
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.Spec.NodeName != r.Node || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed || p.Status.StartTime == nil || !p.Status.StartTime.Time.Before(r.Boot) {
			continue // not on the node, finished, or created after the boot
		}
		for _, c := range p.Status.Conditions {
			if c.Type != corev1.PodReady {
				continue
			}
			t := c.LastTransitionTime.Time
			switch {
			case c.Status != corev1.ConditionTrue:
				r.Waiting = append(r.Waiting, p.Namespace+"/"+p.Name)
			case !t.Before(r.Boot) && !t.After(r.Boot.Add(settleCap)) && t.After(last):
				last = t
			}
		}
	}
	// the pods that came back; one that never did (a broken image, a missing
	// volume) is listed, it does not hold the restart open
	r.Settled = last
}

// evidence: the lines each phase rests on, and the containers it ended.
func (r *Restart) evidence(tl *Timeline) {
	for _, e := range tl.Entries {
		if e.Node != r.Node {
			continue
		}
		switch {
		case (e.Pattern == "shutdown-requested" && e.Time.Equal(r.Requested)) ||
			(e.Pattern == "boot-last-line" && e.Time.Equal(r.LastLine)) ||
			(e.Pattern == "kernel-boot" && absDur(e.Time.Sub(r.Boot)) < 3*time.Minute) ||
			(e.Pattern == "rke2-up" && e.Time.Equal(r.Up)):
			if !slices.ContainsFunc(r.Evidence, func(o Entry) bool { return o.Pattern == e.Pattern }) {
				r.Evidence = append(r.Evidence, e)
			}
		}
	}
	var lost []Entry
	for _, e := range tl.Entries {
		if e.Pattern == "terminated-unknown" && e.Node == r.Node && slices.Contains(r.Lost, e.Unit) {
			lost = append(lost, e)
		}
	}
	r.Evidence = append(r.Evidence, sample(lost, 2)...)
	sort.SliceStable(r.Evidence, func(i, j int) bool { return r.Evidence[i].Time.Before(r.Evidence[j].Time) })
}

// ---- containers lost together ----------------------------------------------

// lostEpisode is a moment a node's containers all ended together: the
// kubelet found them gone (a reboot, a crash, rke2-killall) and recorded
// each as terminated Unknown, exit 255.
type lostEpisode struct {
	node  string
	at    time.Time
	units []string // ns/pod/container
}

// lostSpan and lostMin: containers ending within lostSpan of each other on
// one node, at least lostMin of them, are one episode.
const (
	lostSpan = 2 * time.Minute
	lostMin  = 3
)

func lostEpisodes(s *k8s.Snapshot) []lostEpisode {
	type ended struct {
		at   time.Time
		unit string
	}
	byNode := map[string][]ended{}
	for i := range s.Pods {
		p := &s.Pods[i]
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			if t := cs.LastTerminationState.Terminated; t != nil && t.Reason == "Unknown" && t.ExitCode == 255 && p.Spec.NodeName != "" {
				byNode[p.Spec.NodeName] = append(byNode[p.Spec.NodeName], ended{t.FinishedAt.Time, p.Namespace + "/" + p.Name + "/" + cs.Name})
			}
		}
	}
	var out []lostEpisode
	for _, node := range strutil.SortedKeys(byNode) {
		es := byNode[node]
		sort.Slice(es, func(i, j int) bool { return es[i].at.Before(es[j].at) })
		for i := 0; i < len(es); {
			j := i
			for j < len(es) && es[j].at.Sub(es[i].at) <= lostSpan {
				j++
			}
			if j-i >= lostMin {
				ep := lostEpisode{node: node, at: es[i].at}
				for _, e := range es[i:j] {
					ep.units = append(ep.units, e.unit)
				}
				out = append(out, ep)
			}
			i = j
		}
	}
	return out
}

// ---- the syslog file ------------------------------------------------------------

// syslogEntries reads /var/log/messages or syslog from a bundle: the only
// record of earlier boots on a node whose journal is kept in memory. Each
// boot (the kernel's first lines) becomes a kernel-boot entry with the line
// before it as the old boot's last sign of life (boot-last-line); shutdown
// requests and completions are kept wherever they are; with keepOld the
// earlier boots' warnings and errors too (the current boot is the
// journal's).
func syslogEntries(path, rel, node string, now time.Time, keepOld bool) ([]Entry, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var out, old []Entry
	var prev Entry
	var lastBoot time.Time
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		t, body := parseSyslog(line, now)
		if t.IsZero() {
			continue
		}
		e := Entry{Time: t, Node: node, Kind: "file", Unit: syslogProg.FindString(body), Class: logs.ClassInfo, Text: body, Ref: Ref{File: rel, Line: n}}
		if bootLine.MatchString(body) && (lastBoot.IsZero() || t.Sub(lastBoot) > 2*time.Minute) {
			if !prev.Time.IsZero() {
				prev.Pattern = "boot-last-line"
				out = append(out, prev)
			}
			e.Pattern = "kernel-boot"
			out = append(out, e)
			lastBoot = t
		} else if logs.MayMatch(line) {
			if p := logs.Lookup(body); p != nil {
				e.Class, e.Pattern = p.Class, p.Name
				switch {
				case p.Name == "shutdown-requested" || p.Name == "shutdown-clean":
					out = append(out, e)
				case keepOld && p.Class >= logs.ClassWarn:
					old = append(old, e)
				}
			}
		}
		e.Pattern, e.Class = "", logs.ClassInfo
		prev = e
	}
	for _, e := range old {
		if e.Time.Before(lastBoot) {
			out = append(out, e)
		}
	}
	return out, n
}

// parseSyslog reads "Sep 27 20:32:29 host prog[pid]: msg" (no year: the
// current one, unless that lands in the future) or rsyslog's ISO stamp,
// and returns the time and "prog[pid]: msg".
func parseSyslog(l string, now time.Time) (time.Time, string) {
	g := syslogStamp.FindStringSubmatch(l)
	if g == nil {
		return time.Time{}, ""
	}
	if g[6] != "" {
		ts := g[6]
		if len(ts) > 5 && ts[len(ts)-1] != 'Z' && ts[len(ts)-3] != ':' {
			ts = ts[:len(ts)-2] + ":" + ts[len(ts)-2:]
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return time.Time{}, ""
		}
		return t, g[7]
	}
	m, err := time.Parse("Jan", g[1])
	if err != nil {
		return time.Time{}, ""
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	t := time.Date(now.Year(), m.Month(), n(g[2]), n(g[3]), n(g[4]), n(g[5]), 0, now.Location())
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, g[7]
}

// lastLineEntry is the last line of a journal dump (previous-boot.log: the
// old boot's last sign of life).
func lastLineEntry(path, rel, node string) (Entry, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var last string
	n, at := 0, 0
	for sc.Scan() {
		n++
		if strings.TrimSpace(sc.Text()) != "" {
			last, at = sc.Text(), n
		}
	}
	t, body := parseSyslog(last, time.Now())
	if t.IsZero() {
		return Entry{}, false
	}
	return Entry{Time: t, Node: node, Kind: "journal", Unit: syslogProg.FindString(body), Class: logs.ClassInfo, Pattern: "boot-last-line", Text: body, Ref: Ref{File: rel, Line: at}}, true
}
