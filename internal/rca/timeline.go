// Package rca looks for the root cause of an incident in a log bundle
// (internal/gather). It puts everything the bundle recorded on one
// timeline - journals, rke2 log files, the kernel log, container logs,
// events and the state changes the snapshot carries - classifies each line
// with the log knowledge base (internal/logs), and runs rules that tie a
// cause to the effects that followed it. Every conclusion points at the
// bundle file and line it rests on.
package rca

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/gather"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Entry is one point on the timeline.
type Entry struct {
	Time    time.Time  `json:"time"`
	Node    string     `json:"node,omitempty"`    // "" for cluster-level entries
	Kind    string     `json:"kind"`              // journal | file | pod | event | status
	Unit    string     `json:"unit,omitempty"`    // systemd unit, ns/pod/container, or the event's object
	Class   logs.Class `json:"class"`             // info | startup | warn | error
	Pattern string     `json:"pattern,omitempty"` // knowledge-base name, event reason or status reason
	Text    string     `json:"text"`
	Ref     Ref        `json:"ref"`
}

// Ref locates an entry's evidence in the bundle.
type Ref struct {
	File string `json:"file"`           // bundle path
	Line int    `json:"line,omitempty"` // 1-based, 0 when the entry is not a line of the file
}

func (r Ref) String() string {
	if r.Line > 0 {
		return r.File + ":" + strconv.Itoa(r.Line)
	}
	return r.File
}

// Timeline is the bundle's entries in time order.
type Timeline struct {
	Entries []Entry
	// ClockFix is the correction applied to each node's log times: the
	// node's clock offset measured by its probe, when over clockTolerance.
	ClockFix map[string]time.Duration
	Lines    int // log lines read
}

// clockTolerance: offsets below it are probe latency, not a wrong clock.
const clockTolerance = 2 * time.Second

// Build reads the bundle into a timeline. Only lines the knowledge base
// recognizes become entries (a journal is mostly routine); events, container
// terminations and node condition changes always do.
func Build(b *gather.Bundle, r *gather.Replayed) *Timeline {
	tl := &Timeline{ClockFix: map[string]time.Duration{}}
	now := b.Manifest.Created
	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(es []Entry, lines int) {
		mu.Lock()
		tl.Entries = append(tl.Entries, es...)
		tl.Lines += lines
		mu.Unlock()
	}
	ents, _ := os.ReadDir(b.Path("nodes"))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := "nodes/" + e.Name()
		node := nodeName(r, b, e.Name())
		var fix time.Duration
		if ni := r.Input.Nodes[node]; ni != nil && absDur(ni.ClockOffset) > clockTolerance {
			fix = ni.ClockOffset
			tl.ClockFix[node] = fix
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			es, n := nodeEntries(b, dir, node, now)
			for i := range es {
				es[i].Time = es[i].Time.Add(-fix)
			}
			add(es, n)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		es, n := apiPodLogs(b)
		add(es, n)
	}()
	wg.Wait()
	tl.Entries = append(tl.Entries, snapshotEntries(r.Snap)...)
	tl.Entries = dedupe(tl.Entries)
	sort.SliceStable(tl.Entries, func(i, j int) bool { return tl.Entries[i].Time.Before(tl.Entries[j].Time) })
	return tl
}

// nodeName maps a bundle directory back to the node it holds (the probe
// metadata keeps the real name; directory names are made file-safe).
func nodeName(r *gather.Replayed, b *gather.Bundle, dir string) string {
	for _, n := range b.Manifest.Nodes {
		if safe(n.Name) == dir {
			return n.Name
		}
	}
	for name := range r.Input.Nodes {
		if safe(name) == dir {
			return name
		}
	}
	return dir
}

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '-'
	}, s)
}

// nodeEntries classifies one node's journals and log files together (the
// startup windows of rke2/kubelet restarts apply across them) and its
// on-disk container logs.
func nodeEntries(b *gather.Bundle, dir, node string, now time.Time) ([]Entry, int) {
	var srcs []logs.Source
	var out []Entry
	lines := 0
	root := b.Path(dir)
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(b.Dir, p)
		rel = filepath.ToSlash(rel)
		sub := strings.TrimPrefix(rel, dir+"/")
		switch {
		case strings.HasPrefix(sub, "journal/") && strings.HasSuffix(sub, ".log"):
			ls, nums, n := readCandidates(p)
			lines += n
			srcs = append(srcs, logs.Source{Name: rel, Lines: ls, Numbers: nums})
		case strings.HasPrefix(sub, "files/") && (strings.HasSuffix(sub, "kubelet.log") || strings.HasSuffix(sub, "containerd.log")):
			ls, nums, n := readCandidates(p)
			lines += n
			srcs = append(srcs, logs.Source{Name: rel, Unit: nodeinfo.LogFileUnit(sub), Lines: ls, Numbers: nums})
		case strings.HasPrefix(sub, "pods/") && strings.HasSuffix(sub, ".log"):
			// pods/<ns>_<pod>_<uid>/<container>/<n>.log
			parts := strings.Split(sub, "/")
			if len(parts) != 4 {
				return nil
			}
			ns, pod, _ := strings.Cut(parts[1], "_")
			pod, _, _ = strings.Cut(pod, "_")
			es, n := containerLog(p, rel, node, ns+"/"+pod+"/"+parts[2], parseCRI)
			lines += n
			out = append(out, es...)
		}
		return nil
	})
	// log files with klog / logfmt stamps are read in the node's zone
	sum := logs.ClassifySources(srcs, now.In(nodeZone(b, dir)))
	for _, m := range sum.Matches {
		if m.Pattern == nil || m.Time.IsZero() {
			continue
		}
		kind := "journal"
		if strings.Contains(m.Source, "/files/") {
			kind = "file"
		}
		out = append(out, Entry{Time: m.Time, Node: node, Kind: kind, Unit: m.Unit, Class: m.Class, Pattern: m.Pattern.Name, Text: strings.TrimSpace(m.Line), Ref: Ref{File: m.Source, Line: m.LineNo}})
	}
	return out, lines
}

// nodeZone is the node's UTC offset as gather.sh recorded it (system/node.txt
// "tz: -0400"); UTC when missing.
func nodeZone(b *gather.Bundle, dir string) *time.Location {
	for _, l := range readLines(b.Path(dir + "/system/node.txt")) {
		v, ok := strings.CutPrefix(l, "tz: ")
		if !ok || len(v) != 5 || (v[0] != '+' && v[0] != '-') {
			continue
		}
		h, err1 := strconv.Atoi(v[1:3])
		m, err2 := strconv.Atoi(v[3:5])
		if err1 != nil || err2 != nil {
			continue
		}
		off := h*3600 + m*60
		if v[0] == '-' {
			off = -off
		}
		return time.FixedZone(v, off)
	}
	return time.UTC
}

// apiPodLogs reads cluster/pods/<ns>/<pod>/<container>[.previous].log,
// fetched with timestamps, one file per worker: a cluster bundle holds
// hundreds of them and each is read on its own.
func apiPodLogs(b *gather.Bundle) ([]Entry, int) {
	type job struct{ path, rel, unit string }
	var jobs []job
	_ = filepath.WalkDir(b.Path("cluster/pods"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".log") {
			return nil
		}
		rel, _ := filepath.Rel(b.Dir, p)
		rel = filepath.ToSlash(rel)
		parts := strings.Split(strings.TrimPrefix(rel, "cluster/pods/"), "/")
		if len(parts) != 3 {
			return nil
		}
		ctr := strings.TrimSuffix(strings.TrimSuffix(parts[2], ".log"), ".previous")
		jobs = append(jobs, job{p, rel, parts[0] + "/" + parts[1] + "/" + ctr})
		return nil
	})
	var (
		mu    sync.Mutex
		out   []Entry
		lines int
		wg    sync.WaitGroup
	)
	next := make(chan job)
	for w := 0; w < min(runtime.GOMAXPROCS(0), 8); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range next {
				es, n := containerLog(j.path, j.rel, "", j.unit, parseAPI)
				mu.Lock()
				out = append(out, es...)
				lines += n
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		next <- j
	}
	close(next)
	wg.Wait()
	return out, lines
}

// containerLog classifies a container log whose lines carry their own
// timestamp (CRI files on disk, API logs with timestamps=true).
func containerLog(path, rel, node, unit string, parse func(string) (time.Time, string)) ([]Entry, int) {
	var out []Entry
	ls, nums, total := readCandidates(path)
	for i, l := range ls {
		t, body := parse(l)
		if t.IsZero() {
			continue
		}
		p := logs.Lookup(body)
		if p == nil {
			continue
		}
		out = append(out, Entry{Time: t, Node: node, Kind: "pod", Unit: unit, Class: p.Class, Pattern: p.Name, Text: strings.TrimSpace(body), Ref: Ref{File: rel, Line: nums[i]}})
	}
	return out, total
}

// parseCRI reads "2026-09-26T19:35:19.123456789Z stdout F message".
func parseCRI(l string) (time.Time, string) {
	ts, rest, ok := strings.Cut(l, " ")
	if !ok {
		return time.Time{}, ""
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, ""
	}
	if _, rest, ok = strings.Cut(rest, " "); ok { // stream
		if _, rest, ok = strings.Cut(rest, " "); ok { // F/P tag
			return t, rest
		}
	}
	return t, rest
}

// parseAPI reads "2026-09-26T19:35:19.123456789Z message".
func parseAPI(l string) (time.Time, string) {
	ts, rest, ok := strings.Cut(l, " ")
	if !ok {
		return time.Time{}, ""
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, ""
	}
	return t, rest
}

// snapshotEntries turns what the API recorded into timeline points: every
// event, each container's last termination, and node condition changes.
func snapshotEntries(s *k8s.Snapshot) []Entry {
	var out []Entry
	for i := range s.Events {
		ev := &s.Events[i]
		t := ev.EventTime.Time
		if t.IsZero() {
			t = ev.LastTimestamp.Time
		}
		if t.IsZero() {
			t = ev.FirstTimestamp.Time
		}
		if t.IsZero() {
			continue
		}
		class := logs.ClassInfo
		if ev.Type == corev1.EventTypeWarning {
			class = logs.ClassWarn
		}
		obj := strings.ToLower(ev.InvolvedObject.Kind) + " " + ev.InvolvedObject.Name
		if ev.InvolvedObject.Namespace != "" {
			obj = strings.ToLower(ev.InvolvedObject.Kind) + " " + ev.InvolvedObject.Namespace + "/" + ev.InvolvedObject.Name
		}
		node := ev.Source.Host
		if ev.InvolvedObject.Kind == "Node" {
			node = ev.InvolvedObject.Name
		}
		text := ev.Message
		if ev.Count > 1 {
			text += " (x" + strconv.Itoa(int(ev.Count)) + ")"
		}
		out = append(out, Entry{Time: t, Node: node, Kind: "event", Unit: obj, Class: class, Pattern: ev.Reason, Text: text, Ref: Ref{File: "cluster/resources/events.yaml"}})
	}
	for i := range s.Pods {
		p := &s.Pods[i]
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			t := cs.LastTerminationState.Terminated
			if t == nil || t.FinishedAt.IsZero() {
				continue
			}
			class := logs.ClassWarn
			if t.Reason == "OOMKilled" || t.ExitCode != 0 {
				class = logs.ClassError
			}
			text := "container " + cs.Name + " terminated: " + t.Reason + " exit " + strconv.Itoa(int(t.ExitCode)) + ", restarts " + strconv.Itoa(int(cs.RestartCount))
			if t.Message != "" {
				text += ": " + firstLine(t.Message)
			}
			out = append(out, Entry{Time: t.FinishedAt.Time, Node: p.Spec.NodeName, Kind: "status", Unit: p.Namespace + "/" + p.Name + "/" + cs.Name, Class: class, Pattern: "terminated-" + strings.ToLower(orDefault(t.Reason, "exit")), Text: text, Ref: Ref{File: "cluster/resources/pods.yaml"}})
		}
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		// cordoned (kubectl cordon / drain, an upgrade controller): the
		// unschedulable taint carries when it happened
		if n.Spec.Unschedulable {
			for _, tn := range n.Spec.Taints {
				if tn.Key == "node.kubernetes.io/unschedulable" && tn.TimeAdded != nil {
					out = append(out, Entry{Time: tn.TimeAdded.Time, Node: n.Name, Kind: "status", Unit: "node " + n.Name, Class: logs.ClassWarn, Pattern: "node-cordoned", Text: "node cordoned: spec.unschedulable (kubectl cordon / drain, or an upgrade controller)", Ref: Ref{File: "cluster/resources/nodes.yaml"}})
				}
			}
		}
		for _, c := range n.Status.Conditions {
			bad := (c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue) || (badWhenTrue[c.Type] && c.Status == corev1.ConditionTrue)
			if !bad || c.LastTransitionTime.IsZero() {
				continue
			}
			out = append(out, Entry{Time: c.LastTransitionTime.Time, Node: n.Name, Kind: "status", Unit: "node " + n.Name, Class: logs.ClassError, Pattern: "node-" + strings.ToLower(string(c.Type)) + "-" + strings.ToLower(string(c.Status)), Text: string(c.Type) + "=" + string(c.Status) + ": " + c.Reason + " " + c.Message, Ref: Ref{File: "cluster/resources/nodes.yaml"}})
		}
	}
	return out
}

// BuildLive is Build for the live TUI: the snapshot's events and states,
// and the log lines each node's probe classified (logSum, keyed by node).
// No file references: live entries point at the unit they came from.
func BuildLive(s *k8s.Snapshot, logSum map[string]*logs.Summary) *Timeline {
	tl := &Timeline{ClockFix: map[string]time.Duration{}}
	for node, sum := range logSum {
		if sum == nil {
			continue
		}
		tl.Lines += sum.Total
		for _, m := range sum.Matches {
			if m.Pattern == nil || m.Time.IsZero() {
				continue
			}
			tl.Entries = append(tl.Entries, Entry{Time: m.Time, Node: node, Kind: "journal", Unit: m.Unit, Class: m.Class, Pattern: m.Pattern.Name, Text: strings.TrimSpace(m.Line), Ref: Ref{File: "journal of " + node + " (" + m.Unit + ")"}})
		}
	}
	tl.Entries = append(tl.Entries, snapshotEntries(s)...)
	tl.Entries = dedupe(tl.Entries)
	sort.SliceStable(tl.Entries, func(i, j int) bool { return tl.Entries[i].Time.Before(tl.Entries[j].Time) })
	return tl
}

// badWhenTrue are the node conditions that report a problem when True;
// distributions add their own positive ones (k3s's EtcdIsVoter).
var badWhenTrue = map[corev1.NodeConditionType]bool{
	corev1.NodeMemoryPressure: true, corev1.NodeDiskPressure: true, corev1.NodePIDPressure: true, corev1.NodeNetworkUnavailable: true,
}

// dedupe drops repeats of the same line on the same node at the same time
// (the per-unit journals, the warnings journal and the previous boot overlap).
func dedupe(es []Entry) []Entry {
	seen := map[string]bool{}
	out := es[:0]
	for _, e := range es {
		k := e.Node + "\x00" + e.Time.UTC().Format(time.RFC3339Nano) + "\x00" + e.Text
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// readCandidates streams a log file and keeps only the lines some
// knowledge-base pattern could match, with their line numbers: a node's
// journals run to hundreds of MiB, and the rest would only become
// unmatched info lines.
func readCandidates(p string) (lines []string, nums []int, total int) {
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var scratch []byte
	for sc.Scan() {
		total++
		if b := sc.Bytes(); logs.MayMatchBytes(b, &scratch) {
			lines = append(lines, string(b))
			nums = append(nums, total)
		}
	}
	return lines, nums, total
}

func readLines(p string) []string {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
