package ui

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	etcdpkg "github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/rescue"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// etcd rescue (X on the etcd tab): restore a snapshot over SSH. The overlay
// walks through picking the node, picking one of its snapshots, a read-only
// preflight on every server, a typed confirmation, and then shows the
// steps as they run (internal/rescue does the work). esc hides the running
// view; the rescue carries on and X brings it back.

type rescuePhase int

const (
	rescuePickMode rescuePhase = iota
	rescuePickNode
	rescuePickSnap
	rescuePreflight
	rescueConfirm
	rescueRunning
	rescueDone
)

const rescueWord = "restore"

// rescueNodeOpt is one control-plane node in the picker.
type rescueNodeOpt struct {
	node       rescue.Node
	probe      *etcdpkg.Probe
	online     bool   // reachable over SSH (probe answered)
	state      string // healthy | UNHEALTHY | unreachable | no probe
	leader     bool   // etcd says it leads right now
	lastLeader bool   // the logs say its member id led at the highest term seen
	member     string // member name on disk (rke2: <host>-<hash>)
	memberID   string
	term       uint64 // highest term at which this node's member id was elected (all logs)
	index      uint64 // WAL index on disk
	snaps      int
	latest     time.Time
	dist       string
}

// rescueSnapOpt is one restore point on the chosen node.
type rescueSnapOpt struct {
	path string // local path, or S3 object name
	name string
	s3   bool
	when time.Time
	size int64
	dir  string
}

type rescueView struct {
	phase    rescuePhase
	rejoin   bool // rejoin one server instead of restoring a snapshot
	modeCur  int
	anchor   rescueNodeOpt // rejoin: the healthy member the node joins through
	kind     rescue.Kind
	nodes    []rescueNodeOpt
	nodeCur  int
	snaps    []rescueSnapOpt
	snapCur  int
	plan     *rescue.Plan
	prefErr  string
	input    textinput.Model
	steps    []rescue.Step
	current  int
	done     bool
	err      error
	ch       chan rescue.Event
	scroll   int
	manual   bool // the operator scrolled the running view: stop following the current step
	started  time.Time
	finished time.Time
	seq      int
}

type rescuePreflightMsg struct {
	seq int
	err error
}

type rescueMsg struct {
	seq int
	ev  rescue.Event
	ok  bool // false: channel closed
}

// openRescue handles X on the etcd tab.
func (a *App) openRescue() tea.Cmd {
	if r := a.rescue; r != nil && (r.phase == rescueRunning || r.phase == rescueDone || r.phase == rescuePreflight) {
		a.overlay = ovRescue
		return nil
	}
	switch {
	case !a.cfg.Actions.Enabled:
		a.setStatus("mutating actions are disabled (--read-only / actions.enabled: false)")
		return nil
	case a.runner == nil:
		a.setStatus("SSH unavailable: " + a.sshErr + " (the rescue runs everything over SSH)")
		return nil
	case !a.sshEnabled:
		a.setStatus("enable SSH collection first (s): the rescue needs the etcd probes and SSH access to every server")
		return nil
	case a.snap == nil:
		a.setStatus("waiting for the first API snapshot")
		return nil
	case a.actionRunning:
		a.setStatus("an action is still running")
		return nil
	}
	nodes, kind, err := a.rescueCandidates()
	if err != nil {
		a.setStatus(err.Error())
		return nil
	}
	a.rescue = &rescueView{phase: rescuePickMode, kind: kind, nodes: nodes}
	if a.rescue.recommendRejoin() {
		a.rescue.modeCur = 1
	}
	a.rescue.input = textinput.New()
	a.rescue.input.Prompt = "type " + rescueWord + " to begin> "
	a.rescue.input.CharLimit = 16
	a.overlay = ovRescue
	// nodes without a probe yet (peers just discovered on disk, a slow
	// cycle): probe them now rather than on the next refresh
	missing := 0
	for _, o := range nodes {
		if o.probe == nil && !a.etcdPend[o.node.Name] {
			missing++
		}
	}
	if missing > 0 && len(a.etcdPend) == 0 && len(a.pending) == 0 {
		a.setStatus(fmt.Sprintf("probing %d node(s) over SSH; the list updates as they answer", missing))
		return a.collectCmds(a.snap)
	}
	return nil
}

// rescueRefresh rebuilds the picker's node list while it is open (probes
// keep arriving), keeping the selection on the same node.
func (a *App) rescueRefresh() {
	r := a.rescue
	if r == nil || (r.phase != rescuePickMode && r.phase != rescuePickNode) {
		return
	}
	nodes, kind, err := a.rescueCandidates()
	if err != nil {
		return
	}
	cur := ""
	if r.nodeCur >= 0 && r.nodeCur < len(r.nodes) {
		cur = r.nodes[r.nodeCur].node.Name
	}
	r.nodes, r.kind = nodes, kind
	r.nodeCur = 0
	for i, o := range nodes {
		if o.node.Name == cur {
			r.nodeCur = i
		}
	}
	if r.phase == rescuePickMode {
		r.modeCur = 0
		if r.recommendRejoin() {
			r.modeCur = 1
		}
	}
}

// rescueCandidates lists the etcd nodes with what is known about each,
// best restore source first: an online healthy leader, then online nodes
// by the highest election term their log saw, then on-disk raft state and
// snapshot age.
func (a *App) rescueCandidates() ([]rescueNodeOpt, rescue.Kind, error) {
	targets, offline := a.sshTargets(a.snap)
	dists := map[string]int{}
	// what every node's disk says about the members and who led last
	peersByHost := map[string]etcdpkg.Peer{}
	bestTerm := map[string]uint64{} // member id -> highest term it was elected at
	bestID, bestT := "", uint64(0)
	for _, n := range strutil.SortedKeys(a.etcd) {
		p := a.etcd[n]
		for _, pr := range p.Peers {
			if cur, ok := peersByHost[pr.Host]; !ok || (cur.ID == "" && pr.ID != "") {
				peersByHost[pr.Host] = pr
			}
		}
		for _, ev := range p.LeaderEvents {
			if ev.Term > bestTerm[ev.Leader] {
				bestTerm[ev.Leader] = ev.Term
			}
			if ev.Term > bestT {
				bestID, bestT = ev.Leader, ev.Term
			}
		}
	}
	var out []rescueNodeOpt
	for i := range targets {
		n := &targets[i]
		if !offline && !k8s.IsEtcdNode(targets, n) {
			continue
		}
		p := a.etcd[n.Name]
		if offline && p != nil && p.Err == nil && p.DataDir == "" {
			continue // ssh.hosts entry that is not an etcd server
		}
		o := rescueNodeOpt{node: rescue.Node{Name: n.Name, Host: a.nodeAddress(n), IP: a.nodeIP(n)}, probe: p, state: "no probe"}
		if p == nil && a.etcdPend[n.Name] {
			o.state = "probing..."
		}
		if p != nil {
			o.node.DataDir = p.DataDir
			o.dist = p.Dist
			switch {
			case p.Err != nil:
				o.state = "unreachable"
			default:
				o.online = true
				o.state = "no /health reply"
				if p.Health != nil {
					o.state = "UNHEALTHY"
					if p.Health.Healthy {
						o.state = "healthy"
					}
				}
				if p.Metrics != nil && p.Metrics.IsLeader {
					o.leader = true
				}
				dists[p.Dist]++
			}
			if p.LocalMemberID != "" {
				o.memberID = p.LocalMemberID
			}
			if p.SelfName != "" {
				o.member = p.SelfName
			}
			if p.Raft != nil {
				o.index = p.Raft.WALIndex
				if o.index == 0 {
					o.index = p.Raft.SnapIndex
				}
			}
			o.snaps = p.SnapshotCount()
			if f, _, ok := p.LatestSnapshot(); ok {
				o.latest = f.ModTime
			}
			if o.node.IP == "" {
				for _, m := range p.Members {
					if p.LocalMemberID != "" && m.ID == p.LocalMemberID && len(m.PeerURLs) > 0 {
						o.node.IP = strutil.URLHost(m.PeerURLs[0])
					}
				}
			}
		}
		if pr, ok := peersByHost[o.node.IP]; ok {
			if o.member == "" {
				o.member = pr.Name
			}
			if o.memberID == "" {
				o.memberID = pr.ID
			}
		}
		if o.memberID != "" {
			o.term = bestTerm[o.memberID]
			o.lastLeader = o.memberID == bestID && bestID != ""
		}
		// the cluster-wide exec probe knows the leader when SSH metrics do not
		if x := a.etcdExec; x != nil && x.Err == nil && !o.leader {
			for _, st := range x.Statuses {
				if st.Leader != "" && st.Leader == st.MemberID {
					if m := x.MemberByEndpoint(st.Endpoint); m != nil && (m.Name == n.Name || (p != nil && m.Name == p.Hostname)) {
						o.leader = true
					}
				}
			}
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("no etcd nodes known: wait for the node list / etcd probes, or list the servers under ssh.hosts")
	}
	dist := a.snap.Distribution
	if _, ok := rescue.Supported(dist); !ok {
		best := 0
		for d, c := range dists {
			if c > best {
				dist, best = d, c
			}
		}
	}
	kind, ok := rescue.Supported(dist)
	if !ok {
		return nil, "", fmt.Errorf("the rescue supports rke2, k3s and kubeadm control planes; this cluster looks like %q - follow the triage steps on the etcd tab instead", strutil.FirstNonEmpty(dist, "-"))
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.online != y.online {
			return x.online
		}
		if (x.state == "healthy") != (y.state == "healthy") {
			return x.state == "healthy"
		}
		if x.leader != y.leader {
			return x.leader
		}
		if x.term != y.term {
			return x.term > y.term
		}
		if x.index != y.index {
			return x.index > y.index
		}
		return x.latest.After(y.latest)
	})
	return out, kind, nil
}

// nodeIP is the address peers use for a node: the InternalIP, else the
// SSH address when it is an IP.
func (a *App) nodeIP(n *corev1.Node) string {
	for _, ad := range n.Status.Addresses {
		if ad.Type == corev1.NodeInternalIP && ad.Address != "" {
			return ad.Address
		}
	}
	h := a.nodeAddress(n)
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	if net.ParseIP(h) != nil {
		return h
	}
	return ""
}

// rescueSnapshots lists the restore points on a node, newest first: local
// files the probe saw, plus S3 records when the node's own config.yaml
// carries the S3 settings (a config secret is unreadable while the
// apiserver is down, so those are not offered).
func (a *App) rescueSnapshots(o rescueNodeOpt) []rescueSnapOpt {
	var out []rescueSnapOpt
	if o.probe == nil {
		return nil
	}
	for _, d := range o.probe.SnapshotDirs {
		for _, f := range d.Files {
			out = append(out, rescueSnapOpt{path: d.Path + "/" + f.Name, name: f.Name, when: f.ModTime, size: f.Size, dir: d.Path})
		}
	}
	if a.rescue != nil && a.rescue.kind != rescue.Kubeadm {
		if c := checks.S3ConfigFor(o.probe, a.s3); c.Enabled && c.SecretName == "" {
			for _, r := range a.snap.RKE2Snapshots {
				if r.S3 && r.Status != "failed" {
					out = append(out, rescueSnapOpt{path: r.Name, name: r.Name, s3: true, when: r.Created, size: r.Size, dir: "s3://" + c.Bucket + "/" + c.Folder})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].when.After(out[j].when) })
	return out
}

// recommendRejoin says whether the picture looks like "quorum is fine, one
// member is broken" (rejoin that member) rather than "restore a snapshot":
// a live leader among the healthy nodes and at least one node that is
// reachable but not healthy.
func (r *rescueView) recommendRejoin() bool {
	leader, broken := false, false
	for _, o := range r.nodes {
		if o.online && o.state == "healthy" && o.leader {
			leader = true
		}
		if o.online && o.state != "healthy" {
			broken = true
		}
	}
	return leader && broken
}

// bestAnchor is the healthy member a node rejoins through: the live leader,
// else any healthy node.
func (r *rescueView) bestAnchor(except string) (rescueNodeOpt, bool) {
	var found rescueNodeOpt
	ok := false
	for _, o := range r.nodes {
		if o.node.Name == except || !o.online || o.state != "healthy" {
			continue
		}
		if o.leader {
			return o, true
		}
		if !ok {
			found, ok = o, true
		}
	}
	return found, ok
}

// rescueOthers returns every other candidate as a plan node.
func (r *rescueView) others(target rescueNodeOpt) []rescue.Node {
	var out []rescue.Node
	for _, o := range r.nodes {
		if o.node.Name != target.node.Name {
			out = append(out, o.node)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (a *App) handleRescueKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	r := a.rescue
	key := m.String()
	if r == nil {
		a.overlay = ovNone
		return a, nil
	}
	switch r.phase {
	case rescuePickMode:
		switch key {
		case "esc", "q":
			a.rescue = nil
			a.overlay = ovNone
		case "j", "down", "k", "up", "tab":
			r.modeCur = 1 - r.modeCur
		case "enter":
			r.rejoin = r.modeCur == 1
			r.phase = rescuePickNode
			r.nodeCur = 0
			if r.rejoin {
				// preselect the broken one
				for i, o := range r.nodes {
					if o.online && o.state != "healthy" {
						r.nodeCur = i
						break
					}
				}
			}
		}
	case rescuePickNode:
		switch key {
		case "esc", "q", "backspace":
			r.phase = rescuePickMode
		case "j", "down":
			if r.nodeCur < len(r.nodes)-1 {
				r.nodeCur++
			}
		case "k", "up":
			if r.nodeCur > 0 {
				r.nodeCur--
			}
		case "enter":
			o := r.nodes[r.nodeCur]
			if !o.online {
				a.setStatus(o.node.Name + " is " + o.state + ": khealth has to reach it over SSH")
				return a, nil
			}
			if r.rejoin {
				anchor, ok := r.bestAnchor(o.node.Name)
				if !ok {
					a.setStatus("no healthy member to rejoin through: the surviving cluster is not serving - restore a snapshot instead")
					return a, nil
				}
				if o.state == "healthy" {
					a.setStatus(o.node.Name + " is a healthy member already; pick the broken one")
					return a, nil
				}
				r.anchor = anchor
				return a, a.startRescuePreflight()
			}
			r.snaps = a.rescueSnapshots(o)
			if len(r.snaps) == 0 {
				a.setStatus("no snapshot files known on " + o.node.Name + " (its etcd probe lists none; etcd.backup_dirs adds directories to scan)")
				return a, nil
			}
			r.snapCur = 0
			r.phase = rescuePickSnap
		}
	case rescuePickSnap:
		switch key {
		case "esc", "q", "backspace":
			r.phase = rescuePickNode
		case "j", "down":
			if r.snapCur < len(r.snaps)-1 {
				r.snapCur++
			}
		case "k", "up":
			if r.snapCur > 0 {
				r.snapCur--
			}
		case "enter":
			return a, a.startRescuePreflight()
		}
	case rescuePreflight:
		switch key {
		case "esc":
			a.overlay = ovNone // preflight is read-only; its result is dropped
			a.rescue = nil
		}
	case rescueConfirm:
		switch key {
		case "esc":
			a.rescue = nil
			a.overlay = ovNone
			a.setStatus("rescue canceled, nothing was changed")
		case "enter":
			if strings.TrimSpace(strings.ToLower(r.input.Value())) != rescueWord {
				a.setStatus("type " + rescueWord + " exactly to begin (esc cancels)")
				return a, nil
			}
			if r.prefErr != "" {
				a.setStatus("preflight failed: " + r.prefErr)
				return a, nil
			}
			r.input.Blur()
			return a, a.startRescue()
		case "down":
			r.scroll++
		case "up":
			r.scroll--
		case "pgdown", "ctrl+d", " ":
			r.scroll += a.bodyHeight() / 2
		case "pgup", "ctrl+u":
			r.scroll -= a.bodyHeight() / 2
		case "home", "ctrl+home":
			r.scroll = 0
		case "end", "ctrl+end":
			r.scroll = 1 << 30
		default:
			var cmd tea.Cmd
			r.input, cmd = r.input.Update(m)
			return a, cmd
		}
	case rescueRunning:
		switch key {
		case "esc", "q":
			a.overlay = ovNone
			a.setStatus("the rescue keeps running in the background; X on the etcd tab shows it again")
		case "x":
			if r.plan != nil && !r.plan.Aborting() {
				r.plan.Abort()
				a.setStatus("aborting after the step in progress (a half-done step would leave a node in an unknown state)")
			}
		case "j", "down":
			r.scroll++
			r.manual = true
		case "k", "up":
			r.scroll--
			r.manual = true
		case "pgdown", "ctrl+d", " ":
			r.scroll += a.bodyHeight() / 2
			r.manual = true
		case "pgup", "ctrl+u":
			r.scroll -= a.bodyHeight() / 2
			r.manual = true
		case "g", "home":
			r.scroll = 0
			r.manual = true
		case "G", "end":
			r.scroll = 1 << 30
			r.manual = true
		case "f":
			r.manual = false // follow the running step again
		}
	case rescueDone:
		switch key {
		case "esc", "q", "enter":
			a.overlay = ovNone
			a.rescue = nil
			a.heavyNext = true
			if !a.refreshing {
				a.setStatus("refreshing after the rescue")
				return a, a.refreshCmd()
			}
		case "j", "down":
			r.scroll++
		case "k", "up":
			if r.scroll > 0 {
				r.scroll--
			}
		case "g", "home":
			r.scroll = 0
		case "G", "end":
			r.scroll = 1 << 30
		case "pgdown", "ctrl+d", " ":
			r.scroll += a.bodyHeight() / 2
		case "pgup", "ctrl+u":
			r.scroll -= a.bodyHeight() / 2
			if r.scroll < 0 {
				r.scroll = 0
			}
		}
	}
	return a, nil
}

// startRescuePreflight builds the plan for the chosen node + snapshot and
// runs the read-only preflight on every server in the background.
func (a *App) startRescuePreflight() tea.Cmd {
	r := a.rescue
	target := r.nodes[r.nodeCur]
	if r.rejoin {
		r.plan = rescue.NewRejoin(r.kind, r.anchor.node, target.node)
	} else {
		snap := r.snaps[r.snapCur]
		r.plan = rescue.New(r.kind, target.node, r.others(target), snap.path, snap.s3)
	}
	r.phase = rescuePreflight
	r.prefErr = ""
	r.seq++
	seq, plan, runner := r.seq, r.plan, a.runner
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		return rescuePreflightMsg{seq: seq, err: plan.Preflight(ctx, runner)}
	}
}

func (a *App) handleRescuePreflight(m rescuePreflightMsg) tea.Cmd {
	r := a.rescue
	if r == nil || m.seq != r.seq || r.phase != rescuePreflight {
		return nil
	}
	r.phase = rescueConfirm
	r.scroll = 0
	if m.err != nil {
		r.prefErr = m.err.Error()
		return nil
	}
	r.input.SetValue("")
	return r.input.Focus()
}

// startRescue runs the plan in the background and follows its events.
func (a *App) startRescue() tea.Cmd {
	r := a.rescue
	r.phase = rescueRunning
	r.started = time.Now()
	r.steps = r.plan.Steps()
	r.current = -1
	r.scroll = 0
	r.seq++
	r.ch = make(chan rescue.Event, 64)
	seq, plan, ch := r.seq, r.plan, r.ch
	a.setStatus("etcd rescue started: " + fmt.Sprint(len(r.steps)) + " steps")
	go plan.Run(context.Background(), ch)
	return waitRescue(ch, seq)
}

func waitRescue(ch chan rescue.Event, seq int) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		return rescueMsg{seq: seq, ev: ev, ok: ok}
	}
}

func (a *App) handleRescueMsg(m rescueMsg) tea.Cmd {
	r := a.rescue
	if r == nil || m.seq != r.seq {
		return nil
	}
	if !m.ok {
		if r.phase == rescueRunning {
			r.phase = rescueDone
			r.finished = time.Now()
		}
		return nil
	}
	r.steps, r.current = m.ev.Steps, m.ev.Current
	if m.ev.Done {
		r.done, r.err = true, m.ev.Err
		r.phase = rescueDone
		r.finished = time.Now()
		r.scroll = 0
		switch {
		case m.ev.Err != nil:
			a.setStatus("etcd rescue FAILED: " + strutil.FirstLine(m.ev.Err.Error()))
		case r.plan.Rejoin:
			a.setStatus("etcd rescue finished: " + r.plan.Others[0].Name + " rejoined the cluster")
		default:
			a.setStatus("etcd rescue finished: cluster restored from " + r.plan.Snapshot)
		}
		a.overlay = ovRescue
	}
	return waitRescue(r.ch, r.seq)
}

// rescueHeader is the header-line state while a rescue runs.
func (a *App) rescueHeader() string {
	r := a.rescue
	if r == nil || r.phase != rescueRunning {
		return ""
	}
	if r.current >= 0 && r.current < len(r.steps) {
		s := r.steps[r.current]
		return fmt.Sprintf("etcd rescue %d/%d: %s on %s", r.current+1, len(r.steps), s.Title, s.Node)
	}
	return "etcd rescue running"
}

// renderRescue returns the overlay title and lines for the current phase.
func (a *App) renderRescue() (string, []string) {
	r := a.rescue
	if r == nil {
		return "", nil
	}
	w := a.width - 8
	var lines []string
	add := func(l ...string) { lines = append(lines, l...) }
	switch r.phase {
	case rescuePickMode:
		healthy, broken, unreachable := 0, 0, 0
		leader := ""
		for _, o := range r.nodes {
			switch {
			case !o.online:
				unreachable++
			case o.state == "healthy":
				healthy++
			default:
				broken++
			}
			if o.leader {
				leader = o.node.Name
			}
		}
		probing := 0
		for _, o := range r.nodes {
			if o.state == "probing..." {
				probing++
			}
		}
		line := fmt.Sprintf("%d control-plane node(s) known: %d healthy, %d reachable but not serving etcd, %d unreachable over SSH; live leader: %s", len(r.nodes), healthy, broken, unreachable-probing, strutil.FirstNonEmpty(leader, "-"))
		if probing > 0 {
			line += fmt.Sprintf("; %s %d still being probed (the recommendation updates when they answer)", a.spinner.View(), probing)
		}
		add(styleDim.Render(line), "")
		opts := []struct{ title, desc string }{
			{"Restore a snapshot onto the whole control plane", "quorum is lost or the data is bad: one node's snapshot becomes the only truth, every other server is wiped and rejoined. Everything written after the snapshot is lost."},
			{"Rejoin one server to the surviving cluster (no restore)", "quorum is fine, one member is broken: that server is stopped, its etcd data moved aside and it rejoins through a healthy member. Nothing else is touched, nothing is lost."},
		}
		for i, o := range opts {
			mark := "  "
			line := o.title
			if r.recommendRejoin() == (i == 1) {
				line += styleDim.Render("  (recommended for what khealth sees)")
			}
			if i == r.modeCur {
				mark = "> "
				add(selectRow(mark+line, w+2))
			} else {
				add(mark + line)
			}
			add(wrap(styleDim.Render("    "+o.desc), w)...)
			add("")
		}
		add(styleDim.Render("j/k choose, enter continues, esc cancels"))
		return "etcd rescue (" + string(r.kind) + ")", lines
	case rescuePickNode:
		if r.rejoin {
			add(styleWarn.Render("Rejoin one server.")+" "+styleDim.Render("Pick the broken member: it is stopped, its etcd data moved aside (kept), and it rejoins through the healthy leader. The healthy members are not touched."), "")
		} else {
			add(styleWarn.Render("Restore an etcd snapshot onto the whole control plane.")+" "+styleDim.Render("Pick the node to restore FROM: its snapshot becomes the cluster's only truth. The best source is preselected (online healthy leader, then the freshest raft state)."), "")
		}
		var rows [][]string
		for _, o := range r.nodes {
			role := styleDim.Render("member")
			switch {
			case o.leader:
				role = styleOK.Render("leader")
			case o.lastLeader:
				role = styleWarn.Render("last leader")
			}
			state := o.state
			switch state {
			case "healthy":
				state = styleOK.Render(state)
			case "unreachable", "UNHEALTHY":
				state = styleCrit.Render(state)
			case "probing...":
				state = a.spinner.View() + " " + styleDim.Render(state)
			default:
				state = styleDim.Render(state)
			}
			term := "-"
			if o.term > 0 {
				term = fmt.Sprint(o.term)
			}
			idx := "-"
			if o.index > 0 {
				idx = fmt.Sprint(o.index)
			}
			snaps := styleDim.Render("none")
			if o.snaps > 0 {
				snaps = fmt.Sprintf("%d, latest %s ago", o.snaps, age(o.latest))
			}
			member := strutil.FirstNonEmpty(o.member, "-")
			if o.memberID != "" {
				member += styleDim.Render(" " + o.memberID)
			}
			rows = append(rows, []string{o.node.Name, strutil.FirstNonEmpty(o.node.IP, "-"), state, role, member, term, idx, snaps, strutil.FirstNonEmpty(o.dist, "-")})
		}
		hdr, rl := renderTable(w, []column{{title: "NODE"}, {title: "IP"}, {title: "STATE"}, {title: "ROLE"}, {title: "MEMBER", max: 40}, {title: "LEADER TERM", right: true}, {title: "RAFT INDEX", right: true}, {title: "SNAPSHOTS ON NODE"}, {title: "DIST"}}, rows)
		add("  " + pad(hdr, w))
		for i, l := range rl {
			if i == r.nodeCur {
				add(selectRow("> "+l, w+2))
			} else {
				add("  " + pad(l, w))
			}
		}
		add("", styleDim.Render("MEMBER = name/id from the node's db and config (readable with etcd down); LEADER TERM = highest term the etcd logs show that member elected (\"last leader\" = highest of all); RAFT INDEX = on-disk WAL position"))
		if r.rejoin {
			add(styleDim.Render("j/k choose, enter runs the read-only preflight, esc goes back"))
			return "etcd rescue: choose the server to rejoin (" + string(r.kind) + ")", lines
		}
		add(styleDim.Render("j/k choose, enter lists the node's snapshots, esc goes back"))
		return "etcd rescue: choose the node to restore from (" + string(r.kind) + ")", lines
	case rescuePickSnap:
		o := r.nodes[r.nodeCur]
		add(styleDim.Render("Snapshots on ")+styleBold.Render(o.node.Name)+styleDim.Render(", newest first. The cluster returns to the state at that point in time; everything written since is lost."), "")
		var rows [][]string
		for _, s := range r.snaps {
			where := s.dir
			if s.s3 {
				where = styleInfo.Render("S3 ") + s.dir
			}
			ageTxt := age(s.when) + " ago"
			if time.Since(s.when) > a.cfg.Etcd.MaxBackupAge {
				ageTxt = styleWarn.Render(ageTxt)
			} else {
				ageTxt = styleOK.Render(ageTxt)
			}
			rows = append(rows, []string{s.name, ageTxt, s.when.Local().Format("2006-01-02 15:04"), humanBytes(float64(s.size)), where})
		}
		hdr, rl := renderTable(w, []column{{title: "SNAPSHOT", max: 60}, {title: "AGE", right: true}, {title: "TAKEN"}, {title: "SIZE", right: true}, {title: "WHERE", max: 50}}, rows)
		add("  " + pad(hdr, w))
		visible := a.bodyHeight() - 9
		start := 0
		if r.snapCur >= visible && visible > 0 {
			start = r.snapCur - visible + 1
		}
		for i := start; i < len(rl) && (visible <= 0 || i < start+visible); i++ {
			if i == r.snapCur {
				add(selectRow("> "+rl[i], w+2))
			} else {
				add("  " + pad(rl[i], w))
			}
		}
		add("", styleDim.Render("j/k choose, enter runs the read-only preflight on every server, esc goes back"))
		return "etcd rescue: choose the restore point on " + o.node.Name, lines
	case rescuePreflight:
		add("", "  "+a.spinner.View()+" checking every server over SSH (binaries, data dirs, free space, manifests, the snapshot file)...", "", styleDim.Render("  nothing is changed by the preflight; esc abandons the rescue"))
		return "etcd rescue: preflight", lines
	case rescueConfirm:
		return a.renderRescueConfirm(w)
	case rescueRunning, rescueDone:
		return a.renderRescueProgress(w)
	}
	return "", nil
}

func (a *App) renderRescueConfirm(w int) (string, []string) {
	r := a.rescue
	p := r.plan
	var lines []string
	add := func(l ...string) { lines = append(lines, l...) }
	if r.prefErr != "" {
		add(styleCrit.Render("Preflight failed on the target: "+r.prefErr), "", styleDim.Render("Fix that and start again (esc). Nothing was changed."))
		return "etcd rescue: cannot start", lines
	}
	t := p.Target
	if p.Rejoin {
		o := p.Others[0]
		add(kv("rejoin", styleBold.Render(o.Name)+" "+styleDim.Render(o.Host+", peer "+strutil.FirstNonEmpty(o.IP, "-"))))
		add(kv("through", styleBold.Render(t.Name)+" "+styleDim.Render(t.Host+" (healthy member; not touched)")))
		add(kv("data kept in", o.Facts.Rescue+" on "+o.Name))
		add("")
		add(styleCrit.Render("WARNING") + " " + styleWarn.Render("this stops "+p.Svc()+" on "+o.Name+", moves its etcd data aside and rejoins it; the cluster keeps serving from the other members meanwhile."))
		for _, wn := range p.Warnings {
			add(wrap(styleWarn.Render("- "+wn), w)...)
		}
		add("", styleBold.Render(fmt.Sprintf("Steps (%d)", len(p.Steps()))))
		for i, s := range p.Steps() {
			add(fmt.Sprintf("  %2d. %-6s %s", i+1, s.Node, s.Title))
		}
		return a.pinInput("etcd rescue: confirm rejoin", lines)
	}
	snapAge := ""
	if !t.Facts.SnapshotTime.IsZero() {
		snapAge = ", taken " + age(t.Facts.SnapshotTime) + " ago"
	} else if r.snapCur < len(r.snaps) && !r.snaps[r.snapCur].when.IsZero() {
		snapAge = ", taken " + age(r.snaps[r.snapCur].when) + " ago"
	}
	size := ""
	if t.Facts.SnapshotSize > 0 {
		size = " (" + humanBytes(float64(t.Facts.SnapshotSize)) + ")"
	}
	add(kv("restore from", styleBold.Render(t.Name)+" "+styleDim.Render(t.Host+", peer "+strutil.FirstNonEmpty(t.IP, "-"))))
	add(kv("snapshot", p.Snapshot+size+snapAge))
	var others []string
	for _, o := range p.Others {
		others = append(others, o.Name)
	}
	if len(others) == 0 {
		others = []string{"(none)"}
	}
	add(kv("rejoin afterward", strings.Join(others, ", ")))
	for _, s := range p.Skipped {
		add(kv("left out", styleCrit.Render(s.Name+": "+s.Facts.Err)))
	}
	add(kv("data kept in", t.Facts.Rescue+" on every node (owner "+strutil.FirstNonEmpty(t.Facts.Owner, "-")+", mode "+strutil.FirstNonEmpty(t.Facts.Mode, "-")+" is re-applied)"))
	add("")
	add(styleCrit.Render("WARNING") + " " + styleWarn.Render("this stops the control plane on every server, replaces the cluster state with the snapshot and rebuilds the members one by one."))
	add(wrap(styleWarn.Render("- everything written to the cluster after the snapshot is lost; the API is down for several minutes; workloads keep running but cannot be changed meanwhile"), w)...)
	add(wrap(styleWarn.Render("- do not run anything else against these nodes until it finishes; a failed step leaves the cluster where that step stopped (every node's previous data is kept)"), w)...)
	for _, wn := range p.Warnings {
		add(wrap(styleWarn.Render("- "+wn), w)...)
	}
	add("", styleBold.Render(fmt.Sprintf("Steps (%d)", len(p.Steps()))))
	for i, s := range p.Steps() {
		add(fmt.Sprintf("  %2d. %-6s %s", i+1, s.Node, s.Title))
	}
	return a.pinInput("etcd rescue: confirm", lines)
}

// pinInput lays out a confirmation: the text scrolls, the input and its
// hint stay pinned at the bottom.
func (a *App) pinInput(title string, body []string) (string, []string) {
	r := a.rescue
	visible := a.bodyHeight() - 5 // title, box borders, input, hint
	if visible < 3 {
		visible = 3
	}
	maxScroll := len(body) - visible
	if maxScroll < 0 {
		maxScroll = 0
	}
	if r.scroll > maxScroll {
		r.scroll = maxScroll
	}
	if r.scroll < 0 {
		r.scroll = 0
	}
	end := r.scroll + visible
	if end > len(body) {
		end = len(body)
	}
	hint := "enter begins once the word matches; esc cancels."
	if len(body) > visible {
		hint = fmt.Sprintf("lines %d-%d of %d: up/down, PgUp/PgDn, Home/End scroll. ", r.scroll+1, end, len(body)) + hint
	}
	return title, append(append([]string{}, body[r.scroll:end]...), r.input.View(), styleDim.Render(hint))
}

func (a *App) renderRescueProgress(w int) (string, []string) {
	r := a.rescue
	var lines []string
	add := func(l ...string) { lines = append(lines, l...) }
	end := r.finished
	if end.IsZero() {
		end = time.Now()
	}
	title := "etcd rescue: running"
	switch {
	case r.phase == rescueDone && r.err != nil:
		title = "etcd rescue: FAILED"
		add(styleCrit.Render("FAILED after " + strutil.HumanDur(end.Sub(r.started)) + ": " + r.err.Error()))
	case r.phase == rescueDone && r.plan.Rejoin:
		title = "etcd rescue: finished"
		add(styleOK.Render("finished in " + strutil.HumanDur(end.Sub(r.started)) + ": " + r.plan.Others[0].Name + " rejoined the cluster through " + r.plan.Target.Name))
	case r.phase == rescueDone:
		title = "etcd rescue: finished"
		add(styleOK.Render("finished in " + strutil.HumanDur(end.Sub(r.started)) + ": cluster restored from " + r.plan.Snapshot))
	default:
		add(a.spinner.View() + " " + styleWarn.Render("running for "+strutil.HumanDur(end.Sub(r.started))) + styleDim.Render("  esc hides this view (the rescue continues), x aborts after the step in progress"))
		if r.plan.Aborting() {
			add(styleWarn.Render("abort requested: stopping after the step in progress"))
		}
	}
	add("")
	for i, s := range r.steps {
		mark := styleDim.Render("·")
		switch s.State {
		case rescue.Running:
			mark = a.spinner.View()
		case rescue.Done:
			mark = styleOK.Render("✓")
		case rescue.Failed:
			mark = styleCrit.Render("✗")
		case rescue.Skipped:
			mark = styleDim.Render("-")
		}
		dur := ""
		if !s.Started.IsZero() {
			e := s.Finished
			if e.IsZero() {
				e = time.Now()
			}
			dur = styleDim.Render(" " + strutil.HumanDur(e.Sub(s.Started)))
		}
		line := fmt.Sprintf(" %s %2d. %-6s %s%s", mark, i+1, s.Node, s.Title, dur)
		if s.State == rescue.Running {
			line = styleBold.Render(line)
		} else if s.State == rescue.Skipped {
			line = styleDim.Render(line)
		}
		add(line)
		if s.State == rescue.Failed {
			add(wrap(styleCrit.Render("       "+s.Err), w)...)
		}
		// the running step shows its output; finished ones keep the last lines
		show := 0
		switch s.State {
		case rescue.Running:
			show = 8
		case rescue.Failed:
			show = 12
		case rescue.Done:
			show = 2
		}
		if show > 0 {
			logs := s.Log
			if len(logs) > show {
				logs = logs[len(logs)-show:]
			}
			for _, l := range logs {
				add(styleDim.Render("       " + trunc(l, w-8)))
			}
			if s.State == rescue.Running {
				for _, l := range s.Live {
					add(styleInfo.Render("       " + trunc(l, w-8)))
				}
			}
		}
	}
	if r.phase == rescueDone {
		add("", styleBold.Render("Afterward"))
		for _, n := range r.plan.Notes {
			add(wrap("  - "+n, w)...)
		}
		add("", styleDim.Render("esc closes and refreshes"))
	}
	visible := a.bodyHeight() - 3 // title, box borders, position line
	if visible < 3 {
		visible = 3
	}
	if len(lines) > visible {
		if r.phase == rescueRunning && !r.manual && r.current >= 0 {
			// follow the running step until the operator scrolls (f resumes):
			// keep the END of its block in view - its log and live output
			// hang below the title line and the newest lines are the last
			start, end := -1, -1
			for i, l := range lines {
				if start < 0 && strings.Contains(l, fmt.Sprintf(" %2d. ", r.current+1)) {
					start = i
					continue
				}
				if start >= 0 && strings.Contains(l, fmt.Sprintf(" %2d. ", r.current+2)) {
					end = i - 1
					break
				}
			}
			if start >= 0 {
				if end < 0 {
					end = len(lines) - 1
				}
				// one line of context below the block; a block longer than
				// the window scrolls its title off - the newest output matters
				r.scroll = end - visible + 2
			}
		}
		if r.scroll > len(lines)-visible {
			r.scroll = len(lines) - visible
		}
		if r.scroll < 0 {
			r.scroll = 0
		}
		end := r.scroll + visible
		pos := fmt.Sprintf("-- lines %d-%d of %d: j/k, PgUp/PgDn, g/G", r.scroll+1, end, len(lines))
		if r.phase == rescueRunning {
			if r.manual {
				pos += "; f follows the running step again"
			} else {
				pos += "; following the running step"
			}
		}
		lines = append(lines[r.scroll:end], styleDim.Render(pos+" --"))
	}
	return title, lines
}
