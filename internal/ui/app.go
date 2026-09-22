// Package ui implements the Bubble Tea terminal interface.
package ui

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/helmcheck"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/perf"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/stig"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

type tab int

const (
	tabOverview tab = iota
	tabNodes
	tabWorkloads
	tabEtcd
	tabStorage
	tabEvents
	tabAddons
	tabHelm
	tabImages
	tabSecurity
	tabLogs
	tabRKE2
	tabCount
)

var tabNames = [...]string{"Overview", "Nodes", "Inspect", "etcd", "Storage", "Events", "Addons", "Helm", "Images", "Security", "Logs", "RKE2"}
var tabKeys = [...]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "="}

// subTabs are second-level views of a tab (h/l switch). "Inspect" renders
// the object inspector in the body instead of an overlay.
var subTabs = map[tab][]string{
	tabWorkloads: {"Controllers", "Pods", "Resources", "Object"},
	tabEvents:    {"Events", "Object"},
	tabLogs:      {"Nodes", "Lines"},
	tabSecurity:  {"Rules", "Node hardening", "OS STIG"},
}

const subInspect = "Object"

type overlayKind int

const (
	ovNone overlayKind = iota
	ovHelp
	ovNamespace
	ovDetail
	ovConfirm
	ovScanPeek // esc on the running security scan: partial results?
	ovRevisions
	ovInspect
	ovPodLogs
	ovContext
	ovRescue
)

// row is one selectable/scrollable line of a tab.
type row struct {
	id   string
	text string
}

// content is what a tab renders.
type content struct {
	header     []string
	rows       []row
	selectable bool
	empty      string
	// centered draws the empty message in the middle of the body instead of
	// top-left (first load, opt-in tabs); sub goes under it, spin adds the
	// spinner while something is in flight
	centered bool
	spin     bool
	sub      []string
}

// App is the root model.
type App struct {
	cfg        config.Config
	client     *k8s.Client
	runner     *sshrun.Runner
	sshErr     string
	sshEnabled bool
	helm       *helmcheck.Checker

	width, height int
	tab           tab
	namespace     string

	snap       *k8s.Snapshot
	snapErr    string
	nodes      map[string]*nodeinfo.Info
	pending    map[string]bool
	collecting map[string]string // node -> tiers of the probe in flight (perf log, tab status lines)
	etcd       map[string]*etcd.Probe
	etcdPend   map[string]bool
	knownNodes []corev1.Node // last node list the API returned; used when the apiserver is down
	s3         *k8s.S3SecretInfo
	s3Reach    map[string]etcd.S3Check
	logSum     map[string]*logs.Summary
	stigRes    []stig.Result
	helmLatest map[string]helmcheck.Latest
	findings   []checks.Finding
	findingAge map[string]findingTrack // first/last seen per finding key (see findings.go)
	resolved   []resolvedFinding       // findings that went away, shown for resolvedKeep
	hist       map[string]*series

	// seq numbers one refresh: a stale tick or snapshot (a refresh that
	// was superseded by r / R / a context switch) is ignored. gen numbers the
	// cluster the app is attached to and only moves on a context switch:
	// node and etcd answers carry it, so a probe that straddles a refresh
	// tick still lands (a 20 s STIG probe or a slow node must not be thrown
	// away, and with it the node's pending flag).
	seq         int
	gen         int
	cycle       int
	heavyNext   bool
	refreshing  bool
	lastRefresh time.Time
	spinner     spinner.Model
	problemOnly bool
	hideManual  bool // Security: hide MANUAL rules (m)
	// secScanned: the Security tab is opt-in. Nothing is evaluated or shown
	// there until Shift+S runs a scan; after that the rules stay live.
	secScanned bool
	// stigDirty: an input of stig.Evaluate changed since it last ran (the
	// snapshot, a node's config or OS STIG facts, an etcd probe). A light
	// node probe answering does not set it, so the ~1,300 rules are not
	// re-evaluated for data they never read (ARCHITECTURE.md §7.4).
	stigDirty bool
	// scan is the current (or last) Shift+S security scan: the checklist the
	// tab shows until every node has answered
	scan *secScan

	// frame is the content of the current tab, rebuilt only when a message
	// may have changed it: building a tab (highlighting every log line,
	// measuring every table cell) costs tens of milliseconds on a busy
	// node's log view, and View runs on every spinner tick and keypress.
	frame  frameCache
	cursor [tabCount]int
	scroll [tabCount]int
	// the view was scrolled away from the cursor on purpose (k at the first
	// row to read the text above a table, j past the last row, g): clamp
	// leaves the scroll alone until the cursor moves again
	freeScroll [tabCount]bool
	filters    [tabCount]string
	filter     textinput.Model
	filterOn   bool

	overlay      overlayKind
	nsInput      textinput.Model
	nsCursor     int
	ctxList      []k8s.ContextInfo // context picker (c)
	ctxCursor    int
	detailTitle  string
	detailRaw    []string // the detail as produced: long lines intact
	detailLines  []string // detailRaw laid out for the overlay (wrapped when detailWrap)
	detailWrap   bool     // w in the overlay; remembered for the session
	detailFind   textFind // / in the overlay
	inspectFind  textFind // / in the inspector (YAML and the rest of the page)
	detailScroll int
	status       string
	statusAt     time.Time
	logsNode     string // Logs tab: node whose lines are listed ("" = node list)
	logsAll      bool   // Logs tab: show info lines too

	pendingAct    *action
	revRelease    *k8s.HelmRelease
	revCursor     int
	actionRunning bool
	rescue        *rescueView // etcd snapshot restore in progress (X on the etcd tab)

	// apiserver failover: the kubeconfig's server is down, another control
	// plane node's apiserver is used instead (same kubeconfig CA and user)
	apiOverride string          // server URL in use when not the kubeconfig's
	apiTried    map[string]bool // hosts tried since the API was last seen
	apiTrying   bool

	logs        *logView
	inspect     []inspectLevel
	inspectSeq  int
	crdCounts   []k8s.CRDInfo
	crdCounting bool
	etcdExec    *etcd.Probe
	wlPods      bool
	sub         [tabCount]int // active sub-tab per tab

	fp footprint // the tool's own cost per cycle (P overlay, --perf-log)
}

// tabName is the label of a tab. The distribution tab is named after what
// was detected: RKE2, k3s, kubeadm (API endpoint / kubeadm-config) or Config
// until the distribution is known.
func (a *App) tabName(t tab) string {
	if t != tabRKE2 {
		return tabNames[t]
	}
	if a.snap == nil {
		return "Config"
	}
	if d := a.snap.Distribution; d != "" && d != "unknown" {
		return distro.For(d).Label
	}
	return "Config"
}

// subName returns the active sub-tab name ("" when the tab has none).
func (a *App) subName() string {
	st := subTabs[a.tab]
	if len(st) == 0 {
		return ""
	}
	if a.tab == tabLogs {
		if a.logsNode != "" {
			return "Lines"
		}
		return "Nodes"
	}
	i := a.sub[a.tab]
	if i < 0 || i >= len(st) {
		i = 0
	}
	return st[i]
}

// onCRDs reports whether the CRDs sub-tab is showing.
func (a *App) onCRDs() bool { return a.tab == tabWorkloads && a.subName() == "Resources" }

// inInspect reports whether the body currently shows the inspector.
func (a *App) inInspect() bool { return a.subName() == subInspect }

// showInspect switches to the tab's Inspect sub-tab, or opens the overlay
// when the tab has none.
func (a *App) showInspect() {
	a.inspectFind.clear() // a new page: the find belongs to the page it was typed on
	for i, n := range subTabs[a.tab] {
		if n == subInspect {
			a.sub[a.tab] = i
			a.overlay = ovNone
			return
		}
	}
	a.overlay = ovInspect
}

// setSub changes the sub-tab by delta (h/l).
func (a *App) setSub(delta int) {
	st := subTabs[a.tab]
	if len(st) == 0 {
		return
	}
	if a.tab == tabLogs {
		if delta > 0 && a.logsNode == "" {
			if id := a.selectedID(); id != "" {
				a.logsNode = id
				a.cursor[a.tab], a.scroll[a.tab], a.filters[a.tab] = 0, 0, ""
			}
		} else if delta < 0 {
			a.logsNode = ""
			a.cursor[a.tab], a.scroll[a.tab] = 0, 0
		}
		return
	}
	n := (a.sub[a.tab] + delta + len(st)) % len(st)
	a.sub[a.tab] = n
	a.wlPods = a.tab == tabWorkloads && st[n] == "Pods"
	a.cursor[a.tab], a.scroll[a.tab] = 0, 0
}

type snapshotMsg struct {
	seq  int
	snap *k8s.Snapshot
}
type nodeMsg struct {
	gen    int
	info   *nodeinfo.Info
	opts   nodeinfo.Options // what the probe included (cost accounting)
	logSum *logs.Summary    // the journal classified, when this probe carried one (heavy)
}
type etcdMsg struct {
	gen   int
	probe *etcd.Probe
}
type s3Msg struct{ info *k8s.S3SecretInfo }

type s3CheckMsg struct {
	gen   int
	check etcd.S3Check
}
type helmMsg struct{ latest map[string]helmcheck.Latest }
type etcdExecMsg struct {
	gen   int
	probe *etcd.Probe
}
type tickMsg struct{ seq int }

// frameCache holds the last built content of a tab and the rows the filter
// left of it. It is served again only while the frame is "hot": nothing
// but spinner ticks and cursor keys arrived since it was built (Update
// clears hot on every other message) and it is under a second old, so
// "N s ago" texts still move.
type frameCache struct {
	hot    bool
	valid  bool
	tab    tab
	sub    int
	width  int
	height int
	at     time.Time
	c      content
	filter string
	rows   []row
	rowsOK bool
}

// cursorKeys are the keys that only move the cursor / scroll a view: the
// tab's content is the same before and after them.
var cursorKeys = map[string]bool{"j": true, "k": true, "up": true, "down": true, "pgup": true, "pgdown": true, "home": true, "end": true, "g": true, "G": true, "ctrl+u": true, "ctrl+d": true}

// frameHot reports whether msg leaves the current tab's content as it was:
// a spinner tick, or a key that only moves the cursor / scroll of a view.
func (a *App) frameHot(msg tea.Msg) bool {
	switch m := msg.(type) {
	case spinner.TickMsg:
		return true
	case tea.KeyMsg:
		return cursorKeys[m.String()] && a.overlay == ovNone && !a.filterOn
	}
	return false
}

// apiFailoverMsg is the outcome of trying other control-plane apiservers.
type apiFailoverMsg struct {
	seq    int
	client *k8s.Client
	server string
	tried  []string
	err    string
}

// New creates the application model.
func New(cfg config.Config) (*App, error) {
	client, err := k8s.NewWithOptions(cfg.Kubeconfig, cfg.Context, k8s.Options{
		WatchCache: cfg.Perf.WatchCache, Protobuf: cfg.Perf.Protobuf, DiscoveryTTL: cfg.Perf.DiscoveryTTL, ConfigzTTL: cfg.Perf.ConfigzTTL, DeniedTTL: cfg.Perf.DeniedTTL,
	})
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg:        cfg,
		client:     client,
		namespace:  cfg.Namespace,
		nodes:      map[string]*nodeinfo.Info{},
		pending:    map[string]bool{},
		collecting: map[string]string{},
		etcd:       map[string]*etcd.Probe{},
		etcdPend:   map[string]bool{},
		s3Reach:    map[string]etcd.S3Check{},
		logSum:     map[string]*logs.Summary{},
		helmLatest: map[string]helmcheck.Latest{},
		heavyNext:  true,
		fp:         newFootprint(),
	}
	if cfg.Perf.Log != "" {
		l, err := perf.OpenLogger(cfg.Perf.Log)
		if err != nil {
			return nil, fmt.Errorf("perf log: %w", err)
		}
		a.fp.logger = l
	}
	if cfg.SSH.Enabled {
		r, err := sshrun.New(cfg.SSH)
		if err != nil {
			a.sshErr = err.Error()
		} else {
			a.runner = r
			a.sshEnabled = true
		}
	}
	if cfg.Helm.CheckUpdates {
		a.helm = helmcheck.New(cfg.Helm)
	}
	a.spinner = spinner.New(spinner.WithSpinner(spinner.MiniDot))
	a.filter = textinput.New()
	a.filter.Prompt = "/"
	a.filter.CharLimit = 64
	a.nsInput = textinput.New()
	a.nsInput.Prompt = "namespace> "
	a.nsInput.Placeholder = "type to filter, Enter to select, Esc to cancel"
	a.nsInput.CharLimit = 64
	return a, nil
}

// Init starts the first refresh.
func (a *App) Init() tea.Cmd {
	return tea.Batch(a.spinner.Tick, a.refreshCmd())
}

func (a *App) refreshCmd() tea.Cmd {
	a.seq++
	a.refreshing = true
	seq := a.seq
	client := a.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		return snapshotMsg{seq: seq, snap: client.Fetch(ctx)}
	}
}

func (a *App) tickCmd() tea.Cmd {
	seq := a.seq
	return tea.Tick(a.cfg.Refresh, func(time.Time) tea.Msg { return tickMsg{seq: seq} })
}

func (a *App) nodeAddress(n *corev1.Node) string {
	if h, ok := a.cfg.SSH.Hosts[n.Name]; ok && h != "" {
		return h
	}
	return k8s.NodeAddress(n, a.cfg.SSH.Address)
}

func (a *App) collectCmds(snap *k8s.Snapshot) tea.Cmd {
	if !a.sshEnabled || a.runner == nil || snap == nil {
		return nil
	}
	// R, SSH re-enabled and the first cycle force every tier; otherwise the
	// tiers the visible tab (or collect.always) wants and the background
	// floor decide per node (collect.go)
	force := a.heavyNext
	a.heavyNext = false
	full := force || a.cycle%a.cfg.HeavyEvery == 0 // the etcd probe's own slow sections
	want := a.wanted()
	var cmds []tea.Cmd
	gen := a.gen
	runner := a.runner
	timeout := 3 * a.cfg.SSH.Timeout
	only := map[string]bool{}
	for _, n := range a.cfg.SSH.Nodes {
		only[n] = true
	}
	pvPaths := pvPathsOf(snap)
	// apiserver down (power outage, quorum lost): keep probing the nodes we
	// knew, or the ssh.hosts map, and run the etcd probe on all of them
	nodes, offline := a.sshTargets(snap)
	anyTier := false
	// etcdctl over SSH is the fallback for the kubectl-exec probe: skip the
	// three crictl execs per cycle while that probe answers and the API is up
	etcdScript := etcd.Script(a.cfg.Etcd, full, offline || a.etcdExec == nil || a.etcdExec.Err != nil)
	for i := range nodes {
		n := &nodes[i]
		if len(only) > 0 && !only[n.Name] {
			continue
		}
		host := a.nodeAddress(n)
		name := n.Name
		if a.skipProbe(name) != "" {
			continue
		}
		// The OS STIG facts (sysctl -a, package lists, find scans, config
		// dumps) are the most expensive part and never ride on a refresh: they
		// are the Shift+S scan's own staged probes (stigStageCmd).
		journal, images, pvs, config := a.nodeTiers(a.nodes[name], want, force)
		opts := a.nodeOptions(snap, name, pvPaths, journal, images, pvs, config)
		t := timeout
		if opts.Heavy() {
			t = 6 * a.cfg.SSH.Timeout
			anyTier = true
		}
		a.collecting[name] = opts.Tiers()
		cmds = append(cmds, a.nodeProbeCmd(name, host, opts, t))
		if offline || k8s.IsEtcdNode(nodes, n) {
			a.etcdPend[name] = true
			script := etcdScript
			cmds = append(cmds, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				res := runner.Run(ctx, host, script)
				p := etcd.Parse(name, res.Stdout)
				p.Duration = res.Finished.Sub(res.Started)
				p.ScriptSize = res.ScriptSize
				p.Stderr = strings.TrimSpace(res.Stderr)
				if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
					p.Err = fmt.Errorf("%s", strutil.FirstLine(res.Err.Error()+" "+res.Stderr))
				}
				return etcdMsg{gen: gen, probe: p}
			})
		}
	}
	if a.fp.cur != nil {
		a.fp.cur.Heavy = anyTier
	}
	return tea.Batch(cmds...)
}

// nodeProbeCmd runs one node probe script and delivers its nodeMsg.
// probeNodeNow runs the light node probe and the etcd probe on one node
// right away (after its address was changed in the rescue picker) instead
// of on the next refresh tick; the results arrive like any other probe's.
func (a *App) probeNodeNow(name string) tea.Cmd {
	if a.runner == nil || a.snap == nil {
		return nil
	}
	nodes, offline := a.sshTargets(a.snap)
	var n *corev1.Node
	for i := range nodes {
		if nodes[i].Name == name {
			n = &nodes[i]
		}
	}
	if n == nil {
		return nil
	}
	host := a.nodeAddress(n)
	runner, gen, timeout := a.runner, a.gen, 3*a.cfg.SSH.Timeout
	opts := a.nodeOptions(a.snap, name, pvPathsOf(a.snap), false, false, false, false)
	a.collecting[name] = opts.Tiers()
	cmds := []tea.Cmd{a.nodeProbeCmd(name, host, opts, timeout)}
	if offline || k8s.IsEtcdNode(nodes, n) {
		a.etcdPend[name] = true
		script := etcd.Script(a.cfg.Etcd, false, true)
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res := runner.Run(ctx, host, script)
			p := etcd.Parse(name, res.Stdout)
			p.Duration = res.Finished.Sub(res.Started)
			p.ScriptSize = res.ScriptSize
			p.Stderr = strings.TrimSpace(res.Stderr)
			if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
				p.Err = fmt.Errorf("%s", strutil.FirstLine(res.Err.Error()+" "+res.Stderr))
			}
			return etcdMsg{gen: gen, probe: p}
		})
	}
	return tea.Batch(cmds...)
}

func (a *App) nodeProbeCmd(name, host string, opts nodeinfo.Options, timeout time.Duration) tea.Cmd {
	gen, runner := a.gen, a.runner
	a.pending[name] = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res := runner.Run(ctx, host, nodeinfo.Script(opts))
		info := nodeinfo.Parse(name, host, res.Stdout, res.Started)
		info.HostKey = res.HostKey
		info.Duration = res.Finished.Sub(res.Started)
		info.ScriptSize = res.ScriptSize
		info.STIGRun = opts.OSStig
		if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
			msg := res.Err.Error()
			if s := strings.TrimSpace(res.Stderr); s != "" {
				msg += ": " + strutil.FirstLine(s)
			}
			info.Err = fmt.Errorf("%s", msg)
		}
		// classify the journal here, off the UI loop: ~0.5 ms per line through
		// the knowledge base, and it only changes when a heavy probe lands
		return nodeMsg{gen: gen, info: info, opts: opts, logSum: classifyLogs(info)}
	}
}

// secScan is one Shift+S security scan. The OS STIG facts are the slow
// part: every node runs the collection stages (nodeinfo.STIGStages) one
// after the other, each its own SSH script, and the tab shows a checklist
// with per-node progress until the last node has answered. The stages are
// the scan's own probes - they do not ride on the refresh cycle, so a
// pending regular probe, the backoff or a refresh tick never hold them up.
type secScan struct {
	started time.Time
	nodes   []string                  // targets, in order
	hosts   map[string]string         // node -> ssh address
	want    map[string]bool           // nodes that still owe stages
	failed  map[string]string         // node -> error of the stage that failed
	stage   map[string]int            // node -> stages finished
	facts   map[string]*nodeinfo.Info // node -> facts merged so far (adopted by the node's Info when complete)
	took    map[string]time.Duration  // node -> wall time of the finished stages
	doneAt  map[string]time.Time      // node -> when its last stage landed
	at      map[string]time.Time      // node -> when the running stage started
	stages  []nodeinfo.STIGStage
	peek    bool // esc + enter: show the partial results while it runs
}

func newSecScan(nodes []string, hosts map[string]string) *secScan {
	sc := &secScan{started: time.Now(), nodes: nodes, hosts: hosts, want: map[string]bool{}, failed: map[string]string{},
		stage: map[string]int{}, facts: map[string]*nodeinfo.Info{}, took: map[string]time.Duration{}, at: map[string]time.Time{}, doneAt: map[string]time.Time{}, stages: nodeinfo.STIGStages()}
	for _, n := range nodes {
		sc.want[n] = true
		sc.facts[n] = &nodeinfo.Info{Node: n, Host: hosts[n]}
	}
	return sc
}

// running reports whether any node still owes its facts.
func (sc *secScan) running() bool { return sc != nil && len(sc.want) > 0 }

// done is the number of nodes that have answered.
func (sc *secScan) done() int { return len(sc.nodes) - len(sc.want) }

// complete reports whether a node's facts are all in.
func (sc *secScan) complete(n string) bool {
	return sc != nil && sc.failed[n] == "" && sc.stage[n] >= len(sc.stages) && sc.facts[n] != nil
}

// percent is the scan's overall progress: stages finished over stages
// planned (a failed node counts as finished - it will not progress).
func (sc *secScan) percent() int {
	if sc == nil || len(sc.nodes) == 0 || len(sc.stages) == 0 {
		return 0
	}
	done := 0
	for _, n := range sc.nodes {
		if sc.failed[n] != "" {
			done += len(sc.stages)
		} else {
			done += sc.stage[n]
		}
	}
	return 100 * done / (len(sc.nodes) * len(sc.stages))
}

// stigStageMsg is one finished stage of one node.
type stigStageMsg struct {
	gen   int
	node  string
	stage string
	out   string
	err   error
	dur   time.Duration
	size  int
}

// startScan opts the Security tab in and, with SSH, starts the first
// collection stage on every target node.
func (a *App) startScan() tea.Cmd {
	a.secScanned = true
	a.stigDirty = true
	if a.runner == nil || !a.sshEnabled {
		a.scan = nil
		a.recompute() // no node facts to wait for: the rules show at once
		a.setStatus("security scan: STIG/CIS rules from the API only - SSH is disabled, no node facts")
		return nil
	}
	nodes, _ := a.sshTargets(a.snap)
	only := map[string]bool{}
	for _, n := range a.cfg.SSH.Nodes {
		only[n] = true
	}
	var names []string
	hosts := map[string]string{}
	for i := range nodes {
		n := &nodes[i]
		if len(only) == 0 || only[n.Name] {
			names = append(names, n.Name)
			hosts[n.Name] = a.nodeAddress(n)
		}
	}
	sc := newSecScan(names, hosts)
	a.scan = sc
	a.setStatus(fmt.Sprintf("security scan started on %d node(s)", len(names)))
	cmds := []tea.Cmd{a.scheduleRecompute()}
	for _, n := range names {
		cmds = append(cmds, a.stigStageCmd(n, 0))
	}
	return tea.Batch(cmds...)
}

// stigStageCmd runs stage idx of the OS STIG collection on a node.
func (a *App) stigStageCmd(name string, idx int) tea.Cmd {
	sc := a.scan
	if sc == nil || idx >= len(sc.stages) || a.runner == nil {
		return nil
	}
	st := sc.stages[idx]
	gen, runner, host := a.gen, a.runner, sc.hosts[name]
	timeout := 3 * a.cfg.SSH.Timeout
	if st.Slow {
		timeout = 6 * a.cfg.SSH.Timeout
	}
	script := nodeinfo.STIGStageScript(st.Name)
	sc.at[name] = time.Now()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res := runner.Run(ctx, host, script)
		m := stigStageMsg{gen: gen, node: name, stage: st.Name, out: res.Stdout, dur: res.Finished.Sub(res.Started), size: res.ScriptSize}
		if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
			msg := res.Err.Error()
			if s := strings.TrimSpace(res.Stderr); s != "" {
				msg += ": " + strutil.FirstLine(s)
			}
			m.err = fmt.Errorf("%s", msg)
		}
		return m
	}
}

// handleStage merges a finished stage into the node's facts and starts the
// next one; the last stage hands the facts to the node's Info and, once
// every node is in, the tab switches to the results.
func (a *App) handleStage(m stigStageMsg) tea.Cmd {
	sc := a.scan
	if sc == nil || !sc.want[m.node] {
		return nil
	}
	sc.took[m.node] += m.dur
	rec := perf.ProbeRecord{Node: m.node, Kind: "stig:" + m.stage, WallMS: m.dur.Milliseconds(), OutBytes: len(m.out), ScriptSize: m.size}
	if m.err != nil {
		rec.Err = m.err.Error()
		a.addProbe(rec)
		sc.failed[m.node] = m.stage + ": " + m.err.Error()
		delete(sc.want, m.node)
		return a.scanSettled()
	}
	cost := nodeinfo.ParseSTIGStage(sc.facts[m.node], m.out)
	rec.RemoteCPU, rec.RemoteUser, rec.RemoteSys, rec.Load1 = cost.CPU(), cost.User, cost.Sys, cost.Load1
	a.addProbe(rec)
	sc.stage[m.node]++
	if sc.stage[m.node] < len(sc.stages) {
		return a.stigStageCmd(m.node, sc.stage[m.node])
	}
	delete(sc.want, m.node)
	sc.doneAt[m.node] = time.Now()
	a.adoptSTIG(m.node)
	return a.scanSettled()
}

// scanSettled is what follows a node answering: the status line when it
// was the last one, and the rules re-evaluated either way.
func (a *App) scanSettled() tea.Cmd {
	if sc := a.scan; !sc.running() {
		a.setStatus(fmt.Sprintf("security scan finished: %d node(s), %d failed", len(sc.nodes), len(sc.failed)))
	}
	return a.scheduleRecompute()
}

// adoptSTIG hands a node's completed scan facts to its Info. Called when
// the last stage lands and again with every regular probe answer, so a
// node whose Info was replaced (or missing) while the scan ran still gets
// them.
func (a *App) adoptSTIG(name string) {
	sc := a.scan
	ni := a.nodes[name]
	if ni == nil || !sc.complete(name) || (ni.STIGProbed && !ni.STIGCollected.Before(sc.started)) {
		return
	}
	ni.AdoptSTIG(sc.facts[name], sc.doneAt[name])
	a.stigDirty = true
}

// apiFailoverCmd tries the apiserver of other control-plane nodes when
// the current one cannot be reached: the peers the etcd probes found on
// disk (healthy etcd members first), the last node list, ssh.hosts. Each
// host is tried once until the API is seen again.
func (a *App) apiFailoverCmd() tea.Cmd {
	if a.snap == nil || len(a.snap.Nodes) > 0 || a.apiTrying || !k8s.Unreachable(a.snap.Errors) {
		return nil
	}
	cur, _ := url.Parse(a.client.Host)
	port := "6443"
	if cur != nil && cur.Port() != "" {
		port = cur.Port()
	}
	curHost := ""
	if cur != nil {
		curHost = cur.Hostname()
	}
	var hosts []string
	seen := map[string]bool{curHost: true}
	add := func(h string) {
		if h == "" || seen[h] || a.apiTried[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	// etcd-healthy servers first: their apiserver is the most likely to answer
	for _, pass := range []bool{true, false} {
		for _, n := range strutil.SortedKeys(a.etcd) {
			p := a.etcd[n]
			healthy := p.Err == nil && p.Health != nil && p.Health.Healthy
			if healthy != pass {
				continue
			}
			for _, pr := range p.Peers {
				add(pr.Host)
			}
		}
	}
	for i := range a.knownNodes {
		n := &a.knownNodes[i]
		if k8s.IsControlPlane(n) {
			add(a.nodeIP(n))
		}
	}
	for _, h := range strutil.SortedKeys(a.cfg.SSH.Hosts) {
		hp := a.cfg.SSH.Hosts[h]
		if x, _, err := net.SplitHostPort(hp); err == nil {
			hp = x
		}
		add(hp)
	}
	if len(hosts) == 0 {
		return nil
	}
	a.apiTrying = true
	seq, kubeconfig, ctxName, opts := a.seq, a.cfg.Kubeconfig, a.client.Context, a.client.Opts
	return func() tea.Msg {
		var tried []string
		lastErr := ""
		for _, h := range hosts {
			server := "https://" + net.JoinHostPort(h, port)
			tried = append(tried, h)
			o := opts
			o.Server = server
			c, err := k8s.NewWithOptions(kubeconfig, ctxName, o)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			_, err = c.Ping(ctx)
			cancel()
			if err != nil {
				lastErr = server + ": " + strutil.FirstLine(err.Error())
				continue
			}
			return apiFailoverMsg{seq: seq, client: c, server: server, tried: tried}
		}
		return apiFailoverMsg{seq: seq, tried: tried, err: lastErr}
	}
}

// sshTargets returns the nodes to collect from. When the API returned no
// nodes (apiserver/etcd down) it falls back to the last good list, then to
// the ssh.hosts map, and reports offline=true so every host gets the etcd
// probe (roles are unknown).
func (a *App) sshTargets(snap *k8s.Snapshot) ([]corev1.Node, bool) {
	if len(snap.Nodes) > 0 {
		return snap.Nodes, false
	}
	var out []corev1.Node
	if len(a.knownNodes) > 0 {
		out = append(out, a.knownNodes...)
	} else {
		for _, name := range strutil.SortedKeys(a.cfg.SSH.Hosts) {
			out = append(out, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}})
		}
	}
	return a.withPeers(out), true
}

// withPeers adds the cluster members the etcd probes found on disk (the
// members bucket of a node's db, its initial-cluster) that no node in the
// list covers yet: with the apiserver down, one reachable server is enough
// to learn the whole control plane and probe it over its peer addresses.
func (a *App) withPeers(nodes []corev1.Node) []corev1.Node {
	seen := map[string]bool{}
	for i := range nodes {
		seen[a.nodeAddress(&nodes[i])] = true
		seen[nodes[i].Name] = true
		for _, ad := range nodes[i].Status.Addresses {
			seen[ad.Address] = true
		}
	}
	for _, n := range strutil.SortedKeys(a.etcd) {
		for _, pr := range a.etcd[n].Peers {
			name := pr.NodeName()
			if name == "" {
				name = pr.Host
			}
			if pr.Host == "" || seen[pr.Host] || seen[name] {
				continue
			}
			seen[pr.Host], seen[name] = true, true
			nodes = append(nodes, corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node-role.kubernetes.io/etcd": "true", "node-role.kubernetes.io/control-plane": "true"}},
				Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: pr.Host}}},
			})
		}
	}
	return nodes
}

// etcdExecCmd runs etcdctl inside an etcd static pod through the API
// (kubectl exec equivalent). Tries pods in order until one answers.
func (a *App) etcdExecCmd(snap *k8s.Snapshot) tea.Cmd {
	if snap == nil {
		return nil
	}
	pods := snap.EtcdPods()
	if len(pods) == 0 {
		return nil
	}
	gen := a.gen
	client := a.client
	dist := snap.Distribution
	// encryption-at-rest sample: once, then only on R (heavyNext)
	var prevEnc *etcd.Encryption
	if a.etcdExec != nil {
		prevEnc = a.etcdExec.Encryption
	}
	sampleEnc := prevEnc == nil || prevEnc.SamplePrefix == "" || a.heavyNext
	names := strutil.SortedKeys(pods)
	podNames := map[string]string{}
	for _, n := range names {
		podNames[n] = pods[n].Name
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var last *etcd.Probe
		if err, denied := client.Denied("pods/exec"); denied {
			// pods/exec refused earlier: do not exec into every etcd pod again
			return etcdExecMsg{gen: gen, probe: &etcd.Probe{Node: names[0], Collected: time.Now(), Dist: dist, Err: err, EtcdctlDiag: err.Error()}}
		}
		for _, n := range names {
			p := etcd.ExecProbeOpts(ctx, client, n, podNames[n], dist, sampleEnc)
			last = p
			if p.Err == nil && len(p.Members) > 0 {
				break
			}
			if client.NoteDenied("pods/exec", p.Err, false) {
				break
			}
		}
		if last != nil && last.Encryption == nil && prevEnc != nil {
			last.Encryption = prevEnc // sampled earlier; the value does not change
		}
		return etcdExecMsg{gen: gen, probe: last}
	}
}

func (a *App) helmCmd(snap *k8s.Snapshot) tea.Cmd {
	if a.helm == nil || snap == nil || len(snap.HelmReleases) == 0 {
		return nil
	}
	var rels []helmcheck.Release
	for _, r := range snap.HelmReleases {
		if r.Chart == "" {
			continue
		}
		repo := r.ChartRepo
		if i := strings.Index(repo, " "); i >= 0 { // "repo chart" as recorded by the HelmChart CR
			repo = repo[:i]
		}
		rels = append(rels, helmcheck.Release{Key: helmKey(r), Chart: r.Chart, Repo: repo, Home: r.Home, Sources: r.Sources})
	}
	h := a.helm
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return helmMsg{latest: h.Lookup(ctx, rels)}
	}
}

// helmKey identifies a release in helmLatest.
func helmKey(r k8s.HelmRelease) string { return r.Namespace + "/" + r.Name }

func (a *App) s3Cmd(name string) tea.Cmd {
	client := a.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return s3Msg{info: client.S3Secret(ctx, name)}
	}
}

// s3CheckCmd tests the snapshot S3 endpoint from one etcd node with the CA
// and TLS settings that node would use. Runs when the node's S3 config is
// known: after its etcd probe, and again once the config secret is read.
func (a *App) s3CheckCmd(node string) tea.Cmd {
	p := a.etcd[node]
	if p == nil || p.Err != nil || a.runner == nil || !a.sshEnabled {
		return nil
	}
	c := checks.S3ConfigFor(p, a.s3)
	if !c.Enabled || (c.SecretName != "" && !c.SecretFound) {
		return nil
	}
	var n *corev1.Node
	targets, _ := a.sshTargets(a.snap)
	for i := range targets {
		if targets[i].Name == node {
			n = &targets[i]
		}
	}
	if n == nil {
		return nil
	}
	host := a.nodeAddress(n)
	url := c.URL()
	script := etcd.S3CheckScript(url, c.CAFile, c.CAPEM, c.SkipSSLVerify)
	runner, gen, timeout := a.runner, a.gen, a.cfg.SSH.Timeout
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res := runner.Run(ctx, host, script)
		out := res.Stdout
		if res.Err != nil && strings.TrimSpace(out) == "" {
			out = "ssh: " + strutil.FirstLine(res.Err.Error())
		}
		return s3CheckMsg{gen: gen, check: etcd.ParseS3Check(node, url, out)}
	}
}

// recompute re-derives what is shown from the collected data: the STIG
// evaluation, the checks and the finding history. Log classification is
// not part of it: a journal is classified once, in the probe goroutine
// that fetched it (classifyLogs), because it costs ~0.5 ms per line and
// only changes when a heavy probe lands.
func (a *App) recompute() {
	if !a.secScanned {
		a.stigRes = nil
	} else if a.stigDirty || a.stigRes == nil {
		a.stigRes = stig.Evaluate(stig.Input{Snap: a.snap, Nodes: a.nodes, Etcd: a.etcd, EtcdExec: a.etcdExec})
		a.stigDirty = false
	}
	a.findings = checks.Evaluate(checks.Input{
		Snap: a.snap, Nodes: a.nodes, Etcd: a.etcd, EtcdExec: a.etcdExec, S3: a.s3, S3Reach: a.s3Reach, Logs: a.logSum, Stig: a.stigRes,
		HelmLatest: a.helmLatest, SSHEnabled: a.sshEnabled, SSHErr: a.sshErr, Cfg: a.cfg, Now: time.Now(), APIServer: a.apiServer(),
	})
	a.trackFindings(time.Now())
}

// apiServer is the kubeconfig server URL ("" without a client, as in tests).
func (a *App) apiServer() string {
	if a.client == nil {
		return ""
	}
	return a.client.Host
}

// recordSnapshot appends cluster-level series points after an API refresh.
func (a *App) recordSnapshot() {
	s := a.snap
	if s == nil {
		return
	}
	running, pending, failed, unhealthy := 0, 0, 0, 0
	for i := range s.Pods {
		switch s.Pods[i].Status.Phase {
		case corev1.PodRunning:
			running++
		case corev1.PodPending:
			pending++
		case corev1.PodFailed:
			failed++
		}
		if !k8s.PodHealthy(&s.Pods[i]) && s.Pods[i].Status.Phase != corev1.PodSucceeded {
			unhealthy++
		}
	}
	ready := 0
	for i := range s.Nodes {
		if k8s.NodeReady(&s.Nodes[i]) {
			ready++
		}
	}
	a.record("pods.running", float64(running))
	a.record("pods.pending", float64(pending))
	a.record("pods.failed", float64(failed))
	a.record("pods.unhealthy", float64(unhealthy))
	a.record("nodes.ready", float64(ready))
	a.record("nodes.total", float64(len(s.Nodes)))
	a.record("events.warn", float64(len(s.WarningEvents())))
	crit, warn := 0, 0
	for _, f := range a.findings {
		switch f.Severity {
		case checks.SevCrit:
			crit++
		case checks.SevWarn:
			warn++
		}
	}
	a.record("findings.crit", float64(crit))
	a.record("findings.warn", float64(warn))
	cpu, mem, disk := a.clusterUsage()
	a.record("cluster.cpu", cpu)
	a.record("cluster.mem", mem)
	a.record("cluster.disk", disk)
}

// clusterUsage averages CPU/memory (SSH first, metrics-server fallback) and
// returns the worst filesystem usage across nodes. NaN when unknown.
func (a *App) clusterUsage() (cpu, mem, disk float64) {
	var cpus, mems, disks []float64
	for i := range a.snap.Nodes {
		n := &a.snap.Nodes[i]
		if ni, ok := a.nodes[n.Name]; ok && ni.Err == nil {
			if ni.CPUPct >= 0 {
				cpus = append(cpus, ni.CPUPct)
			}
			mems = append(mems, ni.MemPct)
			for _, m := range ni.Mounts {
				disks = append(disks, float64(m.UsePct))
			}
			continue
		}
		if m, ok := a.snap.NodeMetrics[n.Name]; ok {
			if alloc := k8s.QuantityMilli(n.Status.Allocatable, corev1.ResourceCPU); alloc > 0 {
				cpus = append(cpus, float64(m.CPUMilli)*100/float64(alloc))
			}
			if alloc := k8s.QuantityValue(n.Status.Allocatable, corev1.ResourceMemory); alloc > 0 {
				mems = append(mems, float64(m.MemBytes)*100/float64(alloc))
			}
		}
	}
	return avg(cpus), avg(mems), maxOf(disks)
}

func (a *App) recordNode(ni *nodeinfo.Info) {
	if ni == nil || ni.Err != nil {
		return
	}
	a.record("node.cpu:"+ni.Node, ni.CPUPct)
	a.record("node.mem:"+ni.Node, ni.MemPct)
	if ni.CPUs > 0 {
		a.record("node.load:"+ni.Node, ni.Load1/float64(ni.CPUs)*100)
	}
	if m := ni.MountFor("/"); m != nil {
		a.record("node.root:"+ni.Node, float64(m.UsePct))
	}
}

func (a *App) recordEtcd(p *etcd.Probe) {
	if p == nil || p.Err != nil || p.Metrics == nil {
		return
	}
	m := p.Metrics
	if m.Quota > 0 {
		a.record("etcd.db:"+p.Node, m.DBSize/m.Quota*100)
	}
	a.record("etcd.dbsize:"+p.Node, m.DBSize)
	a.record("etcd.fsync:"+p.Node, m.WalFsyncAvgMs)
	a.record("etcd.commit:"+p.Node, m.BackendCommitAvgMs)
	if m.DBSize > 0 {
		a.record("etcd.frag:"+p.Node, (m.DBSize-m.DBSizeInUse)/m.DBSize*100)
	}
}

func (a *App) setStatus(s string) {
	a.status = s
	a.statusAt = time.Now()
}

// Update handles messages.
// Update handles a message; afterwards the frame cache is hot only when
// the message could not have changed the tab (see frameCache).
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	model, cmd := a.update(msg)
	a.frame.hot = a.frameHot(msg)
	return model, cmd
}

func (a *App) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		if a.overlay == ovDetail && a.detailWrap {
			a.layoutDetail()
		}
		return a, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spinner, cmd = a.spinner.Update(m)
		return a, cmd
	case tickMsg:
		if m.seq == a.seq && !a.refreshing {
			return a, a.refreshCmd()
		}
		return a, nil
	case snapshotMsg:
		if m.seq != a.seq {
			return a, nil
		}
		a.snap = m.snap
		a.refreshing = false
		a.lastRefresh = time.Now()
		a.stigDirty = true
		a.cycle++
		a.beginCycle(a.heavyNext)
		// drop nodes that no longer exist - only when the API actually
		// answered; an empty list during an outage must not erase what we know
		if len(a.snap.Nodes) > 0 {
			a.knownNodes = a.snap.Nodes
			names := map[string]bool{}
			for i := range a.snap.Nodes {
				names[a.snap.Nodes[i].Name] = true
			}
			for n := range a.nodes {
				if !names[n] {
					delete(a.nodes, n)
					delete(a.etcd, n)
					delete(a.logSum, n)
				}
			}
		}
		a.crdCounts = nil
		a.crdCounting = false
		if len(a.snap.Nodes) > 0 {
			a.apiTried = nil // the API answers: forget the failover attempts
		}
		a.timedRecompute()
		a.recordSnapshot()
		if a.fp.logger != nil && a.status == "" {
			if s := a.perfSummary(); s != "" {
				a.setStatus(s)
			}
		}
		var crdCmd, execCmd tea.Cmd
		if a.onCRDs() {
			crdCmd = a.crdCountCmd()
		}
		if a.etcdExecWanted(a.snap) {
			execCmd = a.etcdExecCmd(a.snap)
		}
		return a, tea.Batch(a.collectCmds(a.snap), a.helmCmd(a.snap), execCmd, crdCmd, a.apiFailoverCmd(), a.tickCmd())
	case apiFailoverMsg:
		a.apiTrying = false
		if m.seq != a.seq {
			return a, nil
		}
		if a.apiTried == nil {
			a.apiTried = map[string]bool{}
		}
		for _, h := range m.tried {
			a.apiTried[h] = true
		}
		if m.client == nil {
			if m.err != "" {
				a.setStatus("apiserver " + a.client.Host + " unreachable; no other control-plane apiserver answered: " + m.err)
			}
			return a, nil
		}
		a.client = m.client
		a.apiOverride = m.server
		a.client.ResetDenied()
		a.setStatus("apiserver unreachable: switched to " + m.server + " (another control-plane node, same kubeconfig)")
		if !a.refreshing {
			return a, a.refreshCmd()
		}
		return a, nil
	case nodeMsg:
		if m.gen != a.gen {
			return a, nil
		}
		m.info.CPUFromPrev(a.nodes[m.info.Node])
		m.info.MergeTiers(a.nodes[m.info.Node])
		m.info.MergeSTIG(a.nodes[m.info.Node])
		m.info.MergeConfig(a.nodes[m.info.Node])
		a.nodes[m.info.Node] = m.info
		if m.opts.Config && m.info.ControlPlane {
			// the PSA config's exempt namespaces are this deployment's own
			// list of infrastructure namespaces (IsSystemNamespace)
			if psa := a.psaConfig(); psa != nil {
				k8s.SetExemptNamespaces(psa.ExemptNamespaces)
			}
		}
		if m.logSum != nil {
			a.logSum[m.info.Node] = m.logSum
		}
		delete(a.pending, m.info.Node)
		delete(a.collecting, m.info.Node)
		if m.opts.Config || m.opts.OSStig || m.info.Err != nil {
			a.stigDirty = true
		}
		a.adoptSTIG(m.info.Node)
		a.recordNodeProbe(m.info, m.opts)
		a.noteProbeDuration(m.info.Node, m.info.Duration)
		a.recordNode(m.info)
		return a, a.scheduleRecompute()
	case stigStageMsg:
		if m.gen != a.gen {
			return a, nil
		}
		return a, a.handleStage(m)
	case etcdMsg:
		if m.gen != a.gen {
			return a, nil
		}
		m.probe.Merge(a.etcd[m.probe.Node])
		a.etcd[m.probe.Node] = m.probe
		a.stigDirty = true
		delete(a.etcdPend, m.probe.Node)
		a.rescueRefresh()
		a.recordEtcdProbe(m.probe)
		a.noteProbeDuration(m.probe.Node, m.probe.Duration)
		a.recordEtcd(m.probe)
		// peers found on this node's disk are apiserver candidates: try them
		// now rather than on the next refresh tick
		failover := a.apiFailoverCmd()
		if name := m.probe.RKE2Config["etcd-s3-config-secret"]; name != "" && (a.s3 == nil || a.s3.Name != name) {
			return a, tea.Batch(a.scheduleRecompute(), a.s3Cmd(name), failover)
		}
		return a, tea.Batch(a.scheduleRecompute(), a.s3CheckCmd(m.probe.Node), failover)
	case s3Msg:
		a.s3 = m.info
		cmds := []tea.Cmd{a.scheduleRecompute()}
		for _, n := range strutil.SortedKeys(a.etcd) {
			cmds = append(cmds, a.s3CheckCmd(n))
		}
		return a, tea.Batch(cmds...)
	case s3CheckMsg:
		if m.gen == a.gen {
			a.s3Reach[m.check.Node] = m.check
			return a, a.scheduleRecompute()
		}
		return a, nil
	case helmMsg:
		a.helmLatest = m.latest
		return a, a.scheduleRecompute()
	case actionDoneMsg:
		return a, a.handleActionDone(m)
	case rescuePreflightMsg:
		return a, a.handleRescuePreflight(m)
	case rescueMsg:
		return a, a.handleRescueMsg(m)
	case etcdExecMsg:
		if m.gen != a.gen {
			return a, nil
		}
		a.etcdExec = m.probe
		a.stigDirty = true
		return a, a.scheduleRecompute()
	case recomputeMsg:
		a.fp.recomputeTimer = false
		a.timedRecompute()
		return a, nil
	case inspectMsg:
		a.handleInspectMsg(m)
		return a, nil
	case logMsg:
		return a, a.handleLogMsg(m)
	case crdCountMsg:
		a.crdCounting = false
		if m.seq == a.seq {
			a.crdCounts = m.crds
		}
		return a, nil
	case tea.KeyMsg:
		return a.handleKey(m)
	}
	return a, nil
}

// handleKey is Update for one key (tests call it directly). Afterwards the
// frame cache is hot only for a cursor key.
func (a *App) handleKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()
	if key == "ctrl+c" {
		return a, tea.Quit
	}
	before := a.viewSignature()
	model, cmd := a.handleKeyInner(m)
	a.frame.hot = a.frameHot(m)
	if a.viewSignature() != before {
		// An overlay opened or closed, or the inspector changed depth: the
		// frame shape changed, repaint from scratch so no stale rows
		// survive on any terminal. Tab and sub-tab switches deliberately do
		// not: the renderer erases every changed line to its end and the
		// frame is always exactly height lines (fitScreen), and the clear
		// lands after the new frame was flushed - a blank screen and a
		// second full paint on every switch, which reads as lag on wide,
		// heavily colored tabs like Security.
		cmd = tea.Batch(cmd, tea.ClearScreen)
	}
	return model, cmd
}

// viewSignature identifies the shape of the current view: the overlay and
// the inspector depth. Tabs, sub-tabs and the logs node are not part of it
// (see handleKey).
func (a *App) viewSignature() string {
	return fmt.Sprintf("%d|%d", len(a.inspect), a.overlay)
}

func (a *App) handleKeyInner(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()
	if a.overlay != ovNone {
		return a.handleOverlayKey(m)
	}
	if a.filterOn {
		switch key {
		case "esc":
			a.filterOn = false
			a.filter.SetValue("")
			a.filters[a.tab] = ""
			a.filter.Blur()
		case "enter":
			a.filterOn = false
			a.filter.Blur()
		default:
			var cmd tea.Cmd
			a.filter, cmd = a.filter.Update(m)
			a.filters[a.tab] = a.filter.Value()
			a.cursor[a.tab], a.scroll[a.tab], a.freeScroll[a.tab] = 0, 0, false
			return a, cmd
		}
		return a, nil
	}
	if a.inInspect() && a.inspectFind.typing {
		return a.handleInspectKey(key) // digits and - = are query text, not tab keys
	}
	for i, k := range tabKeys {
		if key == k {
			a.tab = tab(i)
			return a, a.onEnter()
		}
	}
	if a.inInspect() {
		switch key {
		case "esc", "backspace", "q", "j", "k", "down", "up", "enter", "J", "K", "pgdown", "pgup", " ", "ctrl+d", "ctrl+u", "g", "G", "home", "end", "/", "n", "N":
			// q steps back out of the inspector like esc; it only quits from a top-level view
			return a.handleInspectKey(key)
		}
	}
	if key == "q" && a.tab == tabLogs && a.logsNode != "" {
		a.logsNode = ""
		a.cursor[a.tab], a.scroll[a.tab] = 0, 0
		return a, nil
	}
	if a.tab == tabWorkloads && a.snap != nil && key == "L" {
		ns, pod, siblings, ok := a.podForLogs()
		if !ok {
			a.setStatus("select a pod, or a Deployment/DaemonSet/StatefulSet/Job with running pods, to tail logs")
			return a, nil
		}
		return a, a.openPodLogs(ns, pod, siblings)
	}
	if a.tab == tabWorkloads && a.snap != nil {
		switch key {
		case "p":
			if a.wlPods {
				a.sub[a.tab] = 0
			} else {
				a.sub[a.tab] = 1
			}
			a.wlPods = !a.wlPods
			a.cursor[a.tab], a.scroll[a.tab] = 0, 0
			return a, nil
		case "t":
			if a.actionRunning {
				a.setStatus("an action is still running")
				return a, nil
			}
			a.startRolloutRestart()
			return a, nil
		}
	}
	if a.tab == tabEtcd && key == "X" {
		return a, a.openRescue()
	}
	if a.tab == tabEtcd && key == "D" {
		if a.actionRunning {
			a.setStatus("an action is still running")
			return a, nil
		}
		a.startEtcdDefrag()
		return a, nil
	}
	if a.tab == tabHelm && a.snap != nil {
		switch key {
		case "u":
			if a.actionRunning {
				a.setStatus("an action is still running")
				return a, nil
			}
			a.startHelmUpgrade()
			return a, nil
		case "b":
			if a.actionRunning {
				a.setStatus("an action is still running")
				return a, nil
			}
			a.startHelmRollback()
			return a, nil
		case "B":
			if a.actionRunning {
				a.setStatus("an action is still running")
				return a, nil
			}
			a.startHelmRollbackLastGood()
			return a, nil
		}
	}
	switch key {
	case "q":
		if r := a.rescue; r != nil && r.phase == rescueRunning {
			a.setStatus("an etcd rescue is running: X shows it, x there aborts after the current step; ctrl+c quits regardless (the step in progress is cut off)")
			return a, nil
		}
		a.closePodLogs()
		a.endCycle()
		a.fp.logger.Close()
		return a, tea.Quit
	case "P":
		a.setDetail("Footprint: what khealth costs the cluster and this host", a.perfLines())
	case "e":
		a.exportReport()
	case "tab", "]":
		a.tab = (a.tab + 1) % tabCount
		return a, a.onEnter()
	case "shift+tab", "[":
		a.tab = (a.tab + tabCount - 1) % tabCount
		return a, a.onEnter()
	case "l", "right":
		a.setSub(1)
		return a, a.onEnter()
	case "h", "left":
		a.setSub(-1)
		return a, a.onEnter()
	case "n":
		a.overlay = ovNamespace
		a.nsInput.SetValue("")
		a.nsCursor = 0
		return a, a.nsInput.Focus()
	case "C":
		a.ctxList = k8s.Contexts(a.cfg.Kubeconfig, a.client.Context)
		a.ctxCursor = 0
		a.overlay = ovContext
		return a, nil
	case "r":
		if !a.refreshing {
			a.setStatus("refreshing")
			return a, a.refreshCmd()
		}
	case "R":
		a.heavyNext = true
		a.client.ResetDenied() // retry the API calls that were refused
		if !a.refreshing {
			a.setStatus("full refresh (every tier: journal, images, PV usage, config, tarballs)")
			return a, a.refreshCmd()
		}
	case "S":
		// The security scan is explicit and only from the Security tab: it
		// evaluates the STIG/CIS rules and, with SSH, collects the OS STIG
		// facts from every node (the expensive part)
		if a.tab != tabSecurity {
			a.setStatus("Shift+S runs the security scan from the Security tab (0)")
			break
		}
		switch {
		case a.snap == nil:
			a.setStatus("waiting for the first API snapshot")
		case a.scan.running():
			a.setStatus(fmt.Sprintf("security scan already running: %d%%, %d/%d nodes done", a.scan.percent(), a.scan.done(), len(a.scan.nodes)))
		default:
			return a, a.startScan()
		}
	case "s":
		if a.runner == nil {
			a.setStatus("SSH unavailable: " + a.sshErr)
		} else {
			a.sshEnabled = !a.sshEnabled
			if a.sshEnabled {
				a.setStatus("SSH collection enabled")
				a.heavyNext = true
				return a, a.collectCmds(a.snap)
			}
			a.setStatus("SSH collection disabled")
		}
	case "a":
		if a.tab == tabLogs && a.logsNode != "" {
			a.logsAll = !a.logsAll
		}
		a.problemOnly = !a.problemOnly
		a.cursor[a.tab], a.scroll[a.tab], a.freeScroll[a.tab] = 0, 0, false
	case "m":
		if a.tab == tabSecurity {
			a.hideManual = !a.hideManual
			a.cursor[a.tab], a.scroll[a.tab], a.freeScroll[a.tab] = 0, 0, false
		}
	case "/":
		a.filterOn = true
		a.filter.SetValue(a.filters[a.tab])
		return a, a.filter.Focus()
	case "esc":
		// leaving the scan checklist early: warn that the rules are partial
		if a.tab == tabSecurity && a.scan.running() && !a.scan.peek && a.filters[a.tab] == "" {
			a.overlay = ovScanPeek
			return a, nil
		}
		if a.tab == tabLogs && a.logsNode != "" && a.filters[a.tab] == "" {
			a.logsNode = ""
			a.cursor[a.tab], a.scroll[a.tab] = 0, 0
			return a, nil
		}
		a.filters[a.tab] = ""
	case "?":
		// help uses the scrollable detail overlay (j/k, PgUp/PgDn, esc)
		a.setDetail("Help", helpLines(a.width-4))
	case "enter":
		if a.tab == tabLogs && a.logsNode == "" {
			if id := a.selectedID(); id != "" {
				a.logsNode = id
				a.cursor[a.tab], a.scroll[a.tab], a.filters[a.tab] = 0, 0, ""
			}
			return a, nil
		}
		if a.tab == tabWorkloads && a.snap != nil {
			if a.onCRDs() {
				return a, a.openCRDInstances(a.selectedID())
			}
			a.openWorkload(a.selectedID())
			return a, nil
		}
		if a.tab == tabEvents && a.snap != nil {
			a.openEvent(a.selectedID())
			return a, nil
		}
		a.openDetail()
	case "j", "down":
		a.move(1)
	case "k", "up":
		a.move(-1)
	case "g", "home":
		// the top of the page, text above the first row included; the cursor
		// sits on the first row even when that is below the fold
		a.cursor[a.tab] = 0
		a.scroll[a.tab] = 0
		a.freeScroll[a.tab] = true
		a.clamp(a.currentContent())
	case "G", "end":
		a.cursor[a.tab] = 1 << 30
		a.scroll[a.tab] = 1 << 30
		a.freeScroll[a.tab] = false
		a.clamp(a.currentContent())
	case "pgdown", "ctrl+d", " ":
		a.move(a.bodyHeight() - 2)
	case "pgup", "ctrl+u":
		a.move(-(a.bodyHeight() - 2))
	}
	return a, nil
}

func (a *App) move(delta int) {
	c := a.currentContent()
	if !c.selectable {
		a.scroll[a.tab] += delta
		a.clamp(c)
		return
	}
	rows := a.filteredRows(c)
	// the cursor is off screen (a fresh page shows its top, the cursor sits
	// on the first row below the fold): scroll the page toward it line by
	// line instead of leaping to the next row
	if a.freeScroll[a.tab] {
		visible := a.bodyHeight() - len(c.header)
		cur := a.cursor[a.tab]
		if cur < a.scroll[a.tab] || cur >= a.scroll[a.tab]+visible {
			a.scroll[a.tab] += delta
			a.clamp(c)
			return
		}
	}
	target := a.cursor[a.tab] + delta
	if target < 0 {
		target = 0
	}
	if target >= len(rows) {
		target = len(rows) - 1
	}
	dir := 1
	if delta < 0 {
		dir = -1
	}
	// headings and blank lines carry no id: land on the next real row in the
	// direction of travel
	for i := target; i >= 0 && i < len(rows); i += dir {
		if rows[i].id != "" {
			if i != a.cursor[a.tab] {
				a.cursor[a.tab] = i
				a.freeScroll[a.tab] = false
			}
			a.clamp(c)
			return
		}
	}
	// no row that way: scroll the page instead, so the text above the first
	// table row (or below the last) can be read; the cursor stays where it is
	a.scroll[a.tab] += delta
	a.freeScroll[a.tab] = true
	a.clamp(c)
}

func (a *App) clamp(c content) {
	rows := a.filteredRows(c)
	if len(rows) == 0 {
		a.cursor[a.tab], a.scroll[a.tab] = 0, 0
		return
	}
	visible := a.bodyHeight() - len(c.header)
	if visible < 1 {
		visible = 1
	}
	if c.selectable {
		if a.cursor[a.tab] < 0 {
			a.cursor[a.tab] = 0
		}
		if a.cursor[a.tab] >= len(rows) {
			a.cursor[a.tab] = len(rows) - 1
		}
		if rows[a.cursor[a.tab]].id == "" {
			// a fresh page (cursor and scroll at 0): the cursor takes the first
			// real row but the view stays at the top, so the text above the
			// first table is what you see first, not the last lines before it
			fresh := a.cursor[a.tab] == 0 && a.scroll[a.tab] == 0
			a.cursor[a.tab] = nearestRow(rows, a.cursor[a.tab])
			if fresh {
				a.freeScroll[a.tab] = true
			}
		}
		if a.freeScroll[a.tab] {
			// page scrolling with the cursor pinned at an edge: keep the scroll
			// inside the content, the cursor may be off screen
			if maxScroll := len(rows) - visible; a.scroll[a.tab] > maxScroll {
				a.scroll[a.tab] = maxScroll
			}
		} else {
			if a.cursor[a.tab] < a.scroll[a.tab] {
				a.scroll[a.tab] = a.cursor[a.tab]
			}
			if a.cursor[a.tab] >= a.scroll[a.tab]+visible {
				a.scroll[a.tab] = a.cursor[a.tab] - visible + 1
			}
		}
	} else {
		maxScroll := len(rows) - visible
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.scroll[a.tab] > maxScroll {
			a.scroll[a.tab] = maxScroll
		}
	}
	if a.scroll[a.tab] < 0 {
		a.scroll[a.tab] = 0
	}
}

// nearestRow returns the index of the closest row with an id (a selectable
// row), preferring the ones after i; i itself when none has an id.
func nearestRow(rows []row, i int) int {
	for j := i; j < len(rows); j++ {
		if rows[j].id != "" {
			return j
		}
	}
	for j := i - 1; j >= 0; j-- {
		if rows[j].id != "" {
			return j
		}
	}
	return i
}

func (a *App) handleOverlayKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()
	// tab switching is disabled while a modal view is open: say so instead
	// of silently swallowing the key (pod logs use tab/[ ] for containers)
	if a.overlay != ovPodLogs && a.overlay != ovNamespace && a.overlay != ovRescue && !(a.overlay == ovDetail && a.detailFind.typing) {
		switch key {
		case "tab", "shift+tab", "[", "]", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "left", "right", "h", "l":
			if a.overlay != ovInspect || key == "tab" || key == "shift+tab" {
				a.setStatus("this view is modal: press esc to close it, then tab / arrows switch tabs again")
				return a, nil
			}
		}
	}
	switch a.overlay {
	case ovConfirm, ovRevisions:
		return a.handleActionOverlayKey(key)
	case ovScanPeek:
		if key == "enter" && a.scan != nil {
			a.scan.peek = true
			a.setStatus("showing partial results - the scan keeps running")
		}
		a.overlay = ovNone
		return a, nil
	case ovInspect:
		return a.handleInspectKey(key)
	case ovPodLogs:
		return a.handleLogKey(key)
	case ovRescue:
		return a.handleRescueKey(m)
	case ovContext:
		switch key {
		case "esc", "q", "C":
			a.overlay = ovNone
		case "j", "down":
			if a.ctxCursor < len(a.ctxList)-1 {
				a.ctxCursor++
			}
		case "k", "up":
			if a.ctxCursor > 0 {
				a.ctxCursor--
			}
		case "enter":
			a.overlay = ovNone
			if a.ctxCursor >= 0 && a.ctxCursor < len(a.ctxList) {
				return a, a.switchContext(a.ctxList[a.ctxCursor])
			}
		}
	case ovNamespace:
		switch key {
		case "esc":
			a.overlay = ovNone
			a.nsInput.Blur()
		case "enter":
			opts := a.nsOptions()
			if a.nsCursor >= 0 && a.nsCursor < len(opts) {
				ns := opts[a.nsCursor]
				if ns == "(all namespaces)" {
					ns = ""
				}
				a.namespace = ns
				for t := range a.cursor {
					a.cursor[t], a.scroll[t], a.freeScroll[t] = 0, 0, false
				}
			}
			a.overlay = ovNone
			a.nsInput.Blur()
		case "down", "ctrl+n":
			a.nsCursor++
			if n := len(a.nsOptions()); a.nsCursor >= n {
				a.nsCursor = n - 1
			}
		case "up", "ctrl+p":
			if a.nsCursor > 0 {
				a.nsCursor--
			}
		default:
			var cmd tea.Cmd
			a.nsInput, cmd = a.nsInput.Update(m)
			a.nsCursor = 0
			return a, cmd
		}
	case ovDetail:
		visible := a.height - 6
		if consumed, changed := a.detailFind.handleKey(key); consumed {
			if changed {
				a.detailFind.run(a.detailLines, a.detailScroll)
				if h, ok := a.detailFind.current(); ok {
					a.detailScroll = jumpScroll(h, visible, len(a.detailLines)-visible)
				}
			}
			return a, nil
		}
		switch key {
		case "/":
			a.detailFind = textFind{typing: true}
			return a, nil
		case "n", "N":
			d := 1
			if key == "N" {
				d = -1
			}
			if h, ok := a.detailFind.step(d); ok {
				a.detailScroll = jumpScroll(h, visible, len(a.detailLines)-visible)
			} else if a.detailFind.query == "" {
				a.setStatus("/ finds text in this view first; n/N then jump between the hits")
			}
		case "esc":
			if a.detailFind.active() {
				a.detailFind.clear()
			} else {
				a.overlay = ovNone
			}
		case "q", "enter":
			a.overlay = ovNone
		case "j", "down":
			a.detailScroll++
		case "k", "up":
			a.detailScroll--
		case "pgdown", " ", "ctrl+d":
			a.detailScroll += visible
		case "pgup", "ctrl+u":
			a.detailScroll -= visible
		case "g", "home":
			a.detailScroll = 0
		case "G", "end":
			a.detailScroll = len(a.detailLines)
		case "w":
			a.detailWrap = !a.detailWrap
			a.layoutDetail()
		}
		if a.detailScroll > len(a.detailLines)-visible {
			a.detailScroll = len(a.detailLines) - visible
		}
		if a.detailScroll < 0 {
			a.detailScroll = 0
		}
	default:
		a.overlay = ovNone
	}
	return a, nil
}

// switchContext points the app at another cluster: a new API client, every
// cached result dropped (in-flight results of the old cluster are ignored
// by their sequence number) and a first-contact refresh cycle.
func (a *App) switchContext(c k8s.ContextInfo) tea.Cmd {
	kubeconfig := a.cfg.Kubeconfig
	if c.File != "" {
		kubeconfig = c.File
	}
	client, err := k8s.NewWithOptions(kubeconfig, c.Name, k8s.Options{
		WatchCache: a.cfg.Perf.WatchCache, Protobuf: a.cfg.Perf.Protobuf, DiscoveryTTL: a.cfg.Perf.DiscoveryTTL, ConfigzTTL: a.cfg.Perf.ConfigzTTL, DeniedTTL: a.cfg.Perf.DeniedTTL,
	})
	if err != nil {
		a.setStatus("context " + c.Name + ": " + err.Error())
		return nil
	}
	a.closePodLogs()
	a.client = client
	a.apiOverride, a.apiTried, a.apiTrying = "", nil, false
	a.cfg.Kubeconfig, a.cfg.Context = kubeconfig, c.Name
	a.snap, a.snapErr, a.knownNodes = nil, "", nil
	a.nodes, a.pending = map[string]*nodeinfo.Info{}, map[string]bool{}
	a.scan, a.secScanned = nil, false
	a.etcd, a.etcdPend, a.etcdExec = map[string]*etcd.Probe{}, map[string]bool{}, nil
	a.s3, a.s3Reach = nil, map[string]etcd.S3Check{}
	a.logSum, a.stigRes, a.helmLatest, a.findings = map[string]*logs.Summary{}, nil, map[string]helmcheck.Latest{}, nil
	a.findingAge, a.resolved = nil, nil
	a.hist, a.crdCounts, a.inspect = nil, nil, nil
	a.logsNode, a.namespace = "", ""
	for t := range a.cursor {
		a.cursor[t], a.scroll[t], a.filters[t], a.freeScroll[t] = 0, 0, "", false
	}
	if a.cfg.SSH.Enabled {
		// the cluster remembers how its nodes were reached (khealth context
		// extension); flags typed at startup still win
		if h := c.SSH; !h.Empty() {
			if h.User != "" && !a.cfg.Flags["ssh-user"] {
				a.cfg.SSH.User = h.User
			}
			if h.Key != "" && !a.cfg.Flags["ssh-key"] {
				a.cfg.SSH.Key = h.Key
			}
			if h.Port != 0 && !a.cfg.Flags["ssh-port"] {
				a.cfg.SSH.Port = h.Port
			}
			if h.Become != "" && !a.cfg.Flags["become"] {
				a.cfg.SSH.Become = h.Become
			}
			a.cfg.SSH.Hosts = nil // the previous cluster's fallback host is not this cluster's
			a.cfg.SSH.AddFallbackHost(h.Host)
		}
		// the runner caches connections per host; the new cluster has its own
		if a.runner != nil {
			a.runner.Close()
		}
		if r, err := sshrun.New(a.cfg.SSH); err == nil {
			a.runner, a.sshEnabled, a.sshErr = r, true, ""
		} else {
			a.runner, a.sshEnabled, a.sshErr = nil, false, err.Error()
		}
	}
	a.heavyNext, a.cycle, a.refreshing = true, 0, false
	a.seq++
	a.gen++ // answers from the previous cluster's probes are not this one's
	a.setStatus("switched to context " + c.Name + " (" + c.Server + ")")
	return a.refreshCmd()
}

func (a *App) nsOptions() []string {
	q := strings.ToLower(a.nsInput.Value())
	opts := []string{"(all namespaces)"}
	if a.snap != nil {
		for _, ns := range a.snap.Namespaces {
			if q == "" || strings.Contains(strings.ToLower(ns.Name), q) {
				opts = append(opts, ns.Name)
			}
		}
	}
	return opts
}

// nsRow describes a namespace for the picker: PSA level (label, else the
// admission config cfg's default) and privileged pods.
func (a *App) nsRow(name string, cfg *nodeinfo.PSAConfig) []string {
	if name == "(all namespaces)" || a.snap == nil {
		return []string{name, "", "", "", ""}
	}
	var labels map[string]string
	for i := range a.snap.Namespaces {
		if a.snap.Namespaces[i].Name == name {
			labels = a.snap.Namespaces[i].Labels
		}
	}
	enforce := labels["pod-security.kubernetes.io/enforce"]
	exempt := cfg != nil && cfg.Exempt(name)
	psa := ""
	switch {
	case exempt:
		// exemptions.namespaces skips admission entirely, labels or not
		psa = styleWarn.Render("privileged (exempt in " + shortPath(cfg.Path) + ")")
	case enforce == "privileged":
		psa = styleWarn.Render("privileged")
	case enforce == "baseline":
		psa = styleInfo.Render("baseline")
	case enforce == "restricted":
		psa = styleOK.Render("restricted")
	case enforce == "" && cfg != nil && cfg.External == "":
		lvl := cfg.EnforceLevel()
		st := styleWarn
		if lvl == "baseline" {
			st = styleInfo
		} else if lvl == "restricted" {
			st = styleOK
		}
		psa = st.Render(lvl) + styleDim.Render(" (cluster default)")
	case enforce == "":
		psa = styleDim.Render("none (cluster default)")
	default:
		psa = enforce
	}
	extra := []string{}
	if v := labels["pod-security.kubernetes.io/warn"]; v != "" && v != enforce {
		extra = append(extra, "warn="+v)
	}
	if v := labels["pod-security.kubernetes.io/audit"]; v != "" && v != enforce {
		extra = append(extra, "audit="+v)
	}
	if len(extra) > 0 {
		psa += styleDim.Render(" [" + strings.Join(extra, " ") + "]")
	}
	pods, priv, hostNS := 0, 0, 0
	for i := range a.snap.Pods {
		p := &a.snap.Pods[i]
		if p.Namespace != name || p.Status.Phase != corev1.PodRunning {
			continue
		}
		pods++
		isPriv := false
		for _, c := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				isPriv = true
			}
		}
		if isPriv {
			priv++
		}
		if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
			hostNS++
		}
	}
	privTxt := styleDim.Render("0")
	if priv > 0 || hostNS > 0 {
		privTxt = styleWarn.Render(fmt.Sprintf("%d privileged, %d host-ns", priv, hostNS))
	}
	note := ""
	switch {
	case exempt && !k8s.IsKnownSystemNamespace(name):
		note = styleWarn.Render("user namespace exempt from PSA")
	case exempt:
		note = styleDim.Render("system, exempt")
	case enforce == "" && (priv > 0 || hostNS > 0) && !k8s.IsSystemNamespace(name) && (cfg == nil || cfg.EnforceLevel() == "privileged"):
		note = styleWarn.Render("privileged workloads without a PSA policy")
	case enforce == "restricted" && (priv > 0 || hostNS > 0):
		note = styleCrit.Render("privileged pods despite restricted (pre-existing or exempt)")
	case k8s.IsSystemNamespace(name):
		note = styleDim.Render("system")
	}
	return []string{name, psa, privTxt, fmt.Sprint(pods), note}
}

// psaConfig is the PodSecurity admission config the apiserver runs with,
// once a server node's config tier has read the file (nil before).
func (a *App) psaConfig() *nodeinfo.PSAConfig {
	if a.snap == nil {
		return nil
	}
	paths := map[string]string{}
	for n, f := range k8s.ComponentArgs(a.snap.Pods, "kube-apiserver") {
		paths[n] = f["admission-control-config-file"]
	}
	return nodeinfo.EffectivePSA(a.nodes, paths)
}

func (a *App) bodyHeight() int {
	h := a.height - 5 // header, tab strip, rule, status line, footer
	if len(subTabs[a.tab]) > 0 {
		h-- // sub-tab strip
	}
	if h < 3 {
		h = 3
	}
	return h
}

func (a *App) currentContent() content {
	fc := &a.frame
	if fc.hot && fc.valid && fc.tab == a.tab && fc.sub == a.sub[a.tab] && fc.width == a.width && fc.height == a.height && time.Since(fc.at) < time.Second {
		return fc.c
	}
	c := a.buildContent()
	*fc = frameCache{hot: fc.hot, valid: true, tab: a.tab, sub: a.sub[a.tab], width: a.width, height: a.height, at: time.Now(), c: c}
	return c
}

// buildContent renders the current tab from the data (uncached).
func (a *App) buildContent() content {
	if a.snap == nil {
		c := content{empty: "loading cluster state...", centered: true, spin: true}
		if a.client != nil {
			where := a.client.Host
			if a.client.Context != "" {
				where = a.client.Context + "  " + styleDim.Render(where)
			}
			c.sub = []string{where}
		}
		return c
	}
	switch a.tab {
	case tabOverview:
		return a.overviewContent()
	case tabNodes:
		return a.nodesContent()
	case tabWorkloads:
		return a.workloadsContent()
	case tabEtcd:
		return a.etcdContent()
	case tabStorage:
		return a.storageContent()
	case tabEvents:
		return a.eventsContent()
	case tabAddons:
		return a.addonsContent()
	case tabHelm:
		return a.helmContent()
	case tabImages:
		return a.imagesContent()
	case tabSecurity:
		return a.securityContent()
	case tabLogs:
		return a.logsContent()
	case tabRKE2:
		return a.rke2Content()
	}
	return content{}
}

func (a *App) filteredRows(c content) []row {
	f := strings.ToLower(a.filters[a.tab])
	if f == "" {
		return c.rows
	}
	fc := &a.frame
	if fc.valid && fc.rowsOK && fc.filter == f && len(fc.c.rows) == len(c.rows) && (len(c.rows) == 0 || &fc.c.rows[0] == &c.rows[0]) {
		return fc.rows
	}
	var out []row
	for _, r := range c.rows {
		if strings.Contains(strings.ToLower(ansi.Strip(r.text)), f) {
			out = append(out, r)
		}
	}
	if fc.valid && len(fc.c.rows) == len(c.rows) && (len(c.rows) == 0 || &fc.c.rows[0] == &c.rows[0]) {
		fc.filter, fc.rows, fc.rowsOK = f, out, true
	}
	return out
}

// selectedID returns the id of the highlighted row on the current tab.
func (a *App) selectedID() string {
	c := a.currentContent()
	if !c.selectable {
		return ""
	}
	rows := a.filteredRows(c)
	if a.cursor[a.tab] >= 0 && a.cursor[a.tab] < len(rows) {
		return rows[a.cursor[a.tab]].id
	}
	return ""
}

// setDetail fills the detail overlay. Lines longer than the box are cut
// unless wrapping is on (w toggles it; the choice sticks for the session).
func (a *App) setDetail(title string, lines []string) {
	a.detailTitle, a.detailRaw, a.detailScroll = title, lines, 0
	a.detailFind.clear()
	a.layoutDetail()
	a.overlay = ovDetail
}

// layoutDetail derives the overlay's lines from the raw detail.
func (a *App) layoutDetail() {
	if !a.detailWrap {
		a.detailLines = a.detailRaw
		return
	}
	w := a.width - 4
	out := make([]string, 0, len(a.detailRaw))
	for _, l := range a.detailRaw {
		out = append(out, wrapStyled(l, w)...)
	}
	a.detailLines = out
	if a.detailFind.query != "" {
		a.detailFind.run(a.detailLines, a.detailScroll)
	}
}

func (a *App) openDetail() {
	if a.selectedID() == "" {
		// the cursor sits on a heading or blank line (a fresh tab): use the
		// nearest row that has something to open, and move there
		c := a.currentContent()
		rows := a.filteredRows(c)
		if i := nearestRow(rows, a.cursor[a.tab]); i < len(rows) && rows[i].id != "" {
			a.cursor[a.tab] = i
			a.clamp(c)
		}
	}
	title, lines := a.detailFor(a.tab, a.selectedID())
	if len(lines) == 0 {
		return
	}
	a.setDetail(title, lines)
}

// View renders the screen.
func (a *App) View() string {
	if a.width == 0 {
		return "starting..."
	}
	var b strings.Builder
	b.WriteString(a.renderHeader())
	b.WriteString("\n")
	b.WriteString(a.renderTabs())
	b.WriteString("\n")
	if st := a.renderSubTabs(); st != "" {
		b.WriteString(st)
		b.WriteString("\n")
	}
	switch {
	case a.overlay != ovNone:
		b.WriteString(a.renderOverlay())
	case a.inInspect():
		b.WriteString(a.renderInspectBody())
	default:
		b.WriteString(a.renderBody())
	}
	b.WriteString("\n")
	b.WriteString(a.renderFooter())
	return fitScreen(b.String(), a.width, a.height)
}

// renderCentered fills the body with msg and the lines under it centered
// both ways (spinner in front while something is in flight), then the
// status line.
func (a *App) renderCentered(msg string, spin bool, sub ...string) string {
	h := a.bodyHeight()
	head := styleBold.Render(msg)
	if spin {
		head = a.spinner.View() + " " + head
	}
	block := append([]string{head}, sub...)
	top := (h - len(block)) / 2
	if top < 0 {
		top = 0
	}
	lines := make([]string, 0, h+1)
	for i := 0; i < top; i++ {
		lines = append(lines, "")
	}
	// the block is centered as a whole and its lines left-aligned within it,
	// so a checklist reads as a list rather than a ragged column
	widest := 0
	for _, l := range block {
		if w := ansi.StringWidth(l); w > widest {
			widest = w
		}
	}
	left := (a.width - widest) / 2
	if left < 0 {
		left = 0
	}
	for _, l := range block {
		lines = append(lines, strings.Repeat(" ", left)+l)
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	lines = lines[:h]
	status := ""
	if a.status != "" && time.Since(a.statusAt) < 5*time.Second {
		status = styleInfo.Render(a.status)
	}
	return strings.Join(lines, "\n") + "\n" + trunc(status, a.width)
}

// fitScreen guarantees the frame is exactly height lines of at most width
// cells: a taller frame (or a line that wraps) makes the terminal scroll and
// leaves stale rows behind.
func fitScreen(frame string, width, height int) string {
	lines := strings.Split(frame, "\n")
	for i, l := range lines {
		lines[i] = trunc(l, width)
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (a *App) renderHeader() string {
	parts := []string{styleTitle.Render(" khealth") + styleDim.Render(" "+config.Version)}
	if a.snap != nil {
		parts = append(parts, kv("ctx", a.client.Context), kv("k8s", a.snap.Version), kv("dist", a.snap.Distribution))
		if a.apiOverride != "" {
			parts = append(parts, kv("api", styleWarn.Render(strings.TrimPrefix(a.apiOverride, "https://")+" (failover)")))
		}
		ready := 0
		for i := range a.snap.Nodes {
			if k8s.NodeReady(&a.snap.Nodes[i]) {
				ready++
			}
		}
		parts = append(parts, kv("nodes", okText(ready == len(a.snap.Nodes), fmt.Sprintf("%d/%d", ready, len(a.snap.Nodes)), fmt.Sprintf("%d/%d", ready, len(a.snap.Nodes)))))
		crit, warn := 0, 0
		for _, f := range a.findings {
			switch f.Severity {
			case checks.SevCrit:
				crit++
			case checks.SevWarn:
				warn++
			}
		}
		parts = append(parts, styleCrit.Render(fmt.Sprintf("%d crit", crit))+" "+styleWarn.Render(fmt.Sprintf("%d warn", warn)))
	} else {
		parts = append(parts, kv("ctx", a.client.Context))
	}
	ns := a.namespace
	if ns == "" {
		ns = "all"
	}
	parts = append(parts, kv("ns", styleBold.Render(ns)))
	ssh := "off"
	if a.sshEnabled {
		ssh = fmt.Sprintf("%d/%d", len(a.nodes)-len(a.pending), len(a.nodes))
		if len(a.pending) > 0 && a.snap != nil {
			ssh = fmt.Sprintf("%d/%d", len(a.snap.Nodes)-len(a.pending), len(a.snap.Nodes))
		}
	} else if a.sshErr != "" {
		ssh = styleWarn.Render("disabled")
	}
	parts = append(parts, kv("ssh", ssh))
	state := ""
	switch {
	case a.rescueHeader() != "":
		state = a.spinner.View() + " " + styleWarn.Render(a.rescueHeader())
	case a.actionRunning:
		state = a.spinner.View() + " " + styleWarn.Render("helm action running")
	case a.refreshing:
		state = a.spinner.View() + " refreshing"
	case a.scan.running():
		state = a.spinner.View() + " " + styleWarn.Render(fmt.Sprintf("scan %d%% %d/%d nodes", a.scan.percent(), a.scan.done(), len(a.scan.nodes)))
	case len(a.pending) > 0 || len(a.etcdPend) > 0:
		state = a.spinner.View() + fmt.Sprintf(" collecting %d", len(a.pending)+len(a.etcdPend))
	case !a.lastRefresh.IsZero():
		state = "updated " + age(a.lastRefresh) + " ago"
	}
	parts = append(parts, styleDim.Render(state))
	return trunc(strings.Join(parts, "  "), a.width)
}

// renderTabs draws the tab strip as its own full-width band (distinct from
// the status header above it) followed by a rule that carries the active
// tab's name.
func (a *App) renderTabs() string {
	var b strings.Builder
	b.WriteString(styleTabBar.Render(" "))
	for i := range tabNames {
		name := a.tabName(tab(i))
		if tab(i) == a.tab {
			b.WriteString(styleTabOn.Render(tabKeys[i] + " " + name))
		} else {
			b.WriteString(styleTabBar.Render(styleTabKey.Render(tabKeys[i]) + " " + styleTabOff.Render(name)))
		}
		b.WriteString(styleTabBar.Render(" "))
	}
	strip := b.String()
	if w := ansi.StringWidth(strip); w < a.width {
		strip += styleTabBar.Render(strings.Repeat(" ", a.width-w))
	}
	strip = trunc(strip, a.width)

	title := " " + a.tabName(a.tab) + " "
	rule := styleRule.Render("━━") + styleRuleTitle.Render(title)
	if w := ansi.StringWidth(rule); w < a.width {
		rule += styleRule.Render(strings.Repeat("━", a.width-w))
	}
	return strip + "\n" + trunc(rule, a.width)
}

// renderSubTabs draws the second-level strip for tabs that have one.
func (a *App) renderSubTabs() string {
	st := subTabs[a.tab]
	if len(st) == 0 {
		return ""
	}
	active := a.subName()
	var b strings.Builder
	b.WriteString(styleSubBar.Render("   "))
	for _, n := range st {
		label := n
		if n == subInspect && len(a.inspect) > 0 {
			label = fmt.Sprintf("%s (%d)", n, len(a.inspect))
		}
		if n == active {
			b.WriteString(styleSubOn.Render(label))
		} else {
			b.WriteString(styleSubOff.Render(" " + label + " "))
		}
		b.WriteString(styleSubBar.Render(" "))
	}
	hint := styleSubBar.Render(styleSubOff.Render("←/→ h/l switch"))
	strip := b.String()
	if w := ansi.StringWidth(strip) + ansi.StringWidth(hint) + 2; w < a.width {
		strip += styleSubBar.Render(strings.Repeat(" ", a.width-w)) + hint + styleSubBar.Render("  ")
	} else if w := ansi.StringWidth(strip); w < a.width {
		strip += styleSubBar.Render(strings.Repeat(" ", a.width-w))
	}
	return trunc(strip, a.width)
}

// renderInspectBody renders the inspector stack in the body area.
func (a *App) renderInspectBody() string {
	h := a.bodyHeight()
	title, lines := a.renderInspect()
	var out []string
	if len(a.inspect) == 0 {
		out = append(out, styleDim.Render("nothing inspected yet: select a row on the other sub-tabs and press enter; references chain from here (esc goes back one level)"))
	} else {
		out = append(out, styleTitle.Render(title))
		out = append(out, lines...)
	}
	for i := range out {
		out[i] = trunc(out[i], a.width)
	}
	for len(out) < h {
		out = append(out, "")
	}
	if len(out) > h {
		out = out[:h]
	}
	status := ""
	if a.status != "" && time.Since(a.statusAt) < 5*time.Second {
		status = styleInfo.Render(a.status)
	}
	return strings.Join(out, "\n") + "\n" + trunc(status, a.width)
}

func (a *App) renderBody() string {
	c := a.currentContent()
	a.clamp(c)
	h := a.bodyHeight()
	lines := make([]string, 0, h)
	for _, l := range c.header {
		lines = append(lines, trunc(l, a.width))
	}
	rows := a.filteredRows(c)
	if len(rows) == 0 && c.empty != "" && c.centered {
		return a.renderCentered(c.empty, c.spin, c.sub...)
	}
	if len(rows) == 0 && c.empty != "" {
		lines = append(lines, styleDim.Render(c.empty))
	}
	visible := h - len(c.header)
	if visible < 1 {
		visible = 1
	}
	start := a.scroll[a.tab]
	if start > len(rows) {
		start = len(rows)
	}
	end := start + visible
	if end > len(rows) {
		end = len(rows)
	}
	for i := start; i < end; i++ {
		t := trunc(rows[i].text, a.width)
		if c.selectable && i == a.cursor[a.tab] {
			t = selectRow(t, a.width)
		}
		lines = append(lines, t)
	}
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	// status / filter line
	status := ""
	switch {
	case a.filterOn:
		status = a.filter.View()
	case a.filters[a.tab] != "":
		status = styleDim.Render(fmt.Sprintf("filter: %q (%d/%d rows, esc clears)", a.filters[a.tab], len(rows), len(c.rows)))
	case a.status != "" && time.Since(a.statusAt) < 5*time.Second:
		status = styleInfo.Render(a.status)
	case len(rows) > visible:
		status = styleDim.Render(fmt.Sprintf("rows %d-%d of %d", start+1, end, len(rows)))
	}
	lines = append(lines, trunc(status, a.width))
	return strings.Join(lines, "\n")
}

func (a *App) renderFooter() string {
	keys := []string{"tab/shift-tab switch", "←/→ sub-tab", "j/k move", "enter inspect", "n namespace", "C context", "/ filter", "a problems", "r refresh", "R full", "s ssh", "? help", "q quit"}
	// a modal view has its own keys; esc is always the way out and the tab
	// row is inactive until it closes
	switch a.overlay {
	case ovDetail, ovHelp:
		keys = []string{"esc close", "j/k scroll", "PgUp/PgDn page", "g/G top/bottom", "/ find", "n/N next/prev hit", "(tabs resume after esc)"}
	case ovConfirm, ovRevisions:
		keys = []string{"esc cancel", "enter confirm", "j/k choose", "(tabs resume after esc)"}
	case ovNamespace:
		keys = []string{"esc cancel", "enter select", "type filter", "↑/↓ choose"}
	case ovContext:
		keys = []string{"esc cancel", "enter switch", "j/k choose"}
	case ovInspect:
		keys = []string{"esc back", "enter drill down", "j/k move", "/ find", "n/N next/prev hit", "q close", "(tabs resume after esc)"}
	case ovPodLogs:
		keys = []string{"esc close", "[ ]/tab container", "{ } pod", "p previous", "f follow", "w wrap", "/ find", "n/N hit", "& only hits", "T timestamps", "H highlight", "r reload"}
	case ovRescue:
		keys = []string{"esc cancel/back", "j/k choose", "enter next"}
		if r := a.rescue; r != nil {
			switch r.phase {
			case rescueConfirm:
				keys = []string{"esc cancel", "enter begin (after typing " + rescueWord + ")", "↑/↓ PgUp/PgDn scroll"}
			case rescueRunning:
				keys = []string{"esc hide (keeps running)", "x abort after current step", "j/k PgUp/PgDn scroll", "f follow"}
			case rescueDone:
				keys = []string{"esc close + refresh", "j/k scroll", "g/G top/bottom"}
			}
		}
	}
	var parts []string
	for _, k := range keys {
		kk, rest, _ := strings.Cut(k, " ")
		parts = append(parts, styleKey.Render(kk)+" "+styleDim.Render(rest))
	}
	return trunc(" "+strings.Join(parts, "  "), a.width)
}

func (a *App) renderOverlay() string {
	h := a.bodyHeight() + 1
	var title string
	var lines []string
	switch a.overlay {
	case ovHelp:
		title = "Help"
		lines = helpLines(a.width - 4)
	case ovNamespace:
		title = "Select namespace"
		lines = append(lines, a.nsInput.View(), styleDim.Render("PSA = pod-security.kubernetes.io/enforce label (warn/audit in brackets), else the admission config's default; exempt = listed in its exemptions.namespaces; PRIV = running pods with privileged containers / host namespaces"), "")
		opts := a.nsOptions()
		visible := h - 7
		start := 0
		if a.nsCursor >= visible {
			start = a.nsCursor - visible + 1
		}
		// size the columns from every namespace, not just the visible window,
		// so the layout stays put while scrolling
		rows := make([][]string, 0, len(opts))
		cfg := a.psaConfig()
		for _, o := range opts {
			rows = append(rows, a.nsRow(o, cfg))
		}
		tw := a.width - 8
		hdr, rl := renderTable(tw, []column{{title: "NAMESPACE", max: 40}, {title: "PSA ENFORCE"}, {title: "PRIV PODS"}, {title: "PODS", right: true}, {title: "NOTE"}}, rows)
		lines = append(lines, "  "+pad(hdr, tw))
		for i := start; i < len(rl) && i < start+visible; i++ {
			if i == a.nsCursor {
				lines = append(lines, selectRow("> "+rl[i], tw+2))
			} else {
				lines = append(lines, "  "+pad(rl[i], tw))
			}
		}
		if len(rl) > visible {
			lines = append(lines, styleDim.Render(fmt.Sprintf("  %d-%d of %d", start+1, min(start+visible, len(rl)), len(rl))))
		}
	case ovConfirm, ovRevisions:
		title, lines = a.renderActionOverlay()
	case ovScanPeek:
		title = "Security scan still running"
		pend := 0
		if a.scan != nil {
			pend = len(a.scan.want)
		}
		lines = append(lines, styleBold.Render(fmt.Sprintf("%d node(s) have not returned their facts yet.", pend)), "")
		lines = append(lines, wrap("Enter shows the results so far: the STIG/CIS rules from the API data and the nodes that have answered. Node hardening and OS STIG rows for the other nodes are missing until they answer - the scan keeps running and the tab fills in as they do.", a.width-6)...)
		lines = append(lines, "", styleKey.Render("enter")+" show partial results    "+styleKey.Render("esc")+" keep waiting")
	case ovInspect:
		title, lines = a.renderInspect()
	case ovPodLogs:
		title, lines = a.renderPodLogs()
	case ovRescue:
		title, lines = a.renderRescue()
	case ovContext:
		title = "Switch cluster context"
		lines = append(lines, styleDim.Render("contexts of the kubeconfig in use plus every ~/.kube/khealth-*.yaml written by `khealth user@host`; enter switches and starts a fresh first-contact cycle"), "")
		var rows [][]string
		for _, c := range a.ctxList {
			cur := ""
			if c.Current {
				cur = styleOK.Render("current")
			}
			file := styleDim.Render("kubeconfig")
			if c.File != "" {
				file = shortPath(c.File)
			}
			ssh := styleDim.Render("-")
			if c.SSH.User != "" {
				ssh = c.SSH.User
				if c.SSH.Host != "" {
					ssh += "@" + c.SSH.Host
				}
			}
			rows = append(rows, []string{c.Name, c.Cluster, c.Server, file, ssh, cur})
		}
		tw := a.width - 8
		hdr, rl := renderTable(tw, []column{{title: "CONTEXT", max: 32}, {title: "CLUSTER", max: 24}, {title: "SERVER", max: 40}, {title: "FILE", max: 32}, {title: "SSH", max: 28}, {title: ""}}, rows)
		lines = append(lines, "  "+pad(hdr, tw))
		for i, l := range rl {
			if i == a.ctxCursor {
				lines = append(lines, selectRow("> "+l, tw+2))
			} else {
				lines = append(lines, "  "+pad(l, tw))
			}
		}
		if len(rows) == 0 {
			lines = append(lines, styleDim.Render("  no contexts found"))
		}
	case ovDetail:
		title = a.detailTitle
		visible := h - 4
		end := a.detailScroll + visible
		if end > len(a.detailLines) {
			end = len(a.detailLines)
		}
		for i := a.detailScroll; i < end; i++ {
			lines = append(lines, a.detailFind.render(a.detailLines[i], i))
		}
		find := a.detailFind.status()
		if find != "" {
			find = "  " + find
		}
		if len(a.detailLines) > visible {
			lines = append(lines, styleDim.Render(fmt.Sprintf("-- %d-%d of %d (j/k, PgUp/PgDn, / find, w wrap, esc closes) --", a.detailScroll+1, end, len(a.detailLines)))+find)
		} else {
			lines = append(lines, styleDim.Render("-- / find, w wrap, esc closes --")+find)
		}
	}
	inner := a.width - 4
	for i := range lines {
		lines[i] = trunc(lines[i], inner)
	}
	body := styleTitle.Render(title) + "\n" + strings.Join(lines, "\n")
	box := styleBox.Width(a.width - 2).Render(body)
	boxLines := strings.Split(box, "\n")
	for len(boxLines) < h {
		boxLines = append(boxLines, "")
	}
	if len(boxLines) > h {
		boxLines = boxLines[:h]
	}
	return strings.Join(boxLines, "\n")
}

// helpLines renders the ? overlay for a content width: key tables per
// section (key column sized to fit, the description wraps in the rest).
func helpLines(width int) []string {
	if width < 40 {
		width = 40
	}
	key := func(k string) string { return styleKey.Render(k) }
	keyCols := []column{{title: "KEY"}, {title: "ACTION"}}
	tabKeyCols := []column{{title: "TAB"}, {title: "KEY"}, {title: "ACTION"}}
	tabCols := []column{{title: "TAB"}, {title: "WHAT IT SHOWS"}}
	var lines []string
	section := func(title string, cols []column, rows [][]string) {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, styleBold.Render(title))
		for _, l := range wrapTable(width-2, cols, rows) {
			lines = append(lines, "  "+l)
		}
	}
	note := func(s string) {
		for _, l := range wrap(s, width-2) {
			lines = append(lines, "  "+styleDim.Render(l))
		}
	}

	section("Navigation", keyCols, [][]string{
		{key("tab / shift+tab / [ ]"), "next / previous tab"},
		{key("1-9 0 - ="), "jump to a tab"},
		{key("← → / h l"), "previous / next sub-tab inside the current tab"},
		{key("↑ ↓ / j k"), "move selection / scroll"},
		{key("g / G"), "top / bottom"},
		{key("PgUp / PgDn / space"), "page"},
		{key("enter"), "open detail for the selected row (j/k scroll, w wraps long lines, esc closes)"},
		{key("C"), "switch cluster context (kubeconfig contexts + ~/.kube/khealth-*.yaml)"},
		{key("esc"), "close overlay / clear filter / step back"},
	})

	section("Everywhere", keyCols, [][]string{
		{key("n"), "choose namespace (shows PSA level + privileged pods; filters Inspect, Events, Storage, Helm)"},
		{key("/"), "filter rows on the current tab (substring); esc clears. Inside a detail view, the inspector or the pod log tailer: find text in that page (the YAML included), hits highlighted as you type, n/N jump to the next/previous hit, esc clears; in the tailer & narrows the view to the matching lines"},
		{key("a"), "toggle problems-only view (Overview, Inspect, Events, Security, Resources)"},
		{key("r"), "refresh now (API + light SSH collection)"},
		{key("R"), "full refresh: journal logs, images, tarballs, PV du (not the OS STIG)"},
		{key("s"), "toggle SSH collection on/off"},
		{key("P"), "footprint: what khealth itself costs the API server, the nodes (remote CPU per probe) and this host"},
		{key("e"), "export the findings, the security scan (one sheet per benchmark) and the node hardening table as JSON + XLSX (--export-dir / export.dir, default: current directory)"},
		{key("?"), "this help"},
		{key("q"), "quit (steps back first when inside an object/log view)"},
	})

	section("Tab-specific keys", tabKeyCols, [][]string{
		{"Inspect", key("enter"), "open the object (references, YAML)"},
		{"", key("L"), "tail logs of the selected pod / the controller's pods"},
		{"", key("p"), "jump to the Pods sub-tab"},
		{"", key("t"), "rollout restart (Deployment/DaemonSet/StatefulSet, confirmed)"},
		{"Helm", key("enter"), "values + history"},
		{"", key("u"), "upgrade to the newest known version: helm upgrade, or spec.version on your HelmChart CR (confirmed)"},
		{"", key("b"), "rollback (pick revision; the last one that deployed is preselected, confirmed)"},
		{"", key("B"), "rollback a failed / pending-* release straight to the last revision that deployed (confirmed)"},
		{"Nodes", key("enter"), "node dashboard: gauges, security runtime-vs-boot, services, filesystems, certs"},
		{"etcd", key("enter"), "raw probe output and config dumps"},
		{"", key("X"), "rescue: rejoin one broken server (quorum fine) or restore a snapshot onto the whole control plane (SSH + actions enabled; preflight, warnings and a typed confirmation first)"},
		{"", key("D"), "defragment every etcd member, one at a time (followers first, leader last, health check between; etcdctl via kubectl exec; confirmed)"},
		{"Logs", key("enter"), "node lines; enter again = full line + explanation"},
		{"", key("a"), "include info lines"},
		{"Events", key("enter"), "open the involved object in the inspector"},
		{"Security", key("← →"), "Rules / Node hardening / OS STIG"},
		{"", key("enter"), "rule detail, fix and the STIG's own check procedure"},
		{"", key("a"), "hide passing rules"},
		{"", key("m"), "hide MANUAL rules"},
		{"", key("shift+S"), "run the security scan: STIG/CIS rules from the API data plus, over SSH, the full DISA OS STIG collection in four stages per node (system facts, file modes, accounts, filesystem sweep; a few seconds each). Per-node progress shows on the tab, the percent in the header. Never runs on its own - not at launch, not on r/R; the OS facts stay until the next Shift+S"},
	})
	note("Security scorecards per benchmark (and per node): score = not a finding / (not a finding + open), as in an SCC / OpenSCAP report")

	section("Log viewer (L)", keyCols, [][]string{
		{key("[ ] / tab"), "switch container"},
		{key("{ }"), "next / previous pod"},
		{key("p"), "previous instance of the container"},
		{key("f"), "follow on/off"},
		{key("w"), "wrap on/off"},
		{key("T"), "timestamps short / off / full"},
		{key("H"), "highlighting on/off"},
		{key("r"), "reload"},
		{key("esc"), "close"},
	})
	note("JSON, logfmt (key=value) and klog lines are color-coded automatically: keys dim, level by severity, messages bold. Lines stream live; / is not needed.")

	section("Tabs", tabCols, [][]string{
		{"Overview", "cluster summary, API health, ranked findings with first-seen age; findings that went away stay listed as resolved for 15m"},
		{"Nodes", "conditions + live CPU/mem/disk/load from SSH (or metrics-server), certs, services"},
		{"Inspect", "controllers (deploy/ds/sts/job/cronjob) then pods not owned by one; p = all pods; t = rollout restart. enter opens the Object sub-tab: owner/child/secret/configmap/PVC/SA references, enter again drills down, esc back. Resources sub-tab: every API type (built-in + CRDs) with instance counts; enter lists instances, enter again inspects one"},
		{"etcd", "members, health, db size/quota/fragmentation, fsync latency, config source, snapshots/backups. X = rescue: stop rke2-server/k3s (or park the kubeadm static pods) on every server, move each etcd data dir into a timestamped rescue dir, cluster-reset/restore the chosen snapshot on the chosen node, fix owner/mode, start it, rejoin the other servers one at a time with an etcd member/health/leader check after each, take a fresh snapshot"},
		{"Storage", "StorageClasses, CSI drivers, PVs/PVCs and node filesystems"},
		{"Events", "warning events"},
		{"Addons", "CNI, CSI, DNS/ingress/metrics, registry mirrors (registries.yaml on rke2/k3s, containerd certs.d elsewhere), Rancher management + join topology (rke2/k3s, or a cluster registered in Rancher), rke2 HelmCharts"},
		{"Helm", "releases (enter = values applied), optional update check; u = upgrade to the newest known chart version (helm upgrade, or a spec.version patch on your own HelmChart CR when the rke2/k3s helm controller owns the release), b = helm rollback to a chosen revision, B = roll a failed or stuck (pending-*) release back to the last revision that deployed (all confirm first; helm/rollback need the helm CLI; --read-only disables them; charts shipped inside rke2 are refused for upgrade)"},
		{"Images", "per-node image inventory, unused images, airgap tarball contents vs running"},
		{"Security", "Rules: DISA Kubernetes / RKE2 / Rancher MCM STIG + CIS checks from component flags, kubelet config, PSA, RBAC, node facts. Node hardening: per-node runtime vs boot facts (SELinux, FIPS, auditd, firewall...) and the OS STIG summary. OS STIG: every rule of the node's DISA RHEL 8/9/10 or Ubuntu 22.04/24.04 STIG. The whole tab is opt-in: empty until Shift+S runs the scan"},
		{"Logs", "rke2/kubelet/containerd/rancher-system-agent logs classified into startup-noise / warnings / errors (Rancher plan events flag config rewrites); enter on a node lists its lines, enter on a line shows the full text + explanation, esc goes back, a shows info lines"},
		{"RKE2/k3s", "config.yaml(.d), data-dir, server/manifests (HelmChartConfig etc.), static pod manifests, audit/PSS policies, config drift, API endpoint vs tls-san vs cert"},
		{"kubeadm", "(same tab on upstream clusters) kubeadm-config ClusterConfiguration, API endpoint vs certSANs vs apiserver.crt"},
	})

	lines = append(lines, "")
	for _, l := range wrap("Config: ~/.config/khealth/config.yaml (khealth --init-config writes the annotated example)", width) {
		lines = append(lines, styleDim.Render(l))
	}
	lines = append(lines, styleDim.Render("khealth "+config.Version+" - created by Zach Mitchell"))
	return lines
}

// inNamespace reports whether an object namespace matches the active filter.
func (a *App) inNamespace(ns string) bool {
	return a.namespace == "" || a.namespace == ns
}

var _ = lipgloss.Width

// classifyLogs runs a probe's journal and log files through the knowledge
// base, or returns nil when the probe carried none (light cycle: the
// previous summary stays).
func classifyLogs(ni *nodeinfo.Info) *logs.Summary {
	if ni == nil || (len(ni.Journal) == 0 && len(ni.LogFiles) == 0) {
		return nil
	}
	// rke2's kubelet/containerd log to files rather than the journal
	srcs := []logs.Source{{Lines: ni.Journal}}
	for _, lf := range ni.LogFiles {
		srcs = append(srcs, logs.Source{Unit: logFileUnit(lf.Path), Lines: strings.Split(lf.Content, "\n")})
	}
	return logs.ClassifySources(srcs, time.Now())
}

// setNetTargets gives a node's probe the addresses its network checks
// target (config tier, see nodeinfo NETPROBE): one pod on every other node
// for the overlay ping, the CoreDNS pod IPs, the DNS and kubernetes
// service IPs.
func setNetTargets(opts *nodeinfo.Options, snap *k8s.Snapshot, node string) {
	if snap == nil {
		return
	}
	for _, t := range snap.PodTargetList() {
		if !strings.HasPrefix(t, node+"=") {
			opts.NetTargets = append(opts.NetTargets, t)
		}
	}
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.Namespace == "kube-system" && strings.Contains(p.Name, "coredns") && !strings.Contains(p.Name, "autoscaler") && p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" && len(opts.DNSPods) < 2 {
			opts.DNSPods = append(opts.DNSPods, p.Status.PodIP)
		}
	}
	opts.DNSIP, opts.APISvcIP = snap.ClusterDNSIP(), snap.APIServiceIP()
}
