// Package ui implements the Bubble Tea terminal interface.
package ui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/sshrun"
	"k8s-health-tui/internal/stig"
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
	tabCRDs
	tabCount
)

var tabNames = [...]string{"Overview", "Nodes", "Inspect", "etcd", "Storage", "Events", "Addons", "Helm", "Images", "Security", "Logs", "RKE2", "CRDs"}
var tabKeys = [...]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "c"}

// subTabs are second-level views of a tab (h/l switch). "Inspect" renders
// the object inspector in the body instead of an overlay.
var subTabs = map[tab][]string{
	tabWorkloads: {"Controllers", "Pods", "Object"},
	tabCRDs:      {"Definitions", "Object"},
	tabEvents:    {"Events", "Object"},
	tabLogs:      {"Nodes", "Lines"},
	tabSecurity:  {"Rules", "Node hardening"},
}

const subInspect = "Object"

type overlayKind int

const (
	ovNone overlayKind = iota
	ovHelp
	ovNamespace
	ovDetail
	ovConfirm
	ovRevisions
	ovInspect
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
	etcd       map[string]*etcd.Probe
	etcdPend   map[string]bool
	s3         *k8s.S3SecretInfo
	logSum     map[string]*logs.Summary
	stigRes    []stig.Result
	helmLatest map[string]helmcheck.Latest
	findings   []checks.Finding
	hist       map[string]*series

	seq         int
	cycle       int
	heavyNext   bool
	refreshing  bool
	lastRefresh time.Time
	spinner     spinner.Model
	problemOnly bool

	cursor   [tabCount]int
	scroll   [tabCount]int
	filters  [tabCount]string
	filter   textinput.Model
	filterOn bool

	overlay      overlayKind
	nsInput      textinput.Model
	nsCursor     int
	detailTitle  string
	detailLines  []string
	detailScroll int
	status       string
	statusAt     time.Time
	logsNode     string // Logs tab: node whose lines are listed ("" = node list)
	logsAll      bool   // Logs tab: show info lines too

	pendingAct    *action
	revRelease    *k8s.HelmRelease
	revCursor     int
	actionRunning bool

	inspect     []inspectLevel
	inspectSeq  int
	crdCounts   []k8s.CRDInfo
	crdCounting bool
	etcdExec    *etcd.Probe
	wlPods      bool
	sub         [tabCount]int // active sub-tab per tab
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

// inInspect reports whether the body currently shows the inspector.
func (a *App) inInspect() bool { return a.subName() == subInspect }

// showInspect switches to the tab's Inspect sub-tab, or opens the overlay
// when the tab has none.
func (a *App) showInspect() {
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
	seq  int
	info *nodeinfo.Info
}
type etcdMsg struct {
	seq   int
	probe *etcd.Probe
}
type s3Msg struct{ info *k8s.S3SecretInfo }
type helmMsg struct{ latest map[string]helmcheck.Latest }
type etcdExecMsg struct {
	seq   int
	probe *etcd.Probe
}
type tickMsg struct{ seq int }

// New creates the application model.
func New(cfg config.Config) (*App, error) {
	client, err := k8s.New(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg:        cfg,
		client:     client,
		namespace:  cfg.Namespace,
		nodes:      map[string]*nodeinfo.Info{},
		pending:    map[string]bool{},
		etcd:       map[string]*etcd.Probe{},
		etcdPend:   map[string]bool{},
		logSum:     map[string]*logs.Summary{},
		helmLatest: map[string]helmcheck.Latest{},
		heavyNext:  true,
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
	heavy := a.heavyNext || a.cycle%a.cfg.HeavyEvery == 0
	a.heavyNext = false
	var cmds []tea.Cmd
	seq := a.seq
	runner := a.runner
	timeout := 3 * a.cfg.SSH.Timeout
	if heavy {
		timeout = 6 * a.cfg.SSH.Timeout
	}
	only := map[string]bool{}
	for _, n := range a.cfg.SSH.Nodes {
		only[n] = true
	}
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if len(only) > 0 && !only[n.Name] {
			continue
		}
		host := a.nodeAddress(n)
		name := n.Name
		opts := nodeinfo.Options{Heavy: heavy, LogLines: a.cfg.Logs.Lines, LogSince: a.cfg.Logs.Since}
		if prev := a.nodes[name]; prev != nil {
			opts.KnownTarballs = prev.TarballKeys()
		}
		a.pending[name] = true
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res := runner.Run(ctx, host, nodeinfo.Script(opts))
			info := nodeinfo.Parse(name, host, res.Stdout, res.Started)
			info.Duration = res.Finished.Sub(res.Started)
			if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
				msg := res.Err.Error()
				if s := strings.TrimSpace(res.Stderr); s != "" {
					msg += ": " + firstLine(s)
				}
				info.Err = fmt.Errorf("%s", msg)
			}
			return nodeMsg{seq: seq, info: info}
		})
		if k8s.IsEtcdNode(snap.Nodes, n) {
			a.etcdPend[name] = true
			script := etcd.Script(a.cfg.Etcd)
			cmds = append(cmds, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				res := runner.Run(ctx, host, script)
				p := etcd.Parse(name, res.Stdout)
				p.Duration = res.Finished.Sub(res.Started)
				p.Stderr = strings.TrimSpace(res.Stderr)
				if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
					p.Err = fmt.Errorf("%s", firstLine(res.Err.Error()+" "+res.Stderr))
				}
				return etcdMsg{seq: seq, probe: p}
			})
		}
	}
	return tea.Batch(cmds...)
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
	seq := a.seq
	client := a.client
	dist := snap.Distribution
	names := sortedKeys(pods)
	podNames := map[string]string{}
	for _, n := range names {
		podNames[n] = pods[n].Name
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var last *etcd.Probe
		for _, n := range names {
			p := etcd.ExecProbe(ctx, client, n, podNames[n], dist)
			last = p
			if p.Err == nil && len(p.Members) > 0 {
				break
			}
		}
		return etcdExecMsg{seq: seq, probe: last}
	}
}

func (a *App) helmCmd(snap *k8s.Snapshot) tea.Cmd {
	if a.helm == nil || snap == nil || len(snap.HelmReleases) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var charts []string
	for _, r := range snap.HelmReleases {
		if r.Chart != "" && !seen[r.Chart] {
			seen[r.Chart] = true
			charts = append(charts, r.Chart)
		}
	}
	h := a.helm
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return helmMsg{latest: h.Lookup(ctx, charts)}
	}
}

func (a *App) s3Cmd(name string) tea.Cmd {
	client := a.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return s3Msg{info: client.S3Secret(ctx, name)}
	}
}

func (a *App) recompute() {
	for name, ni := range a.nodes {
		if ni != nil && len(ni.Journal) > 0 {
			var lines []string
			lines = append(lines, ni.Journal...)
			for _, lf := range ni.LogFiles {
				for _, l := range strings.Split(lf.Content, "\n") {
					if strings.TrimSpace(l) != "" {
						lines = append(lines, l)
					}
				}
			}
			a.logSum[name] = logs.Classify(lines, time.Now())
		}
	}
	a.stigRes = stig.Evaluate(stig.Input{Snap: a.snap, Nodes: a.nodes, Etcd: a.etcd})
	a.findings = checks.Evaluate(checks.Input{
		Snap: a.snap, Nodes: a.nodes, Etcd: a.etcd, EtcdExec: a.etcdExec, S3: a.s3, Logs: a.logSum, Stig: a.stigRes,
		HelmLatest: a.helmLatest, SSHEnabled: a.sshEnabled, SSHErr: a.sshErr, Cfg: a.cfg, Now: time.Now(),
	})
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
	a.record("events.warn", float64(len(s.Events)))
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
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
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
		a.cycle++
		// drop nodes that no longer exist
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
		a.crdCounts = nil
		a.crdCounting = false
		a.recompute()
		a.recordSnapshot()
		var crdCmd tea.Cmd
		if a.tab == tabCRDs {
			crdCmd = a.crdCountCmd()
		}
		return a, tea.Batch(a.collectCmds(a.snap), a.helmCmd(a.snap), a.etcdExecCmd(a.snap), crdCmd, a.tickCmd())
	case nodeMsg:
		if m.seq != a.seq {
			return a, nil
		}
		m.info.MergeHeavy(a.nodes[m.info.Node])
		a.nodes[m.info.Node] = m.info
		delete(a.pending, m.info.Node)
		a.recompute()
		a.recordNode(m.info)
		return a, nil
	case etcdMsg:
		if m.seq != a.seq {
			return a, nil
		}
		a.etcd[m.probe.Node] = m.probe
		delete(a.etcdPend, m.probe.Node)
		a.recompute()
		a.recordEtcd(m.probe)
		if name := m.probe.RKE2Config["etcd-s3-config-secret"]; name != "" && (a.s3 == nil || a.s3.Name != name) {
			return a, a.s3Cmd(name)
		}
		return a, nil
	case s3Msg:
		a.s3 = m.info
		a.recompute()
		return a, nil
	case helmMsg:
		a.helmLatest = m.latest
		a.recompute()
		return a, nil
	case actionDoneMsg:
		return a, a.handleActionDone(m)
	case etcdExecMsg:
		if m.seq != a.seq {
			return a, nil
		}
		a.etcdExec = m.probe
		a.recompute()
		return a, nil
	case inspectMsg:
		a.handleInspectMsg(m)
		return a, nil
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

func (a *App) handleKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()
	if key == "ctrl+c" {
		return a, tea.Quit
	}
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
			a.cursor[a.tab] = 0
			a.scroll[a.tab] = 0
			return a, cmd
		}
		return a, nil
	}
	for i, k := range tabKeys {
		if key == k {
			a.tab = tab(i)
			if a.tab == tabCRDs {
				return a, a.crdCountCmd()
			}
			return a, nil
		}
	}
	if a.inInspect() {
		switch key {
		case "esc", "backspace", "j", "k", "down", "up", "enter", "J", "K", "pgdown", "pgup", " ", "ctrl+d", "ctrl+u", "g", "G", "home", "end":
			return a.handleInspectKey(key)
		}
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
		}
	}
	switch key {
	case "q":
		return a, tea.Quit
	case "tab", "]", "right":
		a.tab = (a.tab + 1) % tabCount
		if a.tab == tabCRDs {
			return a, a.crdCountCmd()
		}
	case "shift+tab", "[", "left":
		a.tab = (a.tab + tabCount - 1) % tabCount
		if a.tab == tabCRDs {
			return a, a.crdCountCmd()
		}
	case "l":
		a.setSub(1)
	case "h":
		a.setSub(-1)
	case "n":
		a.overlay = ovNamespace
		a.nsInput.SetValue("")
		a.nsCursor = 0
		return a, a.nsInput.Focus()
	case "r":
		if !a.refreshing {
			a.setStatus("refreshing")
			return a, a.refreshCmd()
		}
	case "R":
		a.heavyNext = true
		if !a.refreshing {
			a.setStatus("full refresh (logs, images, tarballs)")
			return a, a.refreshCmd()
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
		a.cursor[a.tab] = 0
		a.scroll[a.tab] = 0
	case "/":
		a.filterOn = true
		a.filter.SetValue(a.filters[a.tab])
		return a, a.filter.Focus()
	case "esc":
		if a.tab == tabLogs && a.logsNode != "" && a.filters[a.tab] == "" {
			a.logsNode = ""
			a.cursor[a.tab], a.scroll[a.tab] = 0, 0
			return a, nil
		}
		a.filters[a.tab] = ""
	case "?":
		a.overlay = ovHelp
	case "enter":
		if a.tab == tabLogs && a.logsNode == "" {
			if id := a.selectedID(); id != "" {
				a.logsNode = id
				a.cursor[a.tab], a.scroll[a.tab], a.filters[a.tab] = 0, 0, ""
			}
			return a, nil
		}
		if a.tab == tabWorkloads && a.snap != nil {
			a.openWorkload(a.selectedID())
			return a, nil
		}
		if a.tab == tabCRDs && a.snap != nil {
			return a, a.openCRDInstances(a.selectedID())
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
		a.cursor[a.tab] = 0
		a.scroll[a.tab] = 0
	case "G", "end":
		a.cursor[a.tab] = 1 << 30
		a.scroll[a.tab] = 1 << 30
	case "pgdown", "ctrl+d", " ":
		a.move(a.bodyHeight() - 2)
	case "pgup", "ctrl+u":
		a.move(-(a.bodyHeight() - 2))
	}
	return a, nil
}

func (a *App) move(delta int) {
	c := a.currentContent()
	if c.selectable {
		a.cursor[a.tab] += delta
	} else {
		a.scroll[a.tab] += delta
	}
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
		if a.cursor[a.tab] < a.scroll[a.tab] {
			a.scroll[a.tab] = a.cursor[a.tab]
		}
		if a.cursor[a.tab] >= a.scroll[a.tab]+visible {
			a.scroll[a.tab] = a.cursor[a.tab] - visible + 1
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

func (a *App) handleOverlayKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()
	switch a.overlay {
	case ovConfirm, ovRevisions:
		return a.handleActionOverlayKey(key)
	case ovInspect:
		return a.handleInspectKey(key)
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
					a.cursor[t], a.scroll[t] = 0, 0
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
		switch key {
		case "esc", "q", "enter":
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
	if a.snap == nil {
		return content{empty: "loading cluster state..."}
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
	case tabCRDs:
		return a.crdsContent()
	}
	return content{}
}

func (a *App) filteredRows(c content) []row {
	f := strings.ToLower(a.filters[a.tab])
	if f == "" {
		return c.rows
	}
	var out []row
	for _, r := range c.rows {
		if strings.Contains(strings.ToLower(ansi.Strip(r.text)), f) {
			out = append(out, r)
		}
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

func (a *App) openDetail() {
	title, lines := a.detailFor(a.tab, a.selectedID())
	if len(lines) == 0 {
		return
	}
	a.detailTitle = title
	a.detailLines = lines
	a.detailScroll = 0
	a.overlay = ovDetail
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
	return b.String()
}

func (a *App) renderHeader() string {
	parts := []string{styleTitle.Render(" khealth")}
	if a.snap != nil {
		parts = append(parts, kv("ctx", a.client.Context), kv("k8s", a.snap.Version), kv("dist", a.snap.Distribution))
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
		ssh = styleWarn.Render("error")
	}
	parts = append(parts, kv("ssh", ssh))
	state := ""
	switch {
	case a.actionRunning:
		state = a.spinner.View() + " " + styleWarn.Render("helm action running")
	case a.refreshing:
		state = a.spinner.View() + " refreshing"
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
	for i, name := range tabNames {
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

	title := " " + tabNames[a.tab] + " "
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
	b.WriteString(styleDim.Render(" ┗ "))
	for i, n := range st {
		label := n
		if n == subInspect && len(a.inspect) > 0 {
			label = fmt.Sprintf("%s (%d)", n, len(a.inspect))
		}
		if n == active {
			b.WriteString(styleSubOn.Render(" " + label + " "))
		} else {
			b.WriteString(styleSubOff.Render(" " + label + " "))
		}
		if i < len(st)-1 {
			b.WriteString(styleDim.Render("│"))
		}
	}
	b.WriteString(styleDim.Render("   h/l switch"))
	return trunc(b.String(), a.width)
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
			t = styleSel.Render(pad(t, a.width))
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
	keys := []string{"tab/1-9 switch", "j/k move", "enter inspect", "n namespace", "/ filter", "a problems", "r refresh", "R full", "s ssh", "? help", "q quit"}
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
		lines = helpLines()
	case ovNamespace:
		title = "Select namespace"
		lines = append(lines, a.nsInput.View(), "")
		opts := a.nsOptions()
		visible := h - 6
		start := 0
		if a.nsCursor >= visible {
			start = a.nsCursor - visible + 1
		}
		for i := start; i < len(opts) && i < start+visible; i++ {
			t := opts[i]
			if i == a.nsCursor {
				t = styleSel.Render(" " + t + " ")
			} else {
				t = "  " + t
			}
			lines = append(lines, t)
		}
	case ovConfirm, ovRevisions:
		title, lines = a.renderActionOverlay()
	case ovInspect:
		title, lines = a.renderInspect()
	case ovDetail:
		title = a.detailTitle
		visible := h - 4
		end := a.detailScroll + visible
		if end > len(a.detailLines) {
			end = len(a.detailLines)
		}
		lines = append(lines, a.detailLines[a.detailScroll:end]...)
		if len(a.detailLines) > visible {
			lines = append(lines, styleDim.Render(fmt.Sprintf("-- %d-%d of %d (j/k, PgUp/PgDn, esc closes) --", a.detailScroll+1, end, len(a.detailLines))))
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

func helpLines() []string {
	return []string{
		styleBold.Render("Navigation"),
		"  tab / shift+tab / [ ]    next / previous tab        1-9 0 -   jump to tab",
		"  j/k or arrows            move selection / scroll    g / G     top / bottom",
		"  PgUp / PgDn / space      page                       enter     open detail for the selected row",
		"  esc                      close overlay / clear filter",
		"",
		styleBold.Render("Actions"),
		"  n      choose namespace (filters Workloads, Events, Storage, Helm)",
		"  /      filter rows on the current tab (substring)",
		"  a      toggle problems-only view (Overview findings, Workloads, Security)",
		"  r      refresh now (API + light SSH collection)",
		"  R      full refresh: also journal logs, image inventories and airgap tarball manifests",
		"  s      toggle SSH collection on/off",
		"  q      quit",
		"",
		styleBold.Render("Tabs"),
		"  Overview   cluster summary, API health, ranked findings",
		"  Nodes      conditions + live CPU/mem/disk/load from SSH (or metrics-server), certs, services",
		"  Inspect    controllers (deploy/ds/sts/job/cronjob) then pods not owned by one; p = all pods; t = rollout restart;",
		"             enter opens the Object sub-tab: owner/child/secret/configmap/PVC/SA references, enter again drills down, esc back",
		"  CRDs       every CustomResourceDefinition with instance counts; enter lists instances, enter again inspects one",
		"  etcd       members, health, db size/quota/fragmentation, fsync latency, config source, snapshots/backups",
		"  Storage    StorageClasses, CSI drivers, PVs/PVCs and node filesystems",
		"  Events     warning events",
		"  Addons     CNI, CSI, DNS/ingress/metrics, Rancher management, registries.yaml, rke2 HelmCharts",
		"  Helm       releases (enter = values applied), optional update check;",
		"             u = helm upgrade to the newest known chart version, b = helm rollback to a chosen revision (both confirm first;",
		"             need the helm CLI; --read-only disables them; rke2-bundled charts are refused)",
		"  Images     per-node image inventory, unused images, airgap tarball contents vs running",
		"  Security   STIG / CIS checks from component flags, kubelet config, PSA, RBAC and node facts",
		"  Logs       rke2/kubelet/containerd journal classified into startup-noise / warnings / errors",
		"             enter on a node lists its lines; enter on a line shows the full text + explanation; esc goes back; a shows info lines",
		"  RKE2       config.yaml(.d), data-dir, server/manifests (HelmChartConfig etc.), static pod manifests, audit/PSS policies, config drift",
		"",
		styleDim.Render("Config: ~/.config/k8s-health-tui/config.yaml (see config.example.yaml)"),
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// inNamespace reports whether an object namespace matches the active filter.
func (a *App) inNamespace(ns string) bool {
	return a.namespace == "" || a.namespace == ns
}

var _ = lipgloss.Width
