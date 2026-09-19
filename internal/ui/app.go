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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/perf"
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
	ovRevisions
	ovInspect
	ovPodLogs
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
	knownNodes []corev1.Node // last node list the API returned; used when the apiserver is down
	s3         *k8s.S3SecretInfo
	s3Reach    map[string]etcd.S3Check
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
	hideManual  bool // Security: hide MANUAL rules (m)
	stigNext    bool // collect the OS STIG facts on the next SSH cycle (S on the OS STIG sub-tab)

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
	switch a.snap.Distribution {
	case "rke2":
		return "RKE2"
	case "k3s":
		return "k3s"
	case "kubeadm":
		return "kubeadm"
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
	opts nodeinfo.Options // what the probe included (cost accounting)
}
type etcdMsg struct {
	seq   int
	probe *etcd.Probe
}
type s3Msg struct{ info *k8s.S3SecretInfo }

type s3CheckMsg struct {
	seq   int
	check etcd.S3Check
}
type helmMsg struct{ latest map[string]helmcheck.Latest }
type etcdExecMsg struct {
	seq   int
	probe *etcd.Probe
}
type tickMsg struct{ seq int }

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
	// hostPath/local PV directories (local-path-provisioner etc.) measured with du
	var pvPaths []string
	for i := range snap.PVs {
		pv := &snap.PVs[i]
		if pv.Spec.HostPath != nil {
			pvPaths = append(pvPaths, pv.Spec.HostPath.Path)
		} else if pv.Spec.Local != nil {
			pvPaths = append(pvPaths, pv.Spec.Local.Path)
		}
	}
	// apiserver down (power outage, quorum lost): keep probing the nodes we
	// knew, or the ssh.hosts map, and run the etcd probe on all of them
	nodes, offline := a.sshTargets(snap)
	if a.fp.cur != nil {
		a.fp.cur.Heavy = heavy
	}
	// etcdctl over SSH is the fallback for the kubectl-exec probe: skip the
	// three crictl execs per cycle while that probe answers and the API is up
	etcdScript := etcd.Script(a.cfg.Etcd, heavy, offline || a.etcdExec == nil || a.etcdExec.Err != nil)
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
		opts := nodeinfo.Options{Heavy: heavy, LogLines: a.cfg.Logs.Lines, LogSince: a.cfg.Logs.Since, PVPaths: pvPaths}
		if snap.VSphereConf != nil {
			opts.VCenters = snap.VSphereConf.VCenters
		}
		// OS STIG facts are collected only when asked for (S on the OS STIG
		// sub-tab): sysctl -a, package lists, find scans and config dumps are
		// the most expensive part of the probe and never run unrequested. The
		// config tier (certs, sysctls, config files, slow hardening commands)
		// rides on the heavy cycles for the same reason.
		prev := a.nodes[name]
		opts.OSStig = a.stigNext
		opts.Config = heavy || prev == nil || !prev.ConfigProbed
		opts.CPUSample = prev == nil || prev.Err != nil || prev.CPUStat.Total == 0
		if prev != nil && prev.Err == nil {
			opts.KubeletPID = prev.KubeletPID
		}
		if prev != nil {
			opts.KnownTarballs = prev.TarballKeys()
		}
		a.pending[name] = true
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			res := runner.Run(ctx, host, nodeinfo.Script(opts))
			info := nodeinfo.Parse(name, host, res.Stdout, res.Started)
			info.Duration = res.Finished.Sub(res.Started)
			info.ScriptSize = res.ScriptSize
			info.STIGRun = opts.OSStig
			if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
				msg := res.Err.Error()
				if s := strings.TrimSpace(res.Stderr); s != "" {
					msg += ": " + firstLine(s)
				}
				info.Err = fmt.Errorf("%s", msg)
			}
			return nodeMsg{seq: seq, info: info, opts: opts}
		})
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
					p.Err = fmt.Errorf("%s", firstLine(res.Err.Error()+" "+res.Stderr))
				}
				return etcdMsg{seq: seq, probe: p}
			})
		}
	}
	a.stigNext = false
	return tea.Batch(cmds...)
}

// sshTargetNames is sshTargets filtered by ssh.nodes, names only.
func (a *App) sshTargetNames(snap *k8s.Snapshot) []string {
	only := map[string]bool{}
	for _, n := range a.cfg.SSH.Nodes {
		only[n] = true
	}
	nodes, _ := a.sshTargets(snap)
	var out []string
	for i := range nodes {
		if len(only) == 0 || only[nodes[i].Name] {
			out = append(out, nodes[i].Name)
		}
	}
	return out
}

// sshTargets returns the nodes to collect from. When the API returned no
// nodes (apiserver/etcd down) it falls back to the last good list, then to
// the ssh.hosts map, and reports offline=true so every host gets the etcd
// probe (roles are unknown).
func (a *App) sshTargets(snap *k8s.Snapshot) ([]corev1.Node, bool) {
	if len(snap.Nodes) > 0 {
		return snap.Nodes, false
	}
	if len(a.knownNodes) > 0 {
		return a.knownNodes, true
	}
	var out []corev1.Node
	for _, name := range sortedKeys(a.cfg.SSH.Hosts) {
		out = append(out, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}})
	}
	return out, true
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
		if err, denied := client.Denied("pods/exec"); denied {
			// pods/exec refused earlier: do not exec into every etcd pod again
			return etcdExecMsg{seq: seq, probe: &etcd.Probe{Node: names[0], Collected: time.Now(), Dist: dist, Err: err, EtcdctlDiag: err.Error()}}
		}
		for _, n := range names {
			p := etcd.ExecProbe(ctx, client, n, podNames[n], dist)
			last = p
			if p.Err == nil && len(p.Members) > 0 {
				break
			}
			if client.NoteDenied("pods/exec", p.Err, false) {
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
	runner, seq, timeout := a.runner, a.seq, a.cfg.SSH.Timeout
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res := runner.Run(ctx, host, script)
		out := res.Stdout
		if res.Err != nil && strings.TrimSpace(out) == "" {
			out = "ssh: " + firstLine(res.Err.Error())
		}
		return s3CheckMsg{seq: seq, check: etcd.ParseS3Check(node, url, out)}
	}
}

func (a *App) recompute() {
	for name, ni := range a.nodes {
		if ni != nil && (len(ni.Journal) > 0 || len(ni.LogFiles) > 0) {
			// rke2's kubelet/containerd log to files rather than the journal
			srcs := []logs.Source{{Lines: ni.Journal}}
			for _, lf := range ni.LogFiles {
				srcs = append(srcs, logs.Source{Unit: logFileUnit(lf.Path), Lines: strings.Split(lf.Content, "\n")})
			}
			a.logSum[name] = logs.ClassifySources(srcs, time.Now())
		}
	}
	a.stigRes = stig.Evaluate(stig.Input{Snap: a.snap, Nodes: a.nodes, Etcd: a.etcd, EtcdExec: a.etcdExec})
	a.findings = checks.Evaluate(checks.Input{
		Snap: a.snap, Nodes: a.nodes, Etcd: a.etcd, EtcdExec: a.etcdExec, S3: a.s3, S3Reach: a.s3Reach, Logs: a.logSum, Stig: a.stigRes,
		HelmLatest: a.helmLatest, SSHEnabled: a.sshEnabled, SSHErr: a.sshErr, Cfg: a.cfg, Now: time.Now(), APIServer: a.apiServer(),
	})
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
		a.beginCycle(a.heavyNext || a.cycle%a.cfg.HeavyEvery == 0)
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
		a.timedRecompute()
		a.recordSnapshot()
		if a.fp.logger != nil && a.status == "" {
			if s := a.perfSummary(); s != "" {
				a.setStatus(s)
			}
		}
		var crdCmd tea.Cmd
		if a.onCRDs() {
			crdCmd = a.crdCountCmd()
		}
		return a, tea.Batch(a.collectCmds(a.snap), a.helmCmd(a.snap), a.etcdExecCmd(a.snap), crdCmd, a.tickCmd())
	case nodeMsg:
		if m.seq != a.seq {
			return a, nil
		}
		m.info.CPUFromPrev(a.nodes[m.info.Node])
		m.info.MergeHeavy(a.nodes[m.info.Node])
		m.info.MergeSTIG(a.nodes[m.info.Node])
		m.info.MergeConfig(a.nodes[m.info.Node])
		a.nodes[m.info.Node] = m.info
		delete(a.pending, m.info.Node)
		a.recordNodeProbe(m.info, m.opts)
		a.noteProbeDuration(m.info.Node, m.info.Duration)
		a.recordNode(m.info)
		return a, a.scheduleRecompute()
	case etcdMsg:
		if m.seq != a.seq {
			return a, nil
		}
		m.probe.Merge(a.etcd[m.probe.Node])
		a.etcd[m.probe.Node] = m.probe
		delete(a.etcdPend, m.probe.Node)
		a.recordEtcdProbe(m.probe)
		a.noteProbeDuration(m.probe.Node, m.probe.Duration)
		a.recordEtcd(m.probe)
		if name := m.probe.RKE2Config["etcd-s3-config-secret"]; name != "" && (a.s3 == nil || a.s3.Name != name) {
			return a, tea.Batch(a.scheduleRecompute(), a.s3Cmd(name))
		}
		return a, tea.Batch(a.scheduleRecompute(), a.s3CheckCmd(m.probe.Node))
	case s3Msg:
		a.s3 = m.info
		cmds := []tea.Cmd{a.scheduleRecompute()}
		for _, n := range sortedKeys(a.etcd) {
			cmds = append(cmds, a.s3CheckCmd(n))
		}
		return a, tea.Batch(cmds...)
	case s3CheckMsg:
		if m.seq == a.seq {
			a.s3Reach[m.check.Node] = m.check
			return a, a.scheduleRecompute()
		}
		return a, nil
	case helmMsg:
		a.helmLatest = m.latest
		return a, a.scheduleRecompute()
	case actionDoneMsg:
		return a, a.handleActionDone(m)
	case etcdExecMsg:
		if m.seq != a.seq {
			return a, nil
		}
		a.etcdExec = m.probe
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

func (a *App) handleKey(m tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := m.String()
	if key == "ctrl+c" {
		return a, tea.Quit
	}
	before := a.viewSignature()
	model, cmd := a.handleKeyInner(m)
	if a.viewSignature() != before {
		// the frame layout changed (tab, sub-tab, inspector depth, overlay):
		// repaint from scratch so no stale rows survive on any terminal
		cmd = tea.Batch(cmd, tea.ClearScreen)
	}
	return model, cmd
}

// viewSignature identifies the structural layout of the current view.
func (a *App) viewSignature() string {
	return fmt.Sprintf("%d|%s|%d|%d|%s", a.tab, a.subName(), len(a.inspect), a.overlay, a.logsNode)
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
			a.cursor[a.tab] = 0
			a.scroll[a.tab] = 0
			return a, cmd
		}
		return a, nil
	}
	for i, k := range tabKeys {
		if key == k {
			a.tab = tab(i)
			if a.onCRDs() {
				return a, a.crdCountCmd()
			}
			return a, nil
		}
	}
	if a.inInspect() {
		switch key {
		case "esc", "backspace", "q", "j", "k", "down", "up", "enter", "J", "K", "pgdown", "pgup", " ", "ctrl+d", "ctrl+u", "g", "G", "home", "end":
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
		a.closePodLogs()
		a.endCycle()
		a.fp.logger.Close()
		return a, tea.Quit
	case "P":
		a.detailTitle = "Footprint: what khealth costs the cluster and this host"
		a.detailLines = a.perfLines()
		a.detailScroll = 0
		a.overlay = ovDetail
	case "tab", "]":
		a.tab = (a.tab + 1) % tabCount
		if a.onCRDs() {
			return a, a.crdCountCmd()
		}
	case "shift+tab", "[":
		a.tab = (a.tab + tabCount - 1) % tabCount
		if a.onCRDs() {
			return a, a.crdCountCmd()
		}
	case "l", "right":
		a.setSub(1)
		if a.onCRDs() {
			return a, a.crdCountCmd()
		}
	case "h", "left":
		a.setSub(-1)
		if a.onCRDs() {
			return a, a.crdCountCmd()
		}
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
		a.client.ResetDenied() // retry the API calls that were refused
		if !a.refreshing {
			a.setStatus("full refresh (logs, images, tarballs)")
			return a, a.refreshCmd()
		}
	case "S":
		// OS STIG collection is explicit: only from its own sub-tab
		if a.tab == tabSecurity && a.subName() == "OS STIG" {
			switch {
			case a.runner == nil:
				a.setStatus("SSH unavailable: " + a.sshErr)
			case !a.sshEnabled:
				a.setStatus("enable SSH collection first (s)")
			case a.snap == nil:
				a.setStatus("waiting for the first API snapshot")
			default:
				a.stigNext = true
				a.setStatus(fmt.Sprintf("collecting OS STIG facts from %d node(s)", len(a.sshTargetNames(a.snap))))
				return a, a.collectCmds(a.snap)
			}
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
	case "m":
		if a.tab == tabSecurity {
			a.hideManual = !a.hideManual
			a.cursor[a.tab] = 0
			a.scroll[a.tab] = 0
		}
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
		// help uses the scrollable detail overlay (j/k, PgUp/PgDn, esc)
		a.detailTitle = "Help"
		a.detailLines = helpLines()
		a.detailScroll = 0
		a.overlay = ovDetail
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
		a.cursor[a.tab] = 0
		a.scroll[a.tab] = 0
		a.clamp(a.currentContent())
	case "G", "end":
		a.cursor[a.tab] = 1 << 30
		a.scroll[a.tab] = 1 << 30
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
	// direction of travel, or stay put when there is none
	for i := target; i >= 0 && i < len(rows); i += dir {
		if rows[i].id != "" {
			a.cursor[a.tab] = i
			break
		}
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
		if rows[a.cursor[a.tab]].id == "" {
			a.cursor[a.tab] = nearestRow(rows, a.cursor[a.tab])
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
	switch a.overlay {
	case ovConfirm, ovRevisions:
		return a.handleActionOverlayKey(key)
	case ovInspect:
		return a.handleInspectKey(key)
	case ovPodLogs:
		return a.handleLogKey(key)
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

// nsRow describes a namespace for the picker: PSA level and privileged pods.
func (a *App) nsRow(name string) []string {
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
	psa := ""
	switch enforce {
	case "privileged":
		psa = styleWarn.Render("privileged")
	case "baseline":
		psa = styleInfo.Render("baseline")
	case "restricted":
		psa = styleOK.Render("restricted")
	case "":
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
	case enforce == "" && (priv > 0 || hostNS > 0) && !k8s.IsSystemNamespace(name):
		note = styleWarn.Render("privileged workloads without a PSA policy")
	case enforce == "restricted" && (priv > 0 || hostNS > 0):
		note = styleCrit.Render("privileged pods despite restricted (pre-existing or exempt)")
	case k8s.IsSystemNamespace(name):
		note = styleDim.Render("system")
	}
	return []string{name, psa, privTxt, fmt.Sprint(pods), note}
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
	return fitScreen(b.String(), a.width, a.height)
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
	keys := []string{"tab switch", "←/→ sub-tab", "j/k move", "enter inspect", "n namespace", "/ filter", "a problems", "r refresh", "R full", "s ssh", "? help", "q quit"}
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
		lines = append(lines, a.nsInput.View(), styleDim.Render("PSA = pod-security.kubernetes.io/enforce label (warn/audit in brackets); PRIV = running pods with privileged containers / host namespaces"), "")
		opts := a.nsOptions()
		visible := h - 7
		start := 0
		if a.nsCursor >= visible {
			start = a.nsCursor - visible + 1
		}
		// size the columns from every namespace, not just the visible window,
		// so the layout stays put while scrolling
		rows := make([][]string, 0, len(opts))
		for _, o := range opts {
			rows = append(rows, a.nsRow(o))
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
	case ovInspect:
		title, lines = a.renderInspect()
	case ovPodLogs:
		title, lines = a.renderPodLogs()
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
		"  tab / shift+tab / [ ]    next / previous tab        1-9 0 - =   jump to tab",
		"  left / right or h / l    previous / next sub-tab inside the current tab",
		"  j/k or arrows            move selection / scroll    g / G     top / bottom",
		"  PgUp / PgDn / space      page                       enter     open detail for the selected row",
		"  esc                      close overlay / clear filter",
		"",
		styleBold.Render("Everywhere"),
		"  n      choose namespace (shows PSA level + privileged pods; filters Inspect, Events, Storage, Helm)",
		"  /      filter rows on the current tab (substring)          esc   clear filter / step back",
		"  a      toggle problems-only view (Overview, Inspect, Events, Security, Resources)",
		"  r      refresh now (API + light SSH collection)             R     full refresh: journal logs, images, tarballs, PV du (not the OS STIG)",
		"  s      toggle SSH collection on/off                        q     quit (steps back first when inside an object/log view)",
		"  P      footprint: what khealth itself costs the API server, the nodes (remote CPU per probe) and this host",
		"",
		styleBold.Render("Tab-specific keys"),
		"  Inspect    enter  open the object (references, YAML)      t   rollout restart (Deployment/DaemonSet/StatefulSet, confirmed)",
		"             L      tail logs of the selected pod / controller's pods   p   jump to the Pods sub-tab",
		"  Helm       enter  values + history                        u   upgrade to newest known version (confirmed)   b   rollback (pick revision, confirmed)",
		"  Nodes      enter  node dashboard: gauges, security runtime-vs-boot, services, filesystems, certs",
		"  etcd       enter  raw probe output and config dumps",
		"  Logs       enter  node lines, enter again = full line + explanation; a = include info lines",
		"  Events     enter  open the involved object in the inspector",
		"  Security   ←/→    Rules / Node hardening / OS STIG        enter  rule detail, fix and the STIG's own check procedure",
		"             scorecards per benchmark (and per node): score = not a finding / (not a finding + open), as SCC / OpenSCAP report",
		"             a      hide passing rules                      m      hide MANUAL rules",
		"             S      OS STIG sub-tab only: run the DISA OS STIG collection on the nodes (sysctl -a, packages, audit rules,",
		"                    file sweep, config dumps; a few seconds per node). Never runs on its own - not at launch, not on r/R.",
		"                    Results stay until the next S; the header shows how old they are",
		"",
		styleBold.Render("Log viewer (L)"),
		"  [ ] / tab  switch container    { }  next/prev pod    p  previous instance    f  follow    w  wrap    T  timestamps short/off/full    H  highlighting    r  reload    esc  close",
		"             JSON, logfmt (key=value) and klog lines are colour-coded automatically: keys dim, level by severity, messages bold",
		"",
		styleBold.Render("Tabs"),
		"  Overview   cluster summary, API health, ranked findings",
		"  Nodes      conditions + live CPU/mem/disk/load from SSH (or metrics-server), certs, services",
		"  Inspect    controllers (deploy/ds/sts/job/cronjob) then pods not owned by one; p = all pods; t = rollout restart;",
		"             enter opens the Object sub-tab: owner/child/secret/configmap/PVC/SA references, enter again drills down, esc back",
		"             L = tail logs of the selected pod (or the controller's first pod): [ ] switch container, { } switch pod,",
		"                 p previous instance, f follow on/off, w wrap, r reload, / not needed - lines stream live",
		"             Resources sub-tab: every API type (built-in + CRDs) with instance counts; enter lists instances, enter again inspects one",
		"  etcd       members, health, db size/quota/fragmentation, fsync latency, config source, snapshots/backups",
		"  Storage    StorageClasses, CSI drivers, PVs/PVCs and node filesystems",
		"  Events     warning events",
		"  Addons     CNI, CSI, DNS/ingress/metrics, Rancher management, registries.yaml, rke2 HelmCharts",
		"  Helm       releases (enter = values applied), optional update check;",
		"             u = helm upgrade to the newest known chart version, b = helm rollback to a chosen revision (both confirm first;",
		"             need the helm CLI; --read-only disables them; rke2-bundled charts are refused)",
		"  Images     per-node image inventory, unused images, airgap tarball contents vs running",
		"  Security   Rules: DISA Kubernetes / RKE2 / Rancher MCM STIG + CIS checks from component flags, kubelet config, PSA, RBAC, node facts",
		"             Node hardening: per-node runtime vs boot facts (SELinux, FIPS, auditd, firewall...) and the OS STIG summary",
		"             OS STIG: every rule of the node's DISA RHEL 8/9/10 or Ubuntu 22.04/24.04 STIG - empty until you press S",
		"  Logs       rke2/kubelet/containerd/rancher-system-agent logs classified into startup-noise / warnings / errors (Rancher plan events flag config rewrites)",
		"             enter on a node lists its lines; enter on a line shows the full text + explanation; esc goes back; a shows info lines",
		"  RKE2/k3s   config.yaml(.d), data-dir, server/manifests (HelmChartConfig etc.), static pod manifests, audit/PSS policies, config drift, API endpoint vs tls-san vs cert",
		"  kubeadm    (same tab on upstream clusters) kubeadm-config ClusterConfiguration, API endpoint vs certSANs vs apiserver.crt",
		"",
		styleDim.Render("Config: ~/.config/k8s-health-tui/config.yaml (khealth --init-config writes the annotated example)"),
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
