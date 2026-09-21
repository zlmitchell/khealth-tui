package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Tab-driven collection (docs/ARCHITECTURE.md §7): the light tiers (API
// snapshot, base probe, etcd probe) run every tick because the header, the
// Overview and every timeline are made of them. The demand tiers - the
// journal, the image inventories, the du of hostPath PVs, the config tier
// and the etcd exec view - are collected because the visible tab needs
// them now, `collect.always` pins them, R forced them, or their
// background floor is due. Each tab that shows a tier prints how old its
// facts are, and opening it fires the probe at once when they are stale.

const (
	tierJournal  = "journal"
	tierImages   = "images"
	tierPV       = "pv"
	tierConfig   = "config"
	tierEtcdExec = "etcd-exec"
)

// tierSet is the set of demand tiers wanted.
type tierSet map[string]bool

func (t tierSet) String() string {
	var out []string
	for k := range t {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// tabNeeds is what the visible tab (and sub-tab) wants kept fresh.
func (a *App) tabNeeds() tierSet {
	n := tierSet{}
	switch a.tab {
	case tabLogs:
		n[tierJournal] = true
	case tabImages:
		n[tierImages] = true
	case tabStorage:
		n[tierPV] = true
	case tabRKE2:
		n[tierConfig] = true
	case tabSecurity:
		n[tierConfig] = true
	case tabEtcd:
		n[tierEtcdExec] = true
	case tabAddons:
		// registries.yaml vs the pull dry run is an Addons table
		n[tierImages] = true
	}
	return n
}

// pinned is collect.always: tiers that keep their cadence on every tab.
func (a *App) pinned() tierSet {
	n := tierSet{}
	for _, t := range a.cfg.Collect.Always {
		n[strings.ToLower(strings.TrimSpace(t))] = true
	}
	return n
}

// wanted is tabNeeds ∪ pinned.
func (a *App) wanted() tierSet {
	w := a.tabNeeds()
	for t := range a.pinned() {
		w[t] = true
	}
	return w
}

// tierCadence is how often a wanted tier is refreshed while it stays
// wanted: every heavy_every refreshes, as the heavy cycle did.
func (a *App) tierCadence() time.Duration {
	return time.Duration(max(a.cfg.HeavyEvery, 1)) * a.cfg.Refresh
}

// stale reports whether facts collected at `at` are older than `every`
// (or were never collected).
func stale(at time.Time, every time.Duration) bool {
	return at.IsZero() || time.Since(at) >= every
}

// nodeTiers decides which demand tiers this node's probe carries this
// cycle. force is R (or SSH re-enabled, or the first cycle): everything.
// Otherwise a wanted tier that is stale, the journal background floor, and
// the config tier on first contact.
func (a *App) nodeTiers(prev *nodeinfo.Info, want tierSet, force bool) (journal, images, pvs, config bool) {
	cad := a.tierCadence()
	due := func(tier string) bool {
		return want[tier] && stale(prev.TierAge(tier), cad)
	}
	journal = force || due(tierJournal)
	if bg := a.cfg.Collect.JournalBackground; !journal && bg > 0 && stale(prev.TierAge(tierJournal), bg) {
		journal = true
	}
	images = force || due(tierImages)
	pvs = force || due(tierPV)
	config = force || prev == nil || !prev.ConfigProbed || due(tierConfig)
	return
}

// nodeOptions builds one node's probe options for the tiers decided.
func (a *App) nodeOptions(snap *k8s.Snapshot, name string, pvPaths []string, journal, images, pvs, config bool) nodeinfo.Options {
	opts := nodeinfo.Options{Journal: journal, Images: images, PVs: pvs, Config: config, LogLines: a.cfg.Logs.Lines, LogSince: a.cfg.Logs.Since, PVPaths: pvPaths}
	if snap != nil && snap.VSphereConf != nil {
		opts.VCenters = snap.VSphereConf.VCenters
	}
	setNetTargets(&opts, snap, name)
	prev := a.nodes[name]
	opts.CPUSample = prev == nil || prev.Err != nil || prev.CPUStat.Total == 0
	if prev != nil && prev.Err == nil {
		opts.KubeletPID = prev.KubeletPID
	}
	if prev != nil {
		opts.KnownTarballs = prev.TarballKeys()
	}
	return opts
}

// pvPathsOf lists the hostPath/local PV directories (local-path-provisioner
// etc.) the pv tier measures with du.
func pvPathsOf(snap *k8s.Snapshot) []string {
	var out []string
	if snap == nil {
		return nil
	}
	for i := range snap.PVs {
		pv := &snap.PVs[i]
		if pv.Spec.HostPath != nil {
			out = append(out, pv.Spec.HostPath.Path)
		} else if pv.Spec.Local != nil {
			out = append(out, pv.Spec.Local.Path)
		}
	}
	return out
}

// onEnter fires the probes a freshly opened tab needs when their facts
// are missing or stale, so the tab does not wait for the next tick (the
// Inspect tab's CRD counts already work this way). Nodes with a probe in
// flight or in backoff are left to the tick.
func (a *App) onEnter() tea.Cmd {
	if a.snap == nil {
		return nil
	}
	var cmds []tea.Cmd
	if a.onCRDs() {
		cmds = append(cmds, a.crdCountCmd())
	}
	need := a.tabNeeds()
	if need[tierEtcdExec] && a.etcdExecStale() {
		cmds = append(cmds, a.etcdExecCmd(a.snap))
	}
	delete(need, tierEtcdExec)
	if len(need) == 0 || !a.sshEnabled || a.runner == nil {
		return tea.Batch(cmds...)
	}
	nodes, _ := a.sshTargets(a.snap)
	only := map[string]bool{}
	for _, n := range a.cfg.SSH.Nodes {
		only[n] = true
	}
	pvPaths := pvPathsOf(a.snap)
	timeout := 6 * a.cfg.SSH.Timeout
	for i := range nodes {
		n := &nodes[i]
		name := n.Name
		if len(only) > 0 && !only[name] || a.skipProbe(name) != "" {
			continue
		}
		prev := a.nodes[name]
		if prev == nil {
			continue // first contact is the tick's job (it carries the CPU sample)
		}
		journal, images, pvs, config := a.nodeTiers(prev, need, false)
		// only the tab's own tiers, and only when stale: the journal floor
		// and first-contact config belong to the tick
		journal, images, pvs = journal && need[tierJournal], images && need[tierImages], pvs && need[tierPV]
		config = config && need[tierConfig] && prev.ConfigProbed
		if !journal && !images && !pvs && !config {
			continue
		}
		opts := a.nodeOptions(a.snap, name, pvPaths, journal, images, pvs, config)
		a.collecting[name] = opts.Tiers()
		cmds = append(cmds, a.nodeProbeCmd(name, a.nodeAddress(n), opts, timeout))
	}
	return tea.Batch(cmds...)
}

// etcdExecStale: the exec view is refreshed every tick on clusters with up
// to five members; larger ones only while the etcd tab is open, when a
// quorum finding is pending, or when the view is older than heavy_every.
func (a *App) etcdExecStale() bool {
	if a.etcdExec == nil {
		return true
	}
	return stale(a.etcdExec.Collected, a.tierCadence())
}

// etcdExecWanted decides whether the tick runs the exec probe this cycle.
func (a *App) etcdExecWanted(snap *k8s.Snapshot) bool {
	if snap == nil {
		return false
	}
	if a.pinned()[tierEtcdExec] || a.tab == tabEtcd || a.heavyNext {
		return true
	}
	if len(snap.EtcdPods()) <= 5 {
		return true
	}
	for _, f := range a.findings {
		if f.Area == "etcd" && strings.Contains(f.Message, "quorum") {
			return true
		}
	}
	return a.etcdExecStale()
}

// tierStatus is the "journal from 4 min ago · collecting" line a tab that
// shows a demand tier prints: the oldest node's age, how many nodes never
// delivered it, and whether a probe carrying it is in flight.
func (a *App) tierStatus(tier string) string {
	if !a.sshEnabled || a.runner == nil {
		return ""
	}
	var oldest time.Time
	never, have := 0, 0
	for _, ni := range a.nodes {
		if ni == nil || ni.Err != nil {
			continue
		}
		at := ni.TierAge(tier)
		if at.IsZero() {
			never++
			continue
		}
		have++
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	inFlight := 0
	for name, tiers := range a.collecting {
		if a.pending[name] && strings.Contains(tiers, tier) {
			inFlight++
		}
	}
	label := map[string]string{tierJournal: "journal", tierImages: "image inventory", tierPV: "PV usage", tierConfig: "config facts"}[tier]
	var txt string
	switch {
	case have == 0 && inFlight > 0:
		txt = label + ": collecting from " + fmt.Sprint(inFlight) + " nodes"
	case have == 0:
		txt = label + ": not collected yet (opens on this tab; R forces it)"
	default:
		txt = label + " from " + age(oldest) + " ago"
		if never > 0 {
			txt += fmt.Sprintf(", %d nodes missing", never)
		}
		if inFlight > 0 {
			txt += " · collecting"
		}
	}
	if a.pinned()[tier] {
		txt += " · pinned (collect.always)"
	}
	return txt
}
