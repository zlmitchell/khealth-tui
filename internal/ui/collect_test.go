package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/nodeinfo"
)

func TestTabNeedsAndPinned(t *testing.T) {
	a := testApp()
	for tb, want := range map[tab]string{tabOverview: "", tabLogs: tierJournal, tabImages: tierImages, tabStorage: tierPV, tabRKE2: tierConfig, tabSecurity: tierConfig, tabEtcd: tierEtcdExec, tabAddons: tierImages} {
		a.tab = tb
		if got := a.tabNeeds().String(); got != want {
			t.Errorf("tab %v needs %q, want %q", tb, got, want)
		}
	}
	a.tab = tabOverview
	a.cfg.Collect.Always = []string{"journal", "PV "}
	if got := a.wanted().String(); got != "journal+pv" {
		t.Errorf("pinned: %q", got)
	}
}

// nodeTiers: R forces everything; a wanted tier is collected when its
// facts are stale at the heavy_every cadence; the journal has an hourly
// floor on every tab; config on first contact.
func TestNodeTiers(t *testing.T) {
	a := testApp()
	a.cfg.Refresh, a.cfg.HeavyEvery = 30*time.Second, 6 // cadence 3 min
	a.cfg.Collect.JournalBackground = time.Hour
	now := time.Now()
	fresh := &nodeinfo.Info{Node: "n", ConfigProbed: true, ConfigCollected: now, JournalAt: now, ImagesAt: now, PVsAt: now}
	old := &nodeinfo.Info{Node: "n", ConfigProbed: true, ConfigCollected: now.Add(-10 * time.Minute), JournalAt: now.Add(-10 * time.Minute), ImagesAt: now.Add(-10 * time.Minute), PVsAt: now.Add(-10 * time.Minute)}
	ancient := &nodeinfo.Info{Node: "n", ConfigProbed: true, ConfigCollected: now.Add(-2 * time.Hour), JournalAt: now.Add(-2 * time.Hour)}
	type want struct{ j, i, p, c bool }
	cases := []struct {
		name  string
		prev  *nodeinfo.Info
		tiers tierSet
		force bool
		want  want
	}{
		{"overview, fresh", fresh, tierSet{}, false, want{}},
		{"overview, first contact", nil, tierSet{}, false, want{c: true, j: true}}, // journal floor: never collected
		{"R", fresh, tierSet{}, true, want{true, true, true, true}},
		{"logs tab, fresh journal", fresh, tierSet{tierJournal: true}, false, want{}},
		{"logs tab, stale journal", old, tierSet{tierJournal: true}, false, want{j: true}},
		{"images tab, stale", old, tierSet{tierImages: true}, false, want{i: true}},
		{"storage tab, stale", old, tierSet{tierPV: true}, false, want{p: true}},
		{"rke2 tab, stale config", old, tierSet{tierConfig: true}, false, want{c: true}},
		{"overview, journal floor due", ancient, tierSet{}, false, want{j: true}},
		{"overview, config never probed", &nodeinfo.Info{Node: "n", JournalAt: now}, tierSet{}, false, want{c: true}},
	}
	for _, c := range cases {
		j, i, p, cf := a.nodeTiers(c.prev, c.tiers, c.force)
		if (want{j, i, p, cf}) != c.want {
			t.Errorf("%s: journal=%v images=%v pv=%v config=%v, want %+v", c.name, j, i, p, cf, c.want)
		}
	}
	// no floor configured: the ancient journal stays stale on Overview
	a.cfg.Collect.JournalBackground = 0
	if j, _, _, _ := a.nodeTiers(ancient, tierSet{}, false); j {
		t.Error("journal collected on Overview without a floor")
	}
	// the tier names go to the perf log
	o := nodeinfo.Options{Journal: true, PVs: true, Config: true}
	if o.Tiers() != "journal+pv+config" || !o.Heavy() || (nodeinfo.Options{Config: true}).Heavy() {
		t.Errorf("tiers: %q heavy=%v", o.Tiers(), o.Heavy())
	}
}

// onEnter fires a probe carrying only the tab's stale tier for nodes that
// have been contacted before; fresh facts, first contact and other tabs
// fire nothing.
func TestOnEnterFiresStaleTier(t *testing.T) {
	a := newDriveApp(t)
	a.cfg.Refresh, a.cfg.HeavyEvery = 30*time.Second, 6
	for _, ni := range a.nodes {
		ni.Err = nil
		ni.ConfigProbed, ni.ConfigCollected = true, time.Now()
		ni.JournalAt = time.Now().Add(-time.Hour)
		ni.ImagesAt = time.Now()
	}
	a.tab = tabImages
	if cmd := a.onEnter(); cmd != nil {
		if _, ok := cmd().(tea.BatchMsg); ok && len(a.collecting) > 0 {
			t.Errorf("fresh images: probes fired for %v", a.collecting)
		}
	}
	a.tab = tabLogs
	cmd := a.onEnter()
	if cmd == nil || len(a.collecting) == 0 {
		t.Fatalf("stale journal: no probe fired (collecting=%v)", a.collecting)
	}
	for n, tiers := range a.collecting {
		if tiers != "journal" || !a.pending[n] {
			t.Errorf("node %s: tiers %q pending=%v, want journal only", n, tiers, a.pending[n])
		}
	}
	// the status line names the age and the probe in flight
	if st := a.tierStatus(tierJournal); !strings.Contains(st, "journal from") || !strings.Contains(st, "collecting") {
		t.Errorf("status: %q", st)
	}
	// the same key path: switching tabs with the number key runs onEnter
	a.collecting = map[string]string{}
	a.pending = map[string]bool{}
	for _, ni := range a.nodes {
		ni.ImagesAt = time.Now().Add(-time.Hour)
	}
	key(t, a, "9")
	if a.tab != tabImages || len(a.collecting) == 0 {
		t.Errorf("tab 9 should be Images with a probe fired, collecting=%v", a.collecting)
	}
	for _, ni := range a.nodes {
		ni.ImagesAt = time.Time{}
		ni.Images = nil
	}
	if st := a.tierStatus(tierImages); !strings.Contains(st, "collecting from") {
		t.Errorf("status with nothing collected yet: %q", st)
	}
}

func TestEtcdExecWanted(t *testing.T) {
	a := testApp()
	a.cfg.Refresh, a.cfg.HeavyEvery = 30*time.Second, 6
	if !a.etcdExecWanted(a.snap) {
		t.Error("small cluster: exec view every tick")
	}
	if a.etcdExecWanted(nil) {
		t.Error("no snapshot: nothing to exec into")
	}
	// staleness drives the on-enter refresh of the etcd tab
	if !a.etcdExecStale() {
		t.Error("no exec view yet: stale")
	}
	a.etcdExec = &etcd.Probe{Node: "cp-1", Collected: time.Now()}
	if a.etcdExecStale() {
		t.Error("a fresh exec view is not stale")
	}
	a.etcdExec.Collected = time.Now().Add(-time.Hour)
	if !a.etcdExecStale() {
		t.Error("an hour-old exec view is stale at a 3 min cadence")
	}
}

// A light probe answering leaves the STIG results alone; a config probe,
// the snapshot and an etcd probe mark them dirty.
func TestStigDirty(t *testing.T) {
	a := testApp()
	a.secScanned = true
	a.stigDirty = true
	a.recompute()
	if a.stigDirty || a.stigRes == nil {
		t.Fatalf("first recompute must evaluate: dirty=%v res=%v", a.stigDirty, a.stigRes != nil)
	}
	before := a.stigRes
	a.recompute()
	if len(a.stigRes) != len(before) || a.stigDirty {
		t.Error("clean recompute should keep the results")
	}
	a.Update(nodeMsg{gen: a.gen, info: &nodeinfo.Info{Node: "cp-1"}, opts: nodeinfo.Options{}})
	if a.stigDirty {
		t.Error("a light probe must not dirty the STIG results")
	}
	a.Update(nodeMsg{gen: a.gen, info: &nodeinfo.Info{Node: "cp-1"}, opts: nodeinfo.Options{Config: true}})
	if !a.stigDirty {
		t.Error("a config probe must dirty the STIG results")
	}
}
