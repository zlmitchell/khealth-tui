package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/perf"
)

func TestFootprintCycleAccounting(t *testing.T) {
	a := testApp()
	a.fp = newFootprint()
	a.snap.FetchDuration = 1200 * time.Millisecond
	a.snap.Traffic.Requests, a.snap.Traffic.BytesIn = 27, 3<<20
	a.cycle = 1
	a.beginCycle(true)
	info := &nodeinfo.Info{Node: "cp-1", Duration: 2 * time.Second, OutBytes: 40000, Cost: perf.RemoteCost{User: 0.4, Sys: 0.1, Load1: 0.5, Parsed: true}}
	a.recordNodeProbe(info, nodeinfo.Options{Journal: true, Images: true, PVs: true})
	a.recordEtcdProbe(&etcd.Probe{Node: "cp-1", Duration: time.Second, Cost: perf.RemoteCost{User: 0.2, Parsed: true}})
	a.timedRecompute()
	if a.fp.cur == nil || len(a.fp.cur.Probes) != 2 || a.fp.cur.Recomputes != 1 || !a.fp.cur.Heavy {
		t.Fatalf("cycle record %+v", a.fp.cur)
	}
	lines := strings.Join(a.perfLines(), "\n")
	for _, want := range []string{"27 requests", "3.0 MB in", "node+journal+images+pv", "0.50s", "etcd", "cp-1"} {
		if !strings.Contains(lines, want) {
			t.Errorf("overlay missing %q:\n%s", want, lines)
		}
	}
	a.endCycle()
	if a.fp.cur != nil || len(a.fp.hist) != 1 || a.fp.hist[0].API.Requests != 27 {
		t.Fatalf("history %+v", a.fp.hist)
	}
	// P opens the overlay
	m, _ := a.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("P")})
	if b := m.(*App); b.overlay != ovDetail || !strings.Contains(b.detailTitle, "Footprint") {
		t.Fatalf("P did not open the footprint overlay: %v %q", b.overlay, b.detailTitle)
	}
}

func TestSkipProbeStillRunningAndBackoff(t *testing.T) {
	a := testApp()
	a.fp = newFootprint()
	a.cfg.Refresh = 30 * time.Second
	a.cycle = 3
	a.beginCycle(false)
	if r := a.skipProbe("cp-1"); r != "" {
		t.Fatalf("unexpected skip: %s", r)
	}
	a.pending["cp-1"] = true
	if r := a.skipProbe("cp-1"); !strings.Contains(r, "still running") {
		t.Fatalf("overlapping probe not skipped: %q", r)
	}
	delete(a.pending, "cp-1")
	// a slow probe arms the backoff for the next cycle only
	a.noteProbeDuration("cp-1", 20*time.Second)
	a.cycle++
	if r := a.skipProbe("cp-1"); !strings.Contains(r, "backoff") {
		t.Fatalf("slow node not backed off: %q", r)
	}
	a.cycle++
	if r := a.skipProbe("cp-1"); r != "" {
		t.Fatalf("backoff did not expire: %q", r)
	}
	a.noteProbeDuration("w-1", 2*time.Second)
	if r := a.skipProbe("w-1"); r != "" {
		t.Fatalf("fast node backed off: %q", r)
	}
	a.cfg.SSH.Backoff = false
	a.noteProbeDuration("w-1", time.Minute)
	if r := a.skipProbe("w-1"); r != "" {
		t.Fatalf("backoff applied while disabled: %q", r)
	}
	if a.fp.skips["cp-1"] != 2 {
		t.Fatalf("skips not counted: %v", a.fp.skips)
	}
}

func TestRecomputeIsCoalesced(t *testing.T) {
	a := testApp()
	a.fp = newFootprint()
	a.gen = 1
	info := nodeinfo.Parse("cp-1", "10.0.0.1", nodeSample, time.Now())
	_, c1 := a.Update(nodeMsg{gen: 1, info: info})
	_, c2 := a.Update(nodeMsg{gen: 1, info: info})
	if c1 == nil || c2 != nil {
		t.Fatalf("expected one scheduled recompute, got %v %v", c1 != nil, c2 != nil)
	}
	before := len(a.findings)
	m, c3 := a.Update(recomputeMsg{})
	if c3 != nil || m.(*App).fp.recomputeTimer {
		t.Fatal("recompute timer not cleared")
	}
	if _, c4 := a.Update(nodeMsg{gen: 1, info: info}); c4 == nil {
		t.Fatal("recompute not re-armed after it ran")
	}
	_ = before
}

func TestInspectYAMLPageScrolls(t *testing.T) {
	a := testApp()
	a.height = 20
	var dump []string
	for i := 0; i < 60; i++ {
		dump = append(dump, fmt.Sprintf("line-%02d", i))
	}
	a.inspect = []inspectLevel{{meta: []string{"kind: Pod", "phase: Running"}, refs: []k8s.ObjRef{{Via: "owner", Kind: "ReplicaSet", Name: "rs-1"}}, dump: dump}}
	_, lines := a.renderInspect()
	body := strings.Join(lines, "\n")
	if !strings.Contains(body, "References (1)") || !strings.Contains(body, "line-00") {
		t.Fatalf("unscrolled view must show references and the YAML start:\n%s", body)
	}
	// j past the last reference scrolls into the YAML: header and references go away
	a.handleInspectKey("j")
	a.handleInspectKey("j")
	_, lines = a.renderInspect()
	body = strings.Join(lines, "\n")
	if strings.Contains(body, "References (1)") || strings.Contains(body, "kind: Pod") {
		t.Fatalf("scrolled view must drop the header so the YAML fills the body:\n%s", body)
	}
	if !strings.HasPrefix(strings.TrimSpace(ansi.Strip(lines[1])), "YAML") || !strings.Contains(lines[2], "line-02") {
		t.Fatalf("YAML should start at the top from the scrolled line:\n%s", body)
	}
	// k twice back to line 1 restores the references
	a.handleInspectKey("k")
	a.handleInspectKey("k")
	_, lines = a.renderInspect()
	if !strings.Contains(strings.Join(lines, "\n"), "References (1)") {
		t.Fatal("references not restored at line 1")
	}
}
