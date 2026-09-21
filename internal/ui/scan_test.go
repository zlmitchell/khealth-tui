package ui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
)

// scanning returns a test app with a two-node scan in flight, cp-1 answered.
func scanning(t *testing.T) *App {
	t.Helper()
	a := testApp()
	a.tab, a.secScanned = tabSecurity, true
	a.runner = &sshrun.Runner{} // never run: the stage commands are only created
	sc := newSecScan([]string{"cp-1", "w-1"}, map[string]string{"cp-1": "10.0.0.1", "w-1": "10.0.0.2"})
	sc.started = time.Now().Add(-3 * time.Second)
	delete(sc.want, "cp-1")
	sc.stage["cp-1"], sc.took["cp-1"] = len(sc.stages), 4200*time.Millisecond
	sc.stage["w-1"] = 1
	a.scan = sc
	a.recompute()
	return a
}

// TestScanChecklist: while nodes are pending every Security sub-tab shows the
// checklist (ticked rules, per-node state) instead of any table, and the
// state survives leaving and returning to the tab.
func TestScanChecklist(t *testing.T) {
	a := scanning(t)
	for sub := 0; sub < 3; sub++ {
		a.sub[tabSecurity] = sub
		v := ansi.Strip(a.View())
		for _, want := range []string{"Security scan running: 62%  -  1/2 nodes answered", "STIG/CIS rules from the API data", "cp-1", "done in 4.2s", "4/4 stages", "w-1", "1/4 stages", "files: file modes"} {
			if !strings.Contains(v, want) {
				t.Errorf("sub-tab %d: %q missing:\n%s", sub, want, v)
			}
		}
		if strings.Contains(v, "STIG / CIS checks") || strings.Contains(v, "DISA OS STIG rules") || strings.Contains(v, "Node OS hardening") {
			t.Errorf("sub-tab %d shows a results table during the scan", sub)
		}
	}
	a.tab = tabNodes
	if v := ansi.Strip(a.View()); !strings.Contains(v, "scan 62% 1/2 nodes") {
		t.Errorf("header does not carry the scan on another tab: %q", v)
	}
	a.tab = tabSecurity
	if v := ansi.Strip(a.View()); !strings.Contains(v, "Security scan running") {
		t.Errorf("checklist gone after tabbing away and back")
	}
}

// TestScanEscPeek: esc during the scan asks first; enter shows the partial
// tables with a banner, esc keeps the checklist.
func TestScanEscPeek(t *testing.T) {
	a := scanning(t)
	a.sub[tabSecurity] = 0
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if a.overlay != ovScanPeek {
		t.Fatalf("esc did not open the warning, overlay=%v", a.overlay)
	}
	if v := ansi.Strip(a.View()); !strings.Contains(v, "1 node(s) have not returned") {
		t.Errorf("warning text missing:\n%s", v)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if a.overlay != ovNone || a.scan.peek {
		t.Fatalf("esc on the warning should keep waiting: overlay=%v peek=%v", a.overlay, a.scan.peek)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !a.scan.peek || a.overlay != ovNone {
		t.Fatalf("enter should show partial results: peek=%v overlay=%v", a.scan.peek, a.overlay)
	}
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "STIG / CIS checks") || !strings.Contains(v, "security scan still running: 62%, 1/2 nodes answered") {
		t.Errorf("partial results with banner expected:\n%s", v)
	}
}

// TestScanStagesAndFinish: a stage answer merges its facts and starts the
// next stage; the last stage hands the facts to the node and settles it; a
// failed stage records the error; the results appear when the last node is
// in, and a regular probe answer never settles a node.
func TestScanStagesAndFinish(t *testing.T) {
	a := scanning(t)
	a.nodes["w-1"] = nodeinfo.Parse("w-1", "10.0.0.2", nodeSample, time.Now())
	// a regular answer does not settle the scan
	a.Update(nodeMsg{gen: a.gen, info: &nodeinfo.Info{Node: "w-1", Collected: time.Now()}, opts: nodeinfo.Options{}})
	if !a.scan.want["w-1"] {
		t.Fatalf("regular answer must not settle the scan")
	}
	// stage 2 of 4 lands with facts: merged, progress advances, next stage asked for
	out := "===STIGSTAT\n600|root|root|0|0|regular file|/etc/shadow\n===PERF\n0.10 0.20 0.30 1/2 3\n0m0.20s 0m0.10s\n0m0.30s 0m0.10s\n===END\n"
	_, cmd := a.Update(stigStageMsg{gen: a.gen, node: "w-1", stage: "files", out: out, dur: 700 * time.Millisecond})
	if a.scan.stage["w-1"] != 2 || cmd == nil {
		t.Fatalf("stage not counted / next stage not started: stage=%d cmd=%v", a.scan.stage["w-1"], cmd)
	}
	if p := a.scan.facts["w-1"].STIGStat["/etc/shadow"]; p.Mode != "600" {
		t.Errorf("stage facts not merged: %+v", a.scan.facts["w-1"].STIGStat)
	}
	if a.nodes["w-1"].STIGProbed {
		t.Errorf("facts adopted before the last stage")
	}
	if p := a.scan.percent(); p != 100*(4+2)/8 {
		t.Errorf("percent = %d", p)
	}
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "2/4 stages") || !strings.Contains(v, "accounts:") || !strings.Contains(v, "75%") {
		t.Errorf("progress line missing:\n%s", v)
	}
	// a stale generation is ignored
	a.Update(stigStageMsg{gen: a.gen + 1, node: "w-1", stage: "accounts", out: "===END\n"})
	if a.scan.stage["w-1"] != 2 {
		t.Errorf("stale stage answer must be ignored")
	}
	// the remaining stages land: the node is settled and its Info carries the facts
	a.Update(stigStageMsg{gen: a.gen, node: "w-1", stage: "accounts", out: "===STIGCMD\nefi=1\n===END\n", dur: time.Second})
	a.Update(stigStageMsg{gen: a.gen, node: "w-1", stage: "sweep", out: "===STIGSWEEP\nWWNOSTICKY|/tmp/x\n===END\n", dur: time.Second})
	if a.scan.running() {
		t.Fatalf("scan still running after the last node answered")
	}
	ni := a.nodes["w-1"]
	if !ni.STIGProbed || ni.STIGCmd["efi"] != "1" || len(ni.STIGSweep["WWNOSTICKY"]) != 1 || ni.STIGStat["/etc/shadow"].Mode != "600" {
		t.Errorf("facts not adopted by the node: probed=%v cmd=%v sweep=%v", ni.STIGProbed, ni.STIGCmd, ni.STIGSweep)
	}
	if a.scan.took["w-1"] != 2700*time.Millisecond {
		t.Errorf("took = %v", a.scan.took["w-1"])
	}
	// a later regular probe keeps them (MergeSTIG) without re-adopting
	a.Update(nodeMsg{gen: a.gen, info: nodeinfo.Parse("w-1", "10.0.0.2", nodeSample, time.Now())})
	if ni := a.nodes["w-1"]; !ni.STIGProbed || ni.STIGCmd["efi"] != "1" {
		t.Errorf("facts lost on the next regular probe")
	}
	a.sub[tabSecurity] = 0
	if v := ansi.Strip(a.View()); !strings.Contains(v, "STIG / CIS checks") || strings.Contains(v, "Security scan running") {
		t.Errorf("results expected after the scan:\n%s", v)
	}
	if !strings.Contains(a.status, "finished: 2 node(s), 0 failed") {
		t.Errorf("status %q", a.status)
	}
}

// TestScanStageFailure: a failed stage settles the node with the error.
func TestScanStageFailure(t *testing.T) {
	a := scanning(t)
	a.Update(stigStageMsg{gen: a.gen, node: "w-1", stage: "files", err: errors.New("ssh: timeout"), dur: time.Minute})
	if a.scan.running() || a.scan.failed["w-1"] != "files: ssh: timeout" {
		t.Fatalf("failure not recorded: running=%v failed=%v", a.scan.running(), a.scan.failed)
	}
	if !strings.Contains(a.status, "1 failed") {
		t.Errorf("status %q", a.status)
	}
	a.scan.want["w-1"] = true // show the checklist again to read the row
	a.sub[tabSecurity] = 2
	if v := ansi.Strip(a.View()); !strings.Contains(v, "failed at files: ssh: timeout") {
		t.Errorf("failed row missing:\n%s", v)
	}
}

// TestScanAdoptsOnLateProbe: a node with no Info when its last stage lands
// gets the facts with its next regular probe answer.
func TestScanAdoptsOnLateProbe(t *testing.T) {
	a := scanning(t)
	delete(a.nodes, "w-1")
	for _, st := range []string{"files", "accounts", "sweep"} {
		a.Update(stigStageMsg{gen: a.gen, node: "w-1", stage: st, out: "===STIGCMD\nefi=1\n===END\n"})
	}
	if a.scan.running() || !a.scan.complete("w-1") {
		t.Fatalf("node not complete")
	}
	a.Update(nodeMsg{gen: a.gen, info: nodeinfo.Parse("w-1", "10.0.0.2", nodeSample, time.Now())})
	if ni := a.nodes["w-1"]; ni == nil || !ni.STIGProbed || ni.STIGCmd["efi"] != "1" {
		t.Errorf("late probe did not adopt the facts")
	}
}

// TestScanStartsStages: Shift+S with a runner starts stage 0 on every
// target and the scan's own state; without SSH it only evaluates the API rules.
func TestScanStartsStages(t *testing.T) {
	a := testApp()
	a.tab = tabSecurity
	a.runner = &sshrun.Runner{}
	_, cmd := a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	if cmd == nil || a.scan == nil || len(a.scan.nodes) == 0 || a.scan.percent() != 0 {
		t.Fatalf("scan not started: cmd=%v scan=%+v", cmd, a.scan)
	}
	for _, n := range a.scan.nodes {
		if !a.scan.want[n] || a.scan.at[n].IsZero() || a.scan.hosts[n] == "" {
			t.Errorf("node %s: want=%v at=%v host=%q", n, a.scan.want[n], a.scan.at[n], a.scan.hosts[n])
		}
	}
	if s := nodeinfo.STIGStageScript(a.scan.stages[0].Name); !strings.Contains(s, "sec SYSCTLALL") || !strings.Contains(s, "===END") {
		t.Errorf("stage script incomplete")
	}
	a = testApp()
	a.tab, a.sshEnabled = tabSecurity, false
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	if a.scan != nil || !a.secScanned {
		t.Errorf("without SSH the scan must only opt the tab in")
	}
}

// TestScanKeyFromAnySubTab: Shift+S works from Rules and Node hardening too,
// and is refused while a scan runs.
func TestScanKeyFromAnySubTab(t *testing.T) {
	a := testApp()
	a.tab, a.sub[tabSecurity] = tabSecurity, 0
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	if !a.secScanned {
		t.Fatalf("Shift+S on the Rules sub-tab did not start the scan")
	}
	a = scanning(t)
	a.sub[tabSecurity] = 1
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
	if !strings.Contains(a.status, "already running") {
		t.Errorf("second Shift+S during a scan: status %q", a.status)
	}
}
