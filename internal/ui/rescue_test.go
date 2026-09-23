package ui

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/rescue"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/sshrun/sshtest"
)

func runes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

// rescueNode answers the preflight script like an rke2 server would.
func rescueNode(t *testing.T) *sshtest.Server {
	t.Helper()
	return sshtest.New(t, func(cmd, stdin string) (string, string, int) {
		if strings.HasPrefix(stdin, "id -u;") {
			return "0\n", "", 0
		}
		if !strings.Contains(stdin, `say "preflight=ok"`) {
			return "", "unexpected script", 1
		}
		if !strings.Contains(stdin, "SNAP='/var/lib/rancher/rke2/server/db/snapshots/old'") || !strings.Contains(stdin, "KIND='rke2'") {
			return "", "wrong snapshot or kind in script", 1
		}
		return "hostname=cp-1\nsvc_state=active\ndatadir=/var/lib/rancher/rke2/server/db/etcd\nowner=etcd:etcd\nmode=700\nsize_kb=10\nmember=yes\nmountpoint=no\nrescue_dir=/var/lib/rancher/rke2/server/etcd-rescue-1\navail_kb=999999\nbin=/usr/local/bin/rke2\nconfig: cluster-init: true\netcd_user=998\nsnapshot=/var/lib/rancher/rke2/server/db/snapshots/old\nsnapshot_size=5000000\nsnapshot_mtime=1\npreflight=ok\n", "", 0
	})
}

func TestRescueGuards(t *testing.T) {
	a := testApp()
	a.tab = tabEtcd
	a.handleKey(runes("X"))
	if a.overlay != ovNone || !strings.Contains(a.status, "SSH unavailable") {
		t.Errorf("no runner: overlay %v status %q", a.overlay, a.status)
	}
	a.runner = &sshrun.Runner{}
	a.sshEnabled = false
	a.handleKey(runes("X"))
	if a.overlay != ovNone || !strings.Contains(a.status, "enable SSH collection first") {
		t.Errorf("ssh off: %q", a.status)
	}
	a.sshEnabled = true
	a.cfg.Actions.Enabled = false
	a.handleKey(runes("X"))
	if a.overlay != ovNone || !strings.Contains(a.status, "disabled") {
		t.Errorf("read-only: %q", a.status)
	}
	a.cfg.Actions.Enabled = true
	a.snap.Distribution = "kubespray"
	a.etcd["cp-1"].Dist = "kubespray"
	a.handleKey(runes("X"))
	if a.overlay != ovNone || !strings.Contains(a.status, "supports rke2, k3s and kubeadm") {
		t.Errorf("unsupported: %q", a.status)
	}
	// X on another tab is not the rescue
	a.snap.Distribution = "rke2"
	a.tab = tabNodes
	a.handleKey(runes("X"))
	if a.overlay != ovNone || a.rescue != nil {
		t.Errorf("X outside the etcd tab opened the rescue")
	}
}

func TestRescueFlow(t *testing.T) {
	srv := rescueNode(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	r, err := sshrun.New(config.SSH{User: "root", Key: srv.KeyPath, Timeout: 5 * time.Second, Concurrency: 2, Become: "auto", Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a := testApp()
	a.runner = r
	a.cfg.SSH.Hosts = map[string]string{"cp-1": srv.Addr}
	a.tab = tabEtcd
	a.handleKey(runes("X"))
	if a.overlay != ovRescue || a.rescue == nil || a.rescue.phase != rescuePickMode || a.rescue.modeCur != 0 {
		t.Fatalf("X should open the mode picker with restore preselected: overlay %v status %q", a.overlay, a.status)
	}
	if v := ansi.Strip(a.View()); !strings.Contains(v, "Restore a snapshot onto the whole control plane") || !strings.Contains(v, "Rejoin one server") || !strings.Contains(v, "1 healthy") {
		t.Errorf("mode view:\n%s", v)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescuePickNode || a.rescue.rejoin {
		t.Fatalf("enter should open the node picker for a restore: phase %v", a.rescue.phase)
	}
	if len(a.rescue.nodes) != 1 || a.rescue.nodes[0].node.Name != "cp-1" || !a.rescue.nodes[0].online || a.rescue.nodes[0].node.IP != "10.0.0.1" || a.rescue.kind != rescue.RKE2 {
		t.Fatalf("candidates: %+v", a.rescue.nodes)
	}
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "choose the node to restore from") || !strings.Contains(v, "cp-1") || !strings.Contains(v, "healthy") {
		t.Errorf("picker view:\n%s", v)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescuePickSnap || len(a.rescue.snaps) != 1 || a.rescue.snaps[0].path != "/var/lib/rancher/rke2/server/db/snapshots/old" {
		t.Fatalf("snapshot picker: phase %v snaps %+v", a.rescue.phase, a.rescue.snaps)
	}
	if v := ansi.Strip(a.View()); !strings.Contains(v, "choose the restore point on cp-1") || !strings.Contains(v, "old") {
		t.Errorf("snapshot view:\n%s", v)
	}
	// the S3 record is not offered: the node's S3 settings live in a secret
	for _, s := range a.rescue.snaps {
		if s.s3 {
			t.Errorf("S3 snapshot offered although the config uses a secret")
		}
	}
	_, cmd := a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescuePreflight || cmd == nil {
		t.Fatalf("enter should start the preflight: phase %v", a.rescue.phase)
	}
	_ = a.View()
	msg := cmd()
	pm, ok := msg.(rescuePreflightMsg)
	if !ok {
		t.Fatalf("preflight msg %T", msg)
	}
	a.Update(pm)
	if a.rescue.phase != rescueConfirm || a.rescue.prefErr != "" {
		t.Fatalf("confirm phase expected: %v %q", a.rescue.phase, a.rescue.prefErr)
	}
	p := a.rescue.plan
	if p.Target.Facts.Owner != "etcd:etcd" || len(p.Steps()) == 0 || len(p.Others) != 0 {
		t.Fatalf("plan: %+v steps %d", p.Target.Facts, len(p.Steps()))
	}
	v = ansi.Strip(a.View())
	for _, w := range []string{"WARNING", "restore from", "cp-1", "Steps (", "Stop rke2-server", "cluster-reset", "Take a fresh snapshot", "single-server cluster", "type restore to begin"} {
		if !strings.Contains(v, w) {
			t.Errorf("confirm view lacks %q:\n%s", w, v)
		}
	}
	// enter without the word does nothing; the wrong word does nothing
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescueConfirm || !strings.Contains(a.status, "type restore exactly") {
		t.Errorf("empty confirmation accepted: %v %q", a.rescue.phase, a.status)
	}
	for _, ch := range "nope" {
		a.handleOverlayKey(runes(string(ch)))
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescueConfirm {
		t.Errorf("wrong word accepted")
	}
	// esc cancels without touching anything
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovNone || a.rescue != nil || !strings.Contains(a.status, "nothing was changed") {
		t.Errorf("cancel: overlay %v rescue %v status %q", a.overlay, a.rescue, a.status)
	}
}

func TestRescueProgressView(t *testing.T) {
	a := testApp()
	a.runner = &sshrun.Runner{}
	a.tab = tabEtcd
	a.handleKey(runes("X"))
	r := a.rescue
	r.plan = rescue.New(rescue.RKE2, r.nodes[0].node, nil, "/snap/old", false)
	r.rejoin = false
	r.phase = rescueRunning
	r.started = time.Now()
	r.seq = 1
	r.ch = make(chan rescue.Event, 1)
	steps := []rescue.Step{{Title: "Stop rke2-server", Node: "cp-1", State: rescue.Done, Started: time.Now(), Finished: time.Now(), Log: []string{"cp-1: stopped=ok"}}, {Title: "Restore old", Node: "cp-1", State: rescue.Running, Started: time.Now(), Live: []string{"waiting: 0/1 members"}}, {Title: "Verify", Node: "cp-1"}}
	if cmd := a.handleRescueMsg(rescueMsg{seq: 1, ev: rescue.Event{Steps: steps, Current: 1}, ok: true}); cmd == nil {
		t.Error("should keep waiting for events")
	}
	if !strings.Contains(a.rescueHeader(), "etcd rescue 2/3: Restore old on cp-1") {
		t.Errorf("header %q", a.rescueHeader())
	}
	v := ansi.Strip(a.View())
	for _, w := range []string{"running for", "Stop rke2-server", "waiting: 0/1 members", "x aborts", "etcd rescue 2/3"} {
		if !strings.Contains(v, w) {
			t.Errorf("progress view lacks %q:\n%s", w, v)
		}
	}
	// esc hides, X brings it back, q refuses to quit
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovNone || a.rescue == nil {
		t.Fatal("esc should hide but keep the rescue")
	}
	if _, cmd := a.handleKey(runes("q")); quits(cmd) || !strings.Contains(a.status, "rescue is running") {
		t.Errorf("q quit during a rescue: %q", a.status)
	}
	a.handleKey(runes("X"))
	if a.overlay != ovRescue || a.rescue.phase != rescueRunning {
		t.Errorf("X should reopen the running view")
	}
	a.handleOverlayKey(runes("x"))
	if !r.plan.Aborting() {
		t.Error("x should request an abort")
	}
	// a stale sequence is ignored, the final event switches to the done view
	a.handleRescueMsg(rescueMsg{seq: 0, ev: rescue.Event{Done: true}, ok: true})
	if r.phase != rescueRunning {
		t.Error("stale event changed the phase")
	}
	steps[1].State, steps[1].Err = rescue.Failed, "boom"
	steps[2].State = rescue.Skipped
	a.handleRescueMsg(rescueMsg{seq: 1, ev: rescue.Event{Steps: steps, Current: -1, Done: true, Err: errors.New("step 2/3 failed on cp-1: Restore old: boom")}, ok: true})
	if r.phase != rescueDone || !strings.Contains(a.status, "rescue FAILED") {
		t.Errorf("done: %v %q", r.phase, a.status)
	}
	v = ansi.Strip(a.View())
	for _, w := range []string{"FAILED after", "boom", "Afterward", "esc closes"} {
		if !strings.Contains(v, w) {
			t.Errorf("done view lacks %q:\n%s", w, v)
		}
	}
	_, cmd := a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
	if a.overlay != ovNone || a.rescue != nil || cmd == nil || !a.heavyNext {
		t.Errorf("closing the done view should refresh")
	}
}

// The apiserver is down (no node list, no distribution): the node the
// cluster was bootstrapped from is the SSH target, and its probe alone is
// enough to offer it as the restore source.
func TestRescueOffline(t *testing.T) {
	a := testApp()
	a.runner = &sshrun.Runner{}
	a.snap.Nodes, a.snap.Distribution, a.knownNodes = nil, "", nil
	a.cfg.SSH.Hosts = nil
	a.cfg.SSH.AddFallbackHost("10.0.0.143:22")
	delete(a.etcd, "cp-1")
	a.etcd["10.0.0.143"] = etcd.Parse("10.0.0.143", etcdSample)
	a.tab = tabEtcd
	_ = a.View()
	a.handleKey(runes("X"))
	if a.overlay != ovRescue || a.rescue == nil {
		t.Fatalf("offline X: overlay %v status %q", a.overlay, a.status)
	}
	if n := a.rescue.nodes; len(n) != 1 || n[0].node.Name != "10.0.0.143" || n[0].node.Host != "10.0.0.143:22" || n[0].node.IP != "10.0.0.143" || !n[0].online || a.rescue.kind != rescue.RKE2 {
		t.Errorf("offline candidates: %+v kind %s", n, a.rescue.kind)
	}
}

// Two servers, one healthy leader and one whose etcd is down: X recommends
// the rejoin, preselects the broken node, runs the preflight against the
// anchor and the node, and the confirmation describes a rejoin.
func TestRescueRejoinFlow(t *testing.T) {
	status := "svc_state=active\nhealth={\"health\":\"true\"}\nreadyz=200\n---MEMBERS\n{\"members\":[{\"ID\":1,\"name\":\"cp-1\",\"peerURLs\":[\"https://10.0.0.1:2380\"],\"clientURLs\":[\"https://10.0.0.1:2379\"]},{\"ID\":2,\"name\":\"cp-2\",\"peerURLs\":[\"https://10.0.0.2:2380\"],\"clientURLs\":[\"https://10.0.0.2:2379\"]}]}\n\n---HEALTH\n[{\"endpoint\":\"https://10.0.0.1:2379\",\"health\":true,\"took\":\"1ms\"},{\"endpoint\":\"https://10.0.0.2:2379\",\"health\":false,\"error\":\"down\"}]\n\n---STATUS\n[{\"Endpoint\":\"https://10.0.0.1:2379\",\"Status\":{\"header\":{\"member_id\":1},\"leader\":1,\"raftIndex\":10,\"raftTerm\":2,\"version\":\"3.5.15\",\"dbSize\":1}}]\n\n---ALARMS\n{}\n"
	handler := func(name string) sshtest.Handler {
		return func(cmd, stdin string) (string, string, int) {
			switch {
			case strings.HasPrefix(stdin, "id -u;"):
				return "0\n", "", 0
			case strings.Contains(stdin, `say "preflight=ok"`):
				if strings.Contains(stdin, `"target" = target`) {
					return "", "rejoin preflight must not ask for a snapshot", 1
				}
				return "hostname=" + name + "\nsvc_state=active\ndatadir=/var/lib/rancher/rke2/server/db/etcd\nowner=etcd:etcd\nmode=700\nsize_kb=10\nmember=yes\nmountpoint=no\nrescue_dir=/var/lib/rancher/rke2/server/etcd-rescue-1\navail_kb=999999\nbin=/usr/local/bin/rke2\nconfig: server: https://10.0.0.1:9345\netcd_user=998\npreflight=ok\n", "", 0
			case strings.Contains(stdin, "---MEMBERS"):
				return status, "", 0
			}
			return "", "unexpected script", 1
		}
	}
	anchor := sshtest.New(t, handler("cp-1"))
	broken := sshtest.New(t, handler("cp-2"))
	broken.AcceptKey(anchor.ClientPub)
	t.Setenv("SSH_AUTH_SOCK", "")
	r, err := sshrun.New(config.SSH{User: "root", Key: anchor.KeyPath, Timeout: 5 * time.Second, Concurrency: 2, Become: "auto", Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	a := testApp()
	a.runner = r
	a.cfg.SSH.Hosts = map[string]string{"cp-1": anchor.Addr, "cp-2": broken.Addr}
	a.snap.Nodes = append(a.snap.Nodes, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "cp-2", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.2"}}}})
	a.etcd["cp-1"] = etcd.Parse("cp-1", strings.Replace(etcdSample, "etcd_server_has_leader 1", "etcd_server_has_leader 1\netcd_server_is_leader 1", 1))
	a.etcd["cp-2"] = etcd.Parse("cp-2", "===DIST\nrke2\n===PATHS\ndatadir=/var/lib/rancher/rke2/server/db/etcd\n===HEALTH\n{\"health\":\"false\"}\n===PEERS\ndb: {\"id\":2,\"peerURLs\":[\"https://10.0.0.2:2380\"],\"name\":\"cp-2-abcdef01\"\nself: cp-2-abcdef01\n===END\n")
	a.tab = tabEtcd
	a.handleKey(runes("X"))
	if a.rescue == nil || a.rescue.phase != rescuePickMode || a.rescue.modeCur != 1 {
		t.Fatalf("rejoin should be recommended: %+v", a.rescue)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !a.rescue.rejoin || a.rescue.phase != rescuePickNode || a.rescue.nodes[a.rescue.nodeCur].node.Name != "cp-2" {
		t.Fatalf("rejoin picker should preselect cp-2: rejoin=%v phase=%v cur=%s", a.rescue.rejoin, a.rescue.phase, a.rescue.nodes[a.rescue.nodeCur].node.Name)
	}
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "choose the server to rejoin") || !strings.Contains(v, "cp-2-abcdef01") || !strings.Contains(v, "UNHEALTHY") {
		t.Errorf("rejoin picker view:\n%s", v)
	}
	_, cmd := a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescuePreflight || cmd == nil || a.rescue.anchor.node.Name != "cp-1" {
		t.Fatalf("preflight should start with cp-1 as the anchor: phase %v anchor %s", a.rescue.phase, a.rescue.anchor.node.Name)
	}
	a.Update(cmd())
	if a.rescue.phase != rescueConfirm || a.rescue.prefErr != "" {
		t.Fatalf("confirm expected: %v %q", a.rescue.phase, a.rescue.prefErr)
	}
	p := a.rescue.plan
	if !p.Rejoin || p.Target.Name != "cp-1" || len(p.Others) != 1 || p.Others[0].Name != "cp-2" {
		t.Fatalf("plan: %+v", p)
	}
	v = ansi.Strip(a.View())
	for _, w := range []string{"confirm rejoin", "cp-1 sees 2 members", "cp-2   Stop rke2-server", "Rejoin: start rke2-server", "Verify the cluster"} {
		if !strings.Contains(v, w) {
			t.Errorf("confirm view lacks %q:\n%s", w, v)
		}
	}
	if strings.Contains(v, "Restore ") || strings.Contains(v, "cluster-reset") {
		t.Errorf("rejoin confirm mentions a restore:\n%s", v)
	}
}

// Discovered peers become SSH targets when the apiserver cannot list nodes.
func TestPeersBecomeTargets(t *testing.T) {
	a := testApp()
	a.snap.Nodes, a.knownNodes, a.cfg.SSH.Hosts = nil, nil, nil
	a.cfg.SSH.AddFallbackHost("10.0.0.143")
	delete(a.etcd, "cp-1")
	a.etcd["10.0.0.143"] = etcd.Parse("10.0.0.143", "===DIST\nrke2\n===PATHS\ndatadir=/var/lib/rancher/rke2/server/db/etcd\n===PEERS\ndb: {\"id\":1,\"peerURLs\":[\"https://10.0.0.143:2380\"],\"name\":\"redhat9-test-c01d5123\"\ndb: {\"id\":2,\"peerURLs\":[\"https://10.0.0.235:2380\"],\"name\":\"redhat9-test-2-39b1f557\"\ndb: {\"id\":3,\"peerURLs\":[\"https://10.0.0.223:2380\"],\"name\":\"redhat9-test-3-60c619d8\"\n===END\n")
	nodes, offline := a.sshTargets(a.snap)
	if !offline || len(nodes) != 3 {
		t.Fatalf("targets: offline=%v %d nodes", offline, len(nodes))
	}
	var names []string
	for i := range nodes {
		names = append(names, nodes[i].Name+"="+a.nodeAddress(&nodes[i]))
	}
	if got := strings.Join(names, " "); got != "10.0.0.143=10.0.0.143 redhat9-test-2=10.0.0.235 redhat9-test-3=10.0.0.223" {
		t.Errorf("targets %s", got)
	}
	if !k8s.IsEtcdNode(nodes, &nodes[1]) {
		t.Error("a discovered peer should count as an etcd node")
	}
}

// The confirm screen scrolls with the arrows / page keys while letters go
// to the input; the running view follows the current step until scrolled.
func TestRescueScrolling(t *testing.T) {
	a := testApp()
	a.height = 18 // a small terminal: the plan does not fit
	a.runner = &sshrun.Runner{}
	a.tab = tabEtcd
	a.handleKey(runes("X"))
	r := a.rescue
	r.plan = rescue.New(rescue.RKE2, r.nodes[0].node, nil, "/snap/old", false)
	r.phase = rescueConfirm
	r.input.Focus()
	// fake a long plan: warnings only, since steps need a preflight
	for i := 0; i < 30; i++ {
		r.plan.Warnings = append(r.plan.Warnings, fmt.Sprintf("warning number %d", i))
	}
	first := ansi.Strip(a.View())
	if !strings.Contains(first, "restore from") || strings.Contains(first, "warning number 29") || !strings.Contains(first, "type restore to begin") {
		t.Fatalf("initial confirm view should show the top and the pinned input:\n%s", first)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyDown})
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyDown})
	if r.scroll != 2 {
		t.Errorf("down should scroll one line: %d", r.scroll)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnd})
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "warning number 29") || !strings.Contains(v, "type restore to begin") || !strings.Contains(v, "of ") {
		t.Errorf("end should show the last lines with the input still pinned:\n%s", v)
	}
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyPgUp})
	if r.scroll >= 100 {
		t.Errorf("pgup should move up: %d", r.scroll)
	}
	// letters still type the word
	for _, ch := range "restore" {
		a.handleOverlayKey(runes(string(ch)))
	}
	if r.input.Value() != "restore" {
		t.Errorf("input %q", r.input.Value())
	}
	// running view: follows the current step, stops after a manual scroll, f resumes
	r.phase = rescueRunning
	r.started = time.Now()
	var steps []rescue.Step
	for i := 0; i < 40; i++ {
		st := rescue.Done
		if i == 35 {
			st = rescue.Running
		}
		steps = append(steps, rescue.Step{Title: fmt.Sprintf("step %d", i), Node: "cp-1", State: st, Started: time.Now()})
	}
	r.steps, r.current = steps, 35
	v = ansi.Strip(a.View())
	if !strings.Contains(v, "36. cp-1   step 35") || !strings.Contains(v, "following the running step") {
		t.Errorf("running view should follow step 36:\n%s", v)
	}
	a.handleOverlayKey(runes("g"))
	v = ansi.Strip(a.View())
	if !strings.Contains(v, " 1. cp-1   step 0") || !r.manual || strings.Contains(v, "following") {
		t.Errorf("g should go to the top and stop following:\n%s", v)
	}
	a.handleOverlayKey(runes("f"))
	if v = ansi.Strip(a.View()); r.manual || !strings.Contains(v, "36. cp-1   step 35") {
		t.Errorf("f should follow again:\n%s", v)
	}
	// the running step is near the top but its output is long: following
	// keeps the newest output in view, not the title
	var few []rescue.Step
	for i := 0; i < 3; i++ {
		few = append(few, rescue.Step{Title: fmt.Sprintf("step %d", i), Node: "cp-1", State: rescue.Done, Started: time.Now(), Finished: time.Now()})
	}
	var live []string
	for i := 0; i < 12; i++ {
		live = append(live, fmt.Sprintf("live line %d", i))
	}
	few = append(few, rescue.Step{Title: "long one", Node: "cp-1", State: rescue.Running, Started: time.Now(), Log: []string{"log a", "log b", "log c", "log d", "log e", "log f", "log g", "log h"}, Live: live}, rescue.Step{Title: "later", Node: "cp-1"})
	r.steps, r.current = few, 3
	v = ansi.Strip(a.View())
	if !strings.Contains(v, "live line 11") || !strings.Contains(v, "5. cp-1   later") {
		t.Errorf("following should show the end of the running step's output:\n%s", v)
	}
}

// A cluster whose backups are not where khealth looks - the normal case for
// a hand-rolled kubeadm cron - used to dead-end at the snapshot picker with
// nothing to select and no way forward. The path can be typed instead.
func TestRescueTypedSnapshotPath(t *testing.T) {
	a := testApp()
	a.rescue = &rescueView{
		phase: rescuePickSnap,
		kind:  rescue.Kubeadm,
		nodes: []rescueNodeOpt{{node: rescue.Node{Name: "cp-1", Host: "10.0.0.1", IP: "10.0.0.1"}, online: true, state: "healthy"}},
	}
	a.overlay = ovRescue

	// p opens the prompt, and the picker says so
	if v := ansi.Strip(a.View()); !strings.Contains(v, "types a path khealth did not find") {
		t.Errorf("the snapshot picker does not offer the typed path:\n%s", v)
	}
	a.handleOverlayKey(runes("p"))
	if a.rescue.phase != rescuePickSnapPath {
		t.Fatalf("p should open the path prompt, phase %v", a.rescue.phase)
	}
	if v := ansi.Strip(a.View()); !strings.Contains(v, "Absolute path of the snapshot file on cp-1") {
		t.Errorf("path prompt view:\n%s", v)
	}

	// a relative path is refused: the file is read on the node
	a.rescue.input.SetValue("backup.db")
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescuePickSnapPath || !strings.Contains(a.status, "absolute path") {
		t.Errorf("a relative path should be refused: phase %v status %q", a.rescue.phase, a.status)
	}

	// an absolute one becomes the selected restore point
	a.rescue.input.SetValue("/srv/backups/etcd/snap-2026-09-22.db")
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if len(a.rescue.snaps) != 1 {
		t.Fatalf("the typed path should be the restore point: %+v", a.rescue.snaps)
	}
	s := a.rescue.snaps[0]
	if s.path != "/srv/backups/etcd/snap-2026-09-22.db" || !s.typed || s.name != "snap-2026-09-22.db" || s.dir != "/srv/backups/etcd" {
		t.Errorf("typed snapshot: %+v", s)
	}
	// nothing was stat'ed, so it must not claim a size or a date
	a.rescue.phase = rescuePickSnap
	if v := ansi.Strip(a.View()); !strings.Contains(v, "checked by the preflight") || !strings.Contains(v, "typed") {
		t.Errorf("a typed path should not show an age or size:\n%s", v)
	}
}

// With nothing found at all the prompt opens straight away rather than
// leaving the operator at an empty list.
func TestRescueNoSnapshotsAsksForPath(t *testing.T) {
	a := testApp()
	a.rescue = &rescueView{
		phase: rescuePickNode,
		kind:  rescue.Kubeadm,
		nodes: []rescueNodeOpt{{node: rescue.Node{Name: "cp-1", Host: "10.0.0.1", IP: "10.0.0.1"}, online: true, state: "healthy"}},
	}
	a.overlay = ovRescue
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.rescue.phase != rescuePickSnapPath {
		t.Fatalf("an empty snapshot list should ask for a path, phase %v status %q", a.rescue.phase, a.status)
	}
	if !strings.Contains(a.status, "type the path") {
		t.Errorf("status should say why: %q", a.status)
	}
}
