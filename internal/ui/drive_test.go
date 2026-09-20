package ui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/sshrun/sshtest"
)

// newDriveApp builds the app the way main does (New: real client from a
// kubeconfig, SSH runner, perf log, text inputs) and gives it the fixture
// snapshot of testApp, so the key and message handlers run against the
// complete state rather than a hand-built struct.
func newDriveApp(t testing.TB) *App {
	t.Helper()
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	const kubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster: {server: "https://127.0.0.1:1", insecure-skip-tls-verify: true}
contexts:
- name: test
  context: {cluster: test, user: u}
users:
- name: u
  user: {token: x}
current-context: test
`
	if err := os.WriteFile(kc, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := sshtest.New(t, func(cmd, stdin string) (string, string, int) { return "", "not in this test", 1 })
	cfg := config.Default()
	cfg.Kubeconfig = kc
	cfg.Perf.Log = filepath.Join(dir, "perf.jsonl")
	cfg.SSH = config.SSH{Enabled: true, User: "root", Key: srv.KeyPath, Port: srv.Port(), Timeout: time.Second, Concurrency: 2, Become: "none"}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.fp.logger.Close() })
	f := testApp()
	a.snap, a.nodes, a.etcd, a.s3, a.helmLatest = f.snap, f.nodes, f.etcd, f.s3, f.helmLatest
	a.width, a.height = 140, 40
	a.recompute()
	if a.runner == nil {
		t.Fatalf("no SSH runner: %s", a.sshErr)
	}
	return a
}

// key sends one key through Update (the real entry point, not handleKey)
// and renders the frame afterward, so every state a key can leave the app
// in is also drawn once.
func key(t *testing.T, a *App, k string) {
	t.Helper()
	var m tea.KeyMsg
	switch k {
	case "tab":
		m = tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		m = tea.KeyMsg{Type: tea.KeyShiftTab}
	case "enter":
		m = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		m = tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		m = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		m = tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		m = tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		m = tea.KeyMsg{Type: tea.KeyRight}
	case "pgup":
		m = tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		m = tea.KeyMsg{Type: tea.KeyPgDown}
	case "home":
		m = tea.KeyMsg{Type: tea.KeyHome}
	case "end":
		m = tea.KeyMsg{Type: tea.KeyEnd}
	case "backspace":
		m = tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+d":
		m = tea.KeyMsg{Type: tea.KeyCtrlD}
	case "ctrl+u":
		m = tea.KeyMsg{Type: tea.KeyCtrlU}
	case " ":
		m = tea.KeyMsg{Type: tea.KeySpace}
	default:
		m = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("key %q on tab %v sub %q overlay %v panicked: %v", k, a.tab, a.subName(), a.overlay, r)
		}
	}()
	a.Update(m)
	if v := a.View(); v == "" {
		t.Fatalf("empty frame after key %q on tab %v", k, a.tab)
	}
}

func keys(t *testing.T, a *App, ks ...string) {
	t.Helper()
	for _, k := range ks {
		key(t, a, k)
	}
}

// TestDriveEveryTab walks every tab and sub-tab with the navigation, filter,
// detail, help and toggle keys, the way an operator would, and checks the
// app never panics, always renders, and comes back to the table view.
func TestDriveEveryTab(t *testing.T) {
	a := newDriveApp(t)
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 36})
	if a.width != 120 || a.height != 36 {
		t.Fatalf("window size not applied")
	}
	nav := []string{"j", "j", "down", "k", "up", "G", "end", "g", "home", "pgdown", " ", "ctrl+d", "pgup", "ctrl+u"}
	for i := range tabKeys {
		key(t, a, tabKeys[i])
		if a.tab != tab(i) {
			t.Fatalf("key %q selected tab %v, want %v", tabKeys[i], a.tab, i)
		}
		subs := len(subTabs[a.tab])
		if subs == 0 {
			subs = 1
		}
		for s := 0; s < subs; s++ {
			keys(t, a, nav...)
			// detail of the selected row, scrolled, closed
			keys(t, a, "enter", "j", "k", "pgdown", "pgup", "G", "g", "esc")
			if a.overlay != ovNone && a.overlay != ovInspect && a.overlay != ovPodLogs && a.overlay != ovRescue {
				t.Fatalf("tab %v sub %q: overlay %v still open after esc", a.tab, a.subName(), a.overlay)
			}
			// out of any inspector / modal the row opened
			for n := 0; n < 4 && (a.overlay != ovNone || a.inInspect()); n++ {
				key(t, a, "esc")
			}
			// filter typed, applied, cleared
			keys(t, a, "/", "c", "p", "enter", "esc", "/", "x", "esc")
			if a.filters[a.tab] != "" || a.filterOn {
				t.Fatalf("tab %v: filter left on: %q %v", a.tab, a.filters[a.tab], a.filterOn)
			}
			// toggles
			keys(t, a, "a", "a", "m", "m")
			key(t, a, "l")
		}
		// back to the first sub-tab
		for s := 0; s < subs; s++ {
			key(t, a, "h")
		}
		keys(t, a, "right", "left")
	}
	// tab cycling wraps both ways
	key(t, a, "1")
	key(t, a, "shift+tab")
	if a.tab != tab(tabCount-1) {
		t.Errorf("shift+tab from the first tab should wrap to the last, got %v", a.tab)
	}
	keys(t, a, "tab", "]", "[")
	if a.tab != tabOverview {
		t.Errorf("] then [ should return to Overview, got %v", a.tab)
	}
	// help and footprint overlays scroll and close
	for _, k := range []string{"?", "P"} {
		key(t, a, k)
		if a.overlay != ovDetail {
			t.Fatalf("%q should open the detail overlay", k)
		}
		keys(t, a, "j", "k", "pgdown", "pgup", "G", "g", "tab")
		if !strings.Contains(a.status, "modal") {
			t.Errorf("tab inside a modal view should explain itself, status %q", a.status)
		}
		key(t, a, "esc")
		if a.overlay != ovNone {
			t.Fatalf("esc should close the %q overlay", k)
		}
	}
	// namespace picker: filter, move, choose, and cancel
	keys(t, a, "n")
	if a.overlay != ovNamespace {
		t.Fatalf("n should open the namespace picker")
	}
	keys(t, a, "t", "e", "down", "up", "ctrl+n", "ctrl+p", "enter")
	if a.overlay != ovNone {
		t.Fatalf("enter should close the namespace picker (overlay %v)", a.overlay)
	}
	keys(t, a, "n", "esc")
	if a.overlay != ovNone {
		t.Fatalf("esc should close the namespace picker")
	}
	// context picker
	keys(t, a, "C")
	if a.overlay != ovContext {
		t.Fatalf("C should open the context picker")
	}
	keys(t, a, "j", "k", "esc")
	if a.overlay != ovNone {
		t.Fatalf("esc should close the context picker")
	}
	// refresh keys with no client behind them only set a status
	keys(t, a, "r", "R", "s", "S")
	if a.status == "" {
		t.Errorf("r/R/s/S should leave a status line")
	}
}

// TestDriveWorkloadsAndHelm covers the tab-specific keys: pods/controllers
// toggle, rollout restart and log tailing on Workloads, upgrade / rollback
// on Helm, events detail, logs drill-down and the etcd rescue entry.
func TestDriveWorkloadsAndHelm(t *testing.T) {
	a := newDriveApp(t)
	key(t, a, "3")
	if a.tab != tabWorkloads {
		t.Fatalf("tab 3 should be Workloads, got %v", a.tab)
	}
	keys(t, a, "p")
	if !a.wlPods || a.subName() != "Pods" {
		t.Errorf("p should switch to the pod list, sub %q", a.subName())
	}
	keys(t, a, "j", "enter")
	for n := 0; n < 3 && (a.overlay != ovNone || a.inInspect()); n++ {
		key(t, a, "esc")
	}
	// leaving the inspector lands on Controllers; p toggles from there
	if a.wlPods {
		keys(t, a, "p")
	}
	if a.wlPods || a.subName() != "Controllers" {
		t.Errorf("expected the controller list, got sub %q", a.subName())
	}
	keys(t, a, "t")
	// a rollout restart asks for confirmation (or explains why not)
	if a.overlay == ovConfirm {
		key(t, a, "esc")
	}
	keys(t, a, "L")
	if a.overlay == ovPodLogs {
		keys(t, a, "tab", "]", "[", "j", "k", "G", "g", "f", "w", "esc")
	}
	if a.overlay != ovNone {
		t.Fatalf("workloads: overlay %v left open", a.overlay)
	}
	// helm actions
	key(t, a, "8")
	if a.tab != tabHelm {
		t.Fatalf("tab 8 should be Helm, got %v", a.tab)
	}
	keys(t, a, "u")
	if a.overlay == ovConfirm {
		key(t, a, "esc")
	}
	keys(t, a, "b")
	if a.overlay == ovRevisions {
		keys(t, a, "j", "k", "esc")
	} else if a.overlay == ovConfirm {
		key(t, a, "esc")
	}
	if a.overlay != ovNone {
		t.Fatalf("helm: overlay %v left open", a.overlay)
	}
	a.actionRunning = true
	keys(t, a, "u")
	if !strings.Contains(a.status, "still running") {
		t.Errorf("u while an action runs should say so, status %q", a.status)
	}
	a.actionRunning = false
	// events: enter opens the event, esc closes it
	key(t, a, "6")
	keys(t, a, "enter")
	for n := 0; n < 3 && (a.overlay != ovNone || a.inInspect()); n++ {
		key(t, a, "esc")
	}
	// logs: enter drills into a node, esc / q come back
	key(t, a, "-")
	keys(t, a, "enter")
	if a.logsNode == "" {
		t.Errorf("enter on the Logs node list should drill down")
	}
	keys(t, a, "a", "j", "k", "q")
	if a.logsNode != "" {
		t.Errorf("q should leave the node's lines")
	}
	keys(t, a, "l")
	keys(t, a, "esc")
	if a.logsNode != "" {
		t.Errorf("esc should leave the node's lines")
	}
	// etcd rescue needs SSH: without a runner it explains and stays put
	key(t, a, "4")
	keys(t, a, "X")
	if a.overlay == ovRescue {
		keys(t, a, "j", "k", "esc")
	}
	if a.overlay != ovNone {
		t.Fatalf("etcd: overlay %v left open", a.overlay)
	}
	// q while a rescue runs is refused
	a.rescue = &rescueView{phase: rescueRunning}
	_, cmd := a.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if quits(cmd) || !strings.Contains(a.status, "rescue is running") {
		t.Errorf("q during a rescue should refuse, status %q", a.status)
	}
	a.rescue = nil
}

// TestUpdateMessages feeds every asynchronous result message through
// Update: a new snapshot (nodes gone, CRD counts reset), node and etcd
// probe results (merged, pending cleared), S3, Helm, exec and CRD messages,
// stale sequence / generation numbers (ignored) and the apiserver failover outcome.
func TestUpdateMessages(t *testing.T) {
	a := newDriveApp(t)
	a.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	a.pending["cp-1"] = true
	a.etcdPend["cp-1"] = true

	// stale messages are ignored
	stale := a.seq + 1
	a.Update(nodeMsg{gen: a.gen + 1, info: &nodeinfo.Info{Node: "cp-1", Err: errors.New("stale")}})
	if a.nodes["cp-1"].Err != nil || !a.pending["cp-1"] {
		t.Errorf("a stale nodeMsg must be ignored")
	}
	a.Update(etcdMsg{gen: a.gen + 1, probe: &etcd.Probe{Node: "cp-1"}})
	a.Update(s3CheckMsg{gen: a.gen + 1})
	a.Update(crdCountMsg{seq: stale, crds: []k8s.CRDInfo{{Name: "x"}}})
	a.Update(etcdExecMsg{gen: a.gen + 1, probe: &etcd.Probe{Node: "cp-1"}})
	a.Update(tickMsg{seq: stale})
	if a.crdCounts != nil || a.etcdExec != nil {
		t.Errorf("stale CRD / exec messages must be ignored")
	}

	// live probe results
	info := nodeinfo.Parse("cp-1", "10.0.0.1", nodeSample, time.Now())
	a.Update(nodeMsg{gen: a.gen, info: info, opts: nodeinfo.Options{}})
	if a.pending["cp-1"] {
		t.Errorf("nodeMsg should clear pending")
	}
	probe := etcd.Parse("cp-1", etcdSample)
	a.Update(etcdMsg{gen: a.gen, probe: probe})
	if a.etcdPend["cp-1"] {
		t.Errorf("etcdMsg should clear pending")
	}
	probe2 := etcd.Parse("cp-1", etcdSample)
	probe2.RKE2Config = map[string]string{"etcd-s3-config-secret": "other-secret"}
	a.Update(etcdMsg{gen: a.gen, probe: probe2})
	a.Update(s3Msg{info: &k8s.S3SecretInfo{Name: "other-secret", Found: true, Endpoint: "s3.example.com", Bucket: "b"}})
	if a.s3 == nil || a.s3.Name != "other-secret" {
		t.Errorf("s3Msg should replace the S3 info")
	}
	a.Update(s3CheckMsg{gen: a.gen, check: etcd.S3Check{Node: "cp-1", OK: true}})
	if _, ok := a.s3Reach["cp-1"]; !ok {
		t.Errorf("s3CheckMsg should record the check")
	}
	a.Update(helmMsg{latest: map[string]helmcheck.Latest{"default/web": {Version: "100.0.0", Source: "repo"}}})
	if a.helmLatest["default/web"].Version != "100.0.0" {
		t.Errorf("helmMsg should replace the latest versions")
	}
	a.Update(etcdExecMsg{gen: a.gen, probe: probe})
	if a.etcdExec == nil {
		t.Errorf("etcdExecMsg should be kept")
	}
	a.Update(crdCountMsg{seq: a.seq, crds: []k8s.CRDInfo{{Name: "x"}}})
	if len(a.crdCounts) != 1 {
		t.Errorf("crdCountMsg should be kept")
	}
	a.Update(recomputeMsg{})
	a.Update(spinnerTick())

	// a new snapshot without w-1 drops what was known about it
	snap := *a.snap
	snap.Nodes = snap.Nodes[:1]
	snap.Taken = time.Now()
	a.Update(snapshotMsg{seq: a.seq, snap: &snap})
	if _, ok := a.nodes["w-1"]; ok {
		t.Errorf("a node missing from the snapshot should be dropped")
	}
	if a.refreshing {
		t.Errorf("snapshotMsg ends the refresh")
	}
	if a.View() == "" {
		t.Fatalf("empty frame after the snapshot")
	}
	// an empty node list (API outage) keeps everything
	before := len(a.nodes)
	out := *a.snap
	out.Nodes = nil
	out.Errors = []string{"Get https://10.0.0.1:6443: dial tcp: connection refused"}
	a.Update(snapshotMsg{seq: a.seq, snap: &out})
	if len(a.nodes) != before {
		t.Errorf("an empty node list must not erase known nodes")
	}
	if a.View() == "" {
		t.Fatalf("empty frame during the outage")
	}

	// failover: nothing answered, then another apiserver did
	a.Update(apiFailoverMsg{seq: a.seq, tried: []string{"10.0.0.2"}, err: "dial tcp 10.0.0.2:6443: i/o timeout"})
	if !a.apiTried["10.0.0.2"] || !strings.Contains(a.status, "no other control-plane apiserver") {
		t.Errorf("failed failover should be remembered and reported, status %q", a.status)
	}
	a.Update(apiFailoverMsg{seq: a.seq, client: &k8s.Client{Context: "test", Host: "https://10.0.0.3:6443"}, server: "https://10.0.0.3:6443", tried: []string{"10.0.0.3"}})
	if a.apiOverride != "https://10.0.0.3:6443" || a.client.Host != "https://10.0.0.3:6443" {
		t.Errorf("successful failover should switch the client")
	}
	if a.View() == "" {
		t.Fatalf("empty frame after the failover")
	}
	// the tick for the current sequence schedules a refresh
	_, cmd := a.Update(tickMsg{seq: a.seq})
	if cmd == nil && !a.refreshing {
		t.Errorf("a current tick should schedule the refresh")
	}
}

func spinnerTick() tea.Msg {
	return tea.WindowSizeMsg{Width: 140, Height: 40}
}

// TestNodesAgeAndIP: the Nodes table shows each node's address and age.
func TestNodesAgeAndIP(t *testing.T) {
	a := testApp()
	a.snap.Nodes[0].CreationTimestamp = metav1.NewTime(time.Now().Add(-49 * time.Hour))
	a.snap.Nodes[0].Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}}
	a.tab = tabNodes
	c := a.currentContent()
	found := false
	for _, r := range rowsText(c) {
		if strings.Contains(r, "cp-1") && strings.Contains(r, "10.0.0.1") && strings.Contains(r, "2d1h") {
			found = true
		}
	}
	if !found {
		t.Errorf("nodes row should carry IP and age:\n%s", strings.Join(rowsText(c), "\n"))
	}
}

// TestDriveStorageDetail: enter on a PVC row opens the volume detail with
// the claim, its (Longhorn) backend view and the findings for it; enter
// on a PV and a node filesystem row work too.
func TestDriveStorageDetail(t *testing.T) {
	a := newDriveApp(t)
	s := a.snap
	s.PVCs = append(s.PVCs, corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pvc-web", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}})
	s.PVs = append(s.PVs, corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pvc-web"}, Spec: corev1.PersistentVolumeSpec{StorageClassName: "longhorn", ClaimRef: &corev1.ObjectReference{Namespace: "default", Name: "web"},
		PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: "pvc-web", VolumeAttributes: map[string]string{"numberOfReplicas": "3", "csi.storage.k8s.io/secret": "hidden"}}}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}})
	s.Longhorn = &k8s.LonghornInfo{Volumes: []k8s.LonghornVolume{{Name: "pvc-web", PVC: "default/web", State: "attached", Robustness: "degraded", Node: "cp-1", Replicas: 3, Scheduled: true, Size: 1 << 30,
		ReplicaList: []k8s.LonghornReplica{{Name: "pvc-web-r-1", Node: "cp-1", State: "running", Mode: "RW", Rebuild: -1}, {Name: "pvc-web-r-2", Node: "w-1", State: "stopped", FailedAt: "2026-09-20T19:13:11Z", Mode: "ERR", Rebuild: -1}}, ReplicaMode: map[string]string{"pvc-web-r-1": "RW", "pvc-web-r-2": "ERR"}}},
		Backups: []k8s.LonghornBackup{{Name: "backup-1", Volume: "pvc-web", State: "Error", Error: "rpc error: desc = target unreachable"}}, Settings: map[string]string{}}
	a.recompute()
	key(t, a, "5")
	if a.tab != tabStorage {
		t.Fatalf("tab 5 should be Storage, got %v", a.tab)
	}
	c := a.storageContent()
	if !c.selectable {
		t.Fatal("storage content must be selectable")
	}
	var pvcRow, pvRow, nodeRow int = -1, -1, -1
	for i, r := range c.rows {
		switch {
		case r.id == "pvc:default/web":
			pvcRow = i
		case r.id == "pv:pvc-web":
			pvRow = i
		case strings.HasPrefix(r.id, "node:") && nodeRow < 0:
			nodeRow = i
		}
	}
	if pvcRow < 0 || pvRow < 0 {
		t.Fatalf("rows: pvc=%d pv=%d", pvcRow, pvRow)
	}
	a.cursor[tabStorage] = pvcRow
	key(t, a, "enter")
	if a.overlay != ovDetail {
		t.Fatalf("enter on a PVC row should open the detail overlay, got %v", a.overlay)
	}
	v := ansi.Strip(a.View())
	for _, want := range []string{"PersistentVolumeClaim default/web", "Longhorn", "degraded", "pvc-web-r-2", "w-1", "backup-1", "numberOfReplicas=3"} {
		if !strings.Contains(v, want) {
			t.Errorf("detail lacks %q", want)
		}
	}
	if strings.Contains(v, "hidden") {
		t.Error("secret-looking volume attribute rendered")
	}
	key(t, a, "esc")
	a.cursor[tabStorage] = pvRow
	key(t, a, "enter")
	if v := ansi.Strip(a.View()); a.overlay != ovDetail || !strings.Contains(v, "PersistentVolume pvc-web") || !strings.Contains(v, "Claim") {
		t.Error("enter on a PV row should open the same detail through the claimRef")
	}
	key(t, a, "esc")
	if nodeRow >= 0 {
		a.cursor[tabStorage] = nodeRow
		key(t, a, "enter")
		if a.overlay != ovDetail {
			t.Error("enter on a node filesystem row should open the node detail")
		}
		key(t, a, "esc")
	}
	// the Pending fixture claim explains why
	for i, r := range c.rows {
		if r.id == "pvc:default/data" {
			a.cursor[tabStorage] = i
		}
	}
	key(t, a, "enter")
	if v := ansi.Strip(a.View()); !strings.Contains(v, "no StorageClass on the claim") && !strings.Contains(v, "waiting for provisioner") {
		t.Errorf("pending claim detail should say why:\n%s", v)
	}
	key(t, a, "esc")
}
