package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/gather"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/rca"
)

func openOffline(t *testing.T, path string) *App {
	t.Helper()
	b, err := gather.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	cfg := config.Default()
	r, err := b.Replay(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tl := rca.Build(b, r)
	a := NewOffline(cfg, &Offline{Bundle: b, Replayed: r, Timeline: tl, Source: rca.NewBundleSource(b, r)})
	a.Update(tea.WindowSizeMsg{Width: 160, Height: 45})
	return a
}

func press(a *App, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		a.Update(msg)
	}
}

// A small bundle: one OOMKilled pod on one node. The offline App opens on
// the Incidents tab, lists it, opens it, walks every pane and every tab
// without a cluster.
func TestOfflineIncidents(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	yes := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "hungry-abc12345-x1y2z", Labels: map[string]string{"pod-template-hash": "abc12345"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "hungry-abc12345", Controller: &yes}}},
		Spec: corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("24Mi")}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, StartTime: &metav1.Time{Time: now.Add(-time.Hour)}, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 4,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: metav1.NewTime(now.Add(-5 * time.Minute))}}}}},
	}
	node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Gi"), corev1.ResourceCPU: resource.MustParse("4")},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	snap := &k8s.Snapshot{Taken: now, Distribution: "rke2", Nodes: []corev1.Node{node}, Pods: []corev1.Pod{pod}}
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		p := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", gather.Manifest{Format: gather.FormatVersion, Created: now, Context: "lab", Server: "https://10.0.0.1:6443", Scope: "cluster"})
	write("snapshot.json", snap)
	_ = os.MkdirAll(filepath.Join(dir, "cluster", "pods", "shop", pod.Name), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "cluster", "pods", "shop", pod.Name, "app.previous.log"), []byte(now.Add(-5*time.Minute).Format(time.RFC3339Nano)+" loading cache\n"), 0o600)

	a := openOffline(t, dir)
	v := ansi.Strip(a.View())
	if a.tab != tabIncidents || !strings.Contains(v, "OOMKilled") || !strings.Contains(v, "shop/deploy/hungry/app") {
		t.Fatalf("offline App does not open on the incident list:\n%s", v)
	}
	// the table header is styled once: styling it again styled every
	// character of its escape codes and printed them as text
	if raw := a.View(); !strings.Contains(v, "WHEN") || strings.Contains(v, "[1;4;") || strings.Contains(raw, "4mW\x1b[0m") {
		t.Errorf("the incident table header is mangled:\n%q", raw)
	}
	press(a, "enter")
	if a.inc.open == "" || a.inc.ctx[a.inc.open] == nil {
		t.Fatalf("enter did not open the incident with its context")
	}
	for range incidentPanes[1:] {
		v = ansi.Strip(a.View())
		if n := strings.Count(v, "\n") + 1; n != 45 {
			t.Errorf("pane %s renders %d lines, want 45", a.subName(), n)
		}
		press(a, "l")
	}
	a.sub[tabIncidents] = 6 // Logs
	if v = ansi.Strip(a.View()); !strings.Contains(v, "loading cache") {
		t.Errorf("Logs pane lacks the previous log:\n%s", v)
	}
	press(a, "esc")
	if a.inc.open != "" {
		t.Error("esc did not return to the list")
	}
	// every other tab renders from the bundle, and refresh is refused
	for tb := tab(0); tb < tabCount; tb++ {
		a.tab = tb
		if v := ansi.Strip(a.View()); !strings.Contains(v, tabNames[tb]) && tb != tabRKE2 {
			t.Errorf("tab %s did not render offline", tabNames[tb])
		}
	}
	a.tab = tabOverview
	press(a, "r")
	if !strings.Contains(a.status, "not available on a bundle") {
		t.Errorf("refresh on a bundle: status %q", a.status)
	}
}

// KHT_BUNDLE=<bundle> KHT_DUMP=<file> go test -run TestDumpOfflineBundle
// writes every pane of every incident as text, for reviewing the views.
func TestDumpOfflineBundle(t *testing.T) {
	path, out := os.Getenv("KHT_BUNDLE"), os.Getenv("KHT_DUMP")
	if path == "" || out == "" {
		t.Skip("KHT_BUNDLE and KHT_DUMP not set")
	}
	a := openOffline(t, path)
	var sb strings.Builder
	sb.WriteString("=== list\n" + ansi.Strip(a.View()) + "\n")
	for _, id := range strings.Split(os.Getenv("KHT_INCIDENTS"), ",") {
		if id == "" {
			continue
		}
		a.closeIncident()
		a.openIncident(id)
		for i := 1; i < len(incidentPanes); i++ {
			a.sub[tabIncidents] = i
			a.cursor[tabIncidents], a.scroll[tabIncidents] = 0, 0
			sb.WriteString("=== " + id + " / " + incidentPanes[i] + "\n" + ansi.Strip(a.View()) + "\n")
		}
	}
	if err := os.WriteFile(out, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
