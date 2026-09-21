package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// The Addons tab shows the upgrade plans and, on a management cluster, the
// provisioned clusters; Enter opens the jobs / machines of the row.
func TestAddonsUpgradeSection(t *testing.T) {
	a := testApp()
	a.width = 240
	now := time.Now()
	cp := map[string]string{"node-role.kubernetes.io/control-plane": "true"}
	for i := range a.snap.Nodes {
		a.snap.Nodes[i].Labels = cp
		a.snap.Nodes[i].Status.NodeInfo.KubeletVersion = "v1.35.8+rke2r1"
	}
	a.snap.Nodes[0].Labels = map[string]string{"node-role.kubernetes.io/control-plane": "true", "plan.upgrade.cattle.io/rke2-server": "h1"}
	a.snap.Upgrade = &k8s.UpgradeInfo{PlansCRD: true,
		Plans: []k8s.UpgradePlan{{Namespace: "system-upgrade", Name: "rke2-server", Version: "v1.35.9+rke2r1", Hash: "h1", Image: "rancher/rke2-upgrade", Concurrency: 1, Cordon: true, Selector: &metav1.LabelSelector{MatchLabels: cp}, Created: now.Add(-time.Hour),
			Jobs: []k8s.UpgradeJob{{Name: "apply-rke2-server-on-cp-2-with-h1", Node: "cp-2", Active: 1, PodState: "ImagePullBackOff", PodMessage: "Back-off pulling image", Started: now.Add(-10 * time.Minute)}}}},
		Provisioned: []k8s.ProvCluster{{Namespace: "fleet-default", Name: "prod", Version: "v1.35.9+rke2r1", CPVersion: "v1.35.8+rke2r1", Ready: false, CPReady: false,
			CPConditions: []k8s.CondSummary{{Type: "Reconciled", Status: "Unknown", Reason: "Reconciling", Message: "draining node prod-cp-2"}},
			Machines: []k8s.ProvMachine{
				{Name: "prod-cp-1-abc", Node: "prod-cp-1", Phase: "Running", Version: "v1.35.9+rke2r1", Roles: []string{"control-plane", "etcd"}, Plan: &k8s.MachinePlan{HasPlan: true, InSync: true}},
				{Name: "prod-cp-2-def", Node: "prod-cp-2", Phase: "Running", Version: "v1.35.8+rke2r1", Roles: []string{"control-plane", "etcd"}, Plan: &k8s.MachinePlan{HasPlan: true, Failing: true, Failures: 1, Probes: map[string]bool{"etcd": false}}},
			}}},
	}
	a.tab = tabAddons
	got := ansi.Strip(strings.Join(rowsText(a.currentContent()), "\n"))
	for _, want := range []string{"Upgrade plans", "system-upgrade/rke2-server", "v1.35.9+rke2r1", "1: w-1", "applying on", "Provisioned clusters", "prod", "v1.35.8+rke2r1 -> v1.35.9", "1 in sync, 1 pending, 1 probes failing", "Reconciled: draining node prod-cp-2"} {
		if !strings.Contains(got, want) {
			t.Errorf("addons tab lacks %q:\n%s", want, got)
		}
	}
	title, lines := a.addonsDetail("plan:system-upgrade/rke2-server")
	detail := ansi.Strip(strings.Join(lines, "\n"))
	for _, want := range []string{"rancher/rke2-upgrade", "node-role.kubernetes.io/control-plane=true", "done: 1 cp-1", "pending: 1 w-1", "apply-rke2-server-on-cp-2-with-h1", "ImagePullBackOff: Back-off pulling image"} {
		if title != "Upgrade plan system-upgrade/rke2-server" || !strings.Contains(detail, want) {
			t.Errorf("plan detail (%q) lacks %q:\n%s", title, want, detail)
		}
	}
	title, lines = a.addonsDetail("provcluster:fleet-default/prod")
	detail = ansi.Strip(strings.Join(lines, "\n"))
	for _, want := range []string{"control plane Reconciled Unknown Reconciling: draining node prod-cp-2", "prod-cp-1-abc", "in sync", "pending (1 failed attempts, retrying)", "probes failing: etcd"} {
		if title != "Provisioned cluster fleet-default/prod" || !strings.Contains(detail, want) {
			t.Errorf("cluster detail (%q) lacks %q:\n%s", title, want, detail)
		}
	}
	// Enter on the plan row through the key handler
	for a.selectedID() != "plan:system-upgrade/rke2-server" {
		before := a.cursor[tabAddons]
		a.move(1)
		if a.cursor[tabAddons] == before {
			t.Fatalf("no plan row; last id %q", a.selectedID())
		}
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != ovDetail || a.detailTitle != "Upgrade plan system-upgrade/rke2-server" {
		t.Errorf("enter on the plan row: overlay=%v title=%q", a.overlay, a.detailTitle)
	}
	_ = corev1.Node{}
}
