package checks

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/k8s"
)

func upgradeFindings(f []Finding) []Finding {
	var out []Finding
	for _, x := range f {
		if x.Area == "upgrade" {
			out = append(out, x)
		}
	}
	return out
}

func hasFinding(f []Finding, sev Severity, substr string) bool {
	for _, x := range f {
		if x.Severity == sev && strings.Contains(x.Message, substr) {
			return true
		}
	}
	return false
}

func versionedNode(name, version string, labels map[string]string) corev1.Node {
	n := node(name, true, "10.0.0.9")
	n.Status.NodeInfo.KubeletVersion = version
	n.Labels = labels
	return n
}

func TestKubeVersionHelpers(t *testing.T) {
	if maj, min, patch, ok := kubeVersion("v1.35.8+rke2r1"); !ok || maj != 1 || min != 35 || patch != 8 {
		t.Errorf("rke2 version: %d %d %d %v", maj, min, patch, ok)
	}
	if _, _, _, ok := kubeVersion("latest"); ok {
		t.Error("garbage parsed")
	}
	if !sameVersion("v1.35.8+rke2r1", "v1.35.8+rke2r1") || !sameVersion("v1.35.8", "v1.35.8+rke2r1") || sameVersion("v1.35.8+rke2r1", "v1.35.8+rke2r2") || sameVersion("v1.35.8", "v1.35.9") {
		t.Error("sameVersion")
	}
}

// Kubelets newer than the API server (agents upgraded before the servers)
// are unsupported; more than three minors behind is outside the skew.
func TestUpgradeSkew(t *testing.T) {
	in := baseInput()
	in.Snap.Version = "v1.35.8+rke2r1"
	in.Snap.Nodes = []corev1.Node{versionedNode("cp-1", "v1.35.8+rke2r1", nil), versionedNode("w-new", "v1.36.1+rke2r1", nil), versionedNode("w-old", "v1.31.2+rke2r1", nil), versionedNode("w-ok", "v1.33.0+rke2r1", nil)}
	f := upgradeFindings(Evaluate(in))
	if !hasFinding(f, SevCrit, "kubelet v1.36.1+rke2r1 is newer than the API server") {
		t.Errorf("newer kubelet not flagged: %+v", f)
	}
	if !hasFinding(f, SevWarn, "kubelet v1.31.2+rke2r1 is 4 minors behind") {
		t.Errorf("old kubelet not flagged: %+v", f)
	}
	for _, x := range f {
		if x.Object == "w-ok" || x.Object == "cp-1" {
			t.Errorf("unexpected: %+v", x)
		}
	}
}

func TestUpgradePlans(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	in := baseInput()
	in.Now = now
	in.Snap.Version = "v1.35.8+rke2r1"
	cp := map[string]string{"node-role.kubernetes.io/control-plane": "true"}
	doneCP := map[string]string{"node-role.kubernetes.io/control-plane": "true", "plan.upgrade.cattle.io/rke2-server": "h1"}
	in.Snap.Nodes = []corev1.Node{
		versionedNode("cp-1", "v1.35.9+rke2r1", doneCP),
		versionedNode("cp-2", "v1.35.8+rke2r1", cp),
		versionedNode("cp-3", "v1.35.8+rke2r1", cp),
		versionedNode("cp-rpm", "v1.35.8+rke2r1", doneCP),
	}
	sel := &metav1.LabelSelector{MatchLabels: cp}
	ok := true
	notOK := false
	in.Snap.Rancher = &k8s.RancherInfo{Managed: true, ClusterAgentOK: true, SystemUpgradeOK: &ok}
	in.Snap.Upgrade = &k8s.UpgradeInfo{PlansCRD: true, Plans: []k8s.UpgradePlan{
		{Namespace: "cattle-system", Name: "rke2-server", Version: "v1.35.9+rke2r1", Latest: "v1.35.9+rke2r1", Hash: "h1", Image: "rancher/rke2-upgrade", Selector: sel, Created: now.Add(-2 * time.Hour),
			Applying: []string{"cp-2"},
			Jobs: []k8s.UpgradeJob{
				{Name: "apply-rke2-server-on-cp-2-with-h1", Node: "cp-2", Active: 1, Started: now.Add(-45 * time.Minute)},
				{Name: "apply-rke2-server-on-cp-3-with-h1", Node: "cp-3", Failed: 3, FailedReason: "BackoffLimitExceeded", PodState: "ImagePullBackOff", PodMessage: "Back-off pulling image \"rancher/rke2-upgrade:v1.35.9-rke2r1\"", Started: now.Add(-90 * time.Minute)},
			}},
		{Namespace: "cattle-system", Name: "rke2-agent", Channel: "https://update.rke2.io/v1-release/channels/stable", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"node-role.kubernetes.io/worker": "true"}},
			Conditions: []k8s.CondSummary{{Type: "LatestResolved", Status: "False", Reason: "Error", Message: "Get \"https://update.rke2.io\": dial tcp: lookup update.rke2.io: no such host"}}},
		{Namespace: "system-upgrade", Name: "skip", Version: "v1.37.0+rke2r1", Selector: sel, Created: now.Add(-time.Hour)},
		{Namespace: "system-upgrade", Name: "stale", Version: "v1.35.9+rke2r1", Hash: "h9", Selector: sel, Created: now.Add(-time.Hour)},
	}}
	f := upgradeFindings(Evaluate(in))
	want := []struct {
		sev    Severity
		substr string
	}{
		{SevCrit, "upgrade of cp-3 to v1.35.9+rke2r1 failed (job apply-rke2-server-on-cp-3-with-h1, BackoffLimitExceeded): ImagePullBackOff"},
		{SevWarn, "upgrade of cp-2 to v1.35.9+rke2r1 has been running for 45m"},
		{SevWarn, "cp-rpm is marked upgraded to v1.35.9+rke2r1 but runs v1.35.8+rke2r1"},
		{SevWarn, "plan cannot resolve its version from channel https://update.rke2.io/v1-release/channels/stable: Get"},
		{SevCrit, "plan targets v1.37.0+rke2r1 but 4 nodes more than one minor behind: cp-1 (v1.35.9+rke2r1), cp-2 (v1.35.8+rke2r1), cp-3 (v1.35.8+rke2r1)"},
		{SevWarn, "plan targets v1.35.9+rke2r1 but no upgrade job exists for cp-2, cp-3"},
	}
	for _, w := range want {
		if !hasFinding(f, w.sev, w.substr) {
			t.Errorf("missing %s %q in:\n%s", w.sev, w.substr, dumpFindings(f))
		}
	}
	for _, x := range f {
		if x.Object == "cattle-system/rke2-server" && strings.Contains(x.Message, "cp-1") {
			t.Errorf("done node flagged: %+v", x)
		}
		if x.Object == "system-upgrade/stale" && strings.Contains(x.Message, "no upgrade job exists for cp-1") {
			t.Errorf("node already on the target listed as waiting: %+v", x)
		}
	}
	// the image hint names the registry problem
	for _, x := range f {
		if strings.Contains(x.Message, "ImagePullBackOff") && !strings.Contains(x.Hint, "rancher/rke2-upgrade is not pullable from cp-3") {
			t.Errorf("pull hint: %q", x.Hint)
		}
	}
	// ... unless the registry says the tag does not exist
	in.Snap.Upgrade.Plans[0].Jobs[1].PodMessage = `Back-off pulling image "rancher/rke2-upgrade:v1.35.99-rke2r1": ErrImagePull: rpc error: code = NotFound desc = failed to pull and unpack image`
	for _, x := range upgradeFindings(Evaluate(in)) {
		if strings.Contains(x.Message, "ImagePullBackOff") && !strings.Contains(x.Hint, "there is no rancher/rke2-upgrade image for v1.35.9+rke2r1") {
			t.Errorf("not-found hint: %q", x.Hint)
		}
	}
	// controller down while plans owe nodes
	in.Snap.Rancher.SystemUpgradeOK = &notOK
	f = upgradeFindings(Evaluate(in))
	if !hasFinding(f, SevCrit, "system-upgrade-controller is not ready while plans have nodes to upgrade") {
		t.Errorf("controller down not flagged:\n%s", dumpFindings(f))
	}
}

func TestUpgradeQuietPlan(t *testing.T) {
	// a completed plan on nodes that all carry the hash raises nothing
	in := baseInput()
	in.Snap.Version = "v1.35.8+rke2r1"
	done := map[string]string{"plan.upgrade.cattle.io/p": "h"}
	in.Snap.Nodes = []corev1.Node{versionedNode("a", "v1.35.8+rke2r1", done), versionedNode("b", "v1.35.8+rke2r1", done)}
	in.Snap.Upgrade = &k8s.UpgradeInfo{PlansCRD: true, Plans: []k8s.UpgradePlan{{Namespace: "system-upgrade", Name: "p", Version: "v1.35.8+rke2r1", Hash: "h", Complete: true,
		Jobs: []k8s.UpgradeJob{{Name: "j-a", Node: "a", Succeeded: 1, Started: in.Now.Add(-time.Hour)}, {Name: "j-b", Node: "b", Succeeded: 1, Started: in.Now.Add(-time.Hour)}}}}}
	if f := upgradeFindings(Evaluate(in)); len(f) != 0 {
		t.Errorf("quiet plan produced findings:\n%s", dumpFindings(f))
	}
}

func TestUpgradeProvisionedClusters(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	in := baseInput()
	in.Now = now
	in.Snap.Version = "v1.35.8+rke2r1"
	in.Snap.Rancher = &k8s.RancherInfo{Management: true, Provisioning: "this cluster runs Rancher (management/local cluster)"}
	inSync := &k8s.MachinePlan{HasPlan: true, InSync: true, Probes: map[string]bool{"kubelet": true}}
	in.Snap.Upgrade = &k8s.UpgradeInfo{Provisioned: []k8s.ProvCluster{
		{Namespace: "fleet-default", Name: "prod", Version: "v1.35.9+rke2r1", CPVersion: "v1.35.9+rke2r1", Ready: false, CPReady: false,
			Conditions:   []k8s.CondSummary{{Type: "Updated", Status: "Unknown", Reason: "Reconciling", Message: "waiting for control plane to be available"}},
			CPConditions: []k8s.CondSummary{{Type: "Reconciled", Status: "Unknown", Reason: "Reconciling", Message: "draining node prod-cp-2"}},
			Machines: []k8s.ProvMachine{
				{Name: "prod-cp-1-abc", Node: "prod-cp-1", Phase: "Running", Version: "v1.35.9+rke2r1", Roles: []string{"control-plane", "etcd"}, Plan: inSync, Created: now.Add(-48 * time.Hour)},
				{Name: "prod-cp-2-def", Node: "prod-cp-2", Phase: "Running", Version: "v1.35.8+rke2r1", Roles: []string{"control-plane", "etcd"}, Created: now.Add(-48 * time.Hour),
					Plan: &k8s.MachinePlan{HasPlan: true, InSync: false, Failing: true, Failures: 2, Threshold: 5, Probes: map[string]bool{"kubelet": true, "etcd": false}}},
				{Name: "prod-cp-3-ghi", Node: "prod-cp-3", Phase: "Running", Version: "v1.35.8+rke2r1", Roles: []string{"control-plane", "etcd"}, Created: now.Add(-48 * time.Hour),
					Plan: &k8s.MachinePlan{HasPlan: true, Failed: true, Failures: 5, Threshold: 5, Probes: map[string]bool{}}},
				{Name: "prod-w-9-new", Phase: "Provisioning", Roles: []string{"worker"}, Created: now.Add(-5 * time.Minute),
					Conditions: []k8s.CondSummary{{Type: "InfrastructureReady", Status: "False", Reason: "WaitingForInfrastructure", Message: "waiting for the VM to boot"}}},
			}},
		{Namespace: "fleet-default", Name: "quiet", Version: "v1.35.9+rke2r1", CPVersion: "v1.35.9+rke2r1", Ready: true, CPReady: true,
			Machines: []k8s.ProvMachine{{Name: "quiet-1", Node: "quiet-1", Phase: "Running", Version: "v1.35.9+rke2r1", Plan: inSync, Created: now.Add(-48 * time.Hour)}}},
	}}
	f := upgradeFindings(Evaluate(in))
	want := []struct {
		sev    Severity
		substr string
	}{
		{SevWarn, "provisioned cluster is not ready: Updated unknown (Reconciling): waiting for control plane to be available"},
		{SevWarn, "control plane Reconciled: unknown (Reconciling): draining node prod-cp-2"},
		{SevWarn, "Rancher's plan is not applied yet: 2 failed attempt(s) of 5 before Rancher gives up, the agent keeps retrying"},
		{SevWarn, "rancher-system-agent health probes failing: etcd"},
		{SevCrit, "rancher-system-agent gave up on Rancher's plan after 5/5 failures"},
		{SevWarn, "machine is Provisioning: InfrastructureReady false (WaitingForInfrastructure): waiting for the VM to boot"},
		{SevWarn, "Rancher plan pending on 1 machine(s): prod-cp-2"},
		{SevInfo, "2/4 machine(s) not yet on v1.35.9+rke2r1: prod-cp-2 (v1.35.8+rke2r1), prod-cp-3 (v1.35.8+rke2r1)"},
	}
	for _, w := range want {
		if !hasFinding(f, w.sev, w.substr) {
			t.Errorf("missing %s %q in:\n%s", w.sev, w.substr, dumpFindings(f))
		}
	}
	for _, x := range f {
		if strings.HasPrefix(x.Object, "quiet") {
			t.Errorf("healthy cluster flagged: %+v", x)
		}
	}
	// secrets denied: the per-machine plan state is unknown, said once
	in.Snap.Upgrade.SecretsDenied = true
	if f := upgradeFindings(Evaluate(in)); !hasFinding(f, SevInfo, "machine plan secrets are not readable") {
		t.Error("denied secrets not reported")
	}
}

func dumpFindings(f []Finding) string {
	var b strings.Builder
	for _, x := range f {
		b.WriteString("  " + x.Severity.String() + " " + x.Object + ": " + x.Message + "\n")
	}
	return b.String()
}
