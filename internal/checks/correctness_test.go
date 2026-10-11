package checks

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Regression tests for checks that fired on healthy clusters, each with
// the scenario that used to produce the false finding.

func TestRancherPlanFailedThenApplied(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	line := func(at, msg string) string {
		return "2026-10-11T" + at + "+00:00 w-1 rancher-system-agent[900]: time=\"2026-10-11T" + at + "Z\" level=info msg=\"" + msg + "\""
	}
	failed := []string{
		line("09:00:00", "[Applyinator] Applying one-time instructions for plan with checksum abc"),
		line("09:00:40", "[Applyinator] Command sh [-c run.sh] finished with err: exit status 1 and exit code: 1"),
	}
	in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: now, Logs: map[string]*logs.Summary{"w-1": logs.Classify(failed, now)}}
	if findingWith(Evaluate(in), SevCrit, "node", "Rancher plan failed 1 time(s)") == nil {
		t.Error("a failed plan with no later apply must stay CRIT")
	}
	retried := append(failed,
		line("10:00:00", "[Applyinator] Applying one-time instructions for plan with checksum def"),
		line("10:00:30", "[Applyinator] Command sh [-c run.sh] finished with err: <nil> and exit code: 0"))
	in.Logs["w-1"] = logs.Classify(retried, now)
	fs := Evaluate(in)
	if f := findingWith(fs, SevCrit, "node", "Rancher plan failed"); f != nil {
		t.Errorf("failure followed by a successful apply still CRIT: %s", f.Message)
	}
	if findingWith(fs, SevInfo, "node", "then a later plan was applied") == nil {
		t.Error("the earlier failure should remain visible as INFO")
	}
}

func TestPendingClaimWaitForFirstConsumer(t *testing.T) {
	now := time.Now()
	wffc, imm := storagev1.VolumeBindingWaitForFirstConsumer, storagev1.VolumeBindingImmediate
	lp, lh := "local-path", "longhorn"
	old := metav1.NewTime(now.Add(-time.Hour))
	claim := func(name string, sc *string) corev1.PersistentVolumeClaim {
		return corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, CreationTimestamp: old},
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: sc}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	}
	snap := &k8s.Snapshot{
		StorageClasses: []storagev1.StorageClass{
			{ObjectMeta: metav1.ObjectMeta{Name: lp}, VolumeBindingMode: &wffc},
			{ObjectMeta: metav1.ObjectMeta{Name: lh}, VolumeBindingMode: &imm},
		},
		PVCs: []corev1.PersistentVolumeClaim{claim("unused-wffc", &lp), claim("used-wffc", &lp), claim("immediate", &lh)},
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "p", CreationTimestamp: old},
			Spec:   corev1.PodSpec{Volumes: []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "used-wffc"}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodPending}}},
	}
	fs := Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: now})
	pending := map[string]bool{}
	for _, f := range fs {
		if f.Area == "storage" && f.Message == "Pending" {
			pending[f.Object] = true
		}
	}
	if pending["app/pvc/unused-wffc"] {
		t.Error("an unused WaitForFirstConsumer claim is Pending by design")
	}
	if !pending["app/pvc/used-wffc"] || !pending["app/pvc/immediate"] {
		t.Errorf("claims that should bind are not reported: %v", pending)
	}
}

func TestCNIRestartsOnlyRecent(t *testing.T) {
	now := time.Now()
	cni := func(restarts int32, ago time.Duration, reason string, code int32) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "rke2-canal-x", Labels: map[string]string{"k8s-app": "canal"}},
			Spec: corev1.PodSpec{NodeName: "cp-1"},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "calico-node", RestartCount: restarts,
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code, FinishedAt: metav1.NewTime(now.Add(-ago))}}}}}}
	}
	run := func(p corev1.Pod) *Finding {
		fs := Evaluate(Input{Snap: &k8s.Snapshot{Pods: []corev1.Pod{p}}, Cfg: config.Default(), Now: now})
		for i := range fs {
			if fs[i].Area == "network" && strings.Contains(fs[i].Message, "CNI pod") {
				return &fs[i]
			}
		}
		return nil
	}
	if f := run(cni(7, 40*24*time.Hour, "Error", 1)); f != nil {
		t.Errorf("restarts 40 days ago still reported: %s", f.Message)
	}
	if f := run(cni(7, 10*time.Minute, "Error", 1)); f == nil || f.Severity != SevWarn {
		t.Errorf("recent crash loop: %+v", f)
	}
	if f := run(cni(7, 10*time.Minute, "Unknown", 255)); f == nil || f.Severity != SevInfo {
		t.Errorf("a node reboot is not the agent failing: %+v", f)
	}
}

func TestClockSkewAgainstOtherNodes(t *testing.T) {
	ni := func(off time.Duration) *nodeinfo.Info {
		return &nodeinfo.Info{ClockOffset: off, Settings: map[string]string{}}
	}
	run := func(offs ...time.Duration) []Finding {
		in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: time.Now(), Nodes: map[string]*nodeinfo.Info{}}
		for i, o := range offs {
			in.Nodes["n"+string(rune('1'+i))] = ni(o)
		}
		var out []Finding
		for _, f := range Evaluate(in) {
			if strings.Contains(f.Message, "clock") {
				out = append(out, f)
			}
		}
		return out
	}
	// this machine 30s behind the cluster: one INFO, no node blamed
	fs := run(30*time.Second, 30*time.Second+200*time.Millisecond, 29*time.Second)
	if len(fs) != 1 || fs[0].Severity != SevInfo || fs[0].Object != "clock" {
		t.Errorf("skewed workstation: %+v", fs)
	}
	// two nodes: this machine breaks the tie
	fs = run(0, 20*time.Second)
	if len(fs) != 1 || fs[0].Object != "n2" || fs[0].Severity != SevWarn {
		t.Errorf("two nodes, one skewed: %+v", fs)
	}
	// one node 20s ahead of the other two
	fs = run(0, 100*time.Millisecond, 20*time.Second)
	if len(fs) != 1 || fs[0].Object != "n3" || fs[0].Severity != SevWarn {
		t.Errorf("one skewed node: %+v", fs)
	}
}

func TestCertExpiryLevels(t *testing.T) {
	now := time.Now()
	in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: now, Nodes: map[string]*nodeinfo.Info{"cp-1": {Dist: "rke2", Settings: map[string]string{}, Certs: []nodeinfo.Cert{
		{Path: "/var/lib/rancher/rke2/server/tls/client-admin.crt", NotAfter: now.Add(3 * 24 * time.Hour)},
		{Path: "/var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt", NotAfter: now.Add(20 * 24 * time.Hour)},
		{Path: "/var/lib/rancher/rke2/server/tls/server-ca.crt", NotAfter: now.Add(20 * 24 * time.Hour)},
	}}}}
	fs := Evaluate(in)
	if f := findingWith(fs, SevCrit, "node", "client-admin.crt"); f == nil || !strings.Contains(f.Hint, "120 days") {
		t.Errorf("3 days left: %+v", f)
	}
	if f := findingWith(fs, SevWarn, "node", "serving-kube-apiserver.crt"); f == nil || f.Hint == "" {
		t.Errorf("20 days left needs a hint: %+v", f)
	}
	if f := findingWith(fs, SevWarn, "node", "server-ca.crt"); f == nil || !strings.Contains(f.Hint, "rotate-ca") {
		t.Errorf("a CA is not renewed by a restart: %+v", f)
	}
}

func TestSystemDeploymentNoneAvailable(t *testing.T) {
	now := time.Now()
	two := int32(2)
	dep := func(ns string, avail int32) appsv1.Deployment {
		return appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "d", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
			Spec: appsv1.DeploymentSpec{Replicas: &two}, Status: appsv1.DeploymentStatus{AvailableReplicas: avail, UnavailableReplicas: 2 - avail}}
	}
	sev := func(d appsv1.Deployment) Severity {
		for _, f := range Evaluate(Input{Snap: &k8s.Snapshot{Deployments: []appsv1.Deployment{d}}, Cfg: config.Default(), Now: now}) {
			if strings.Contains(f.Object, "/deploy/") {
				return f.Severity
			}
		}
		return -1
	}
	if s := sev(dep("kube-system", 0)); s != SevCrit {
		t.Errorf("kube-system 0/2: %v", s)
	}
	if s := sev(dep("kube-system", 1)); s != SevWarn {
		t.Errorf("kube-system 1/2: %v", s)
	}
	if s := sev(dep("shop", 0)); s != SevWarn {
		t.Errorf("app namespace 0/2: %v", s)
	}
}
