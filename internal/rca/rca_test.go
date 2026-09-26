package rca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/gather"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// writeBundle lays out a bundle directory the way gather.Run does.
func writeBundle(t *testing.T, files map[string]string, snap *k8s.Snapshot, created time.Time) string {
	t.Helper()
	dir := t.TempDir()
	m, _ := json.Marshal(gather.Manifest{Format: gather.FormatVersion, Created: created, Context: "lab", Scope: "cluster",
		Nodes: []gather.NodeEntry{{Name: "cp-1", Logs: "ok"}}})
	s, _ := json.Marshal(snap)
	files["manifest.json"] = string(m)
	files["snapshot.json"] = string(s)
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cri(t time.Time, msg string) string {
	return t.UTC().Format(time.RFC3339Nano) + " stderr F " + msg + "\n"
}

func TestAnalyze(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	at := func(minAgo int) time.Time { return now.Add(-time.Duration(minAgo) * time.Minute) }

	var etcdLog, schedLog string
	for _, m := range []int{40, 39, 38, 37} {
		etcdLog += cri(at(m), `{"level":"warn","msg":"slow fdatasync","took":"1.8s"}`)
	}
	etcdLog += cri(at(36), `{"msg":"raft.node: 8e9e05c52164694d changed leader from a to b at term 7"}`)
	schedLog += cri(at(35), `E0926 leaderelection.go:340] "Failed to update lock" err="failed to renew lease kube-system/kube-scheduler: timed out"`)

	limit := resource.MustParse("24Mi")
	oom := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "hungry-1"},
		Spec:       corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: limit}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 3,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: metav1.NewTime(at(5))}}}}},
	}
	yes := true
	crash := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "crashy-7d9f-x", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "crashy-7d9f", Controller: &yes}}},
		Spec:       corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 9,
			State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1, FinishedAt: metav1.NewTime(at(2))}}}}},
	}
	sched := corev1.Event{Reason: "FailedScheduling", Type: corev1.EventTypeWarning, LastTimestamp: metav1.NewTime(at(3)),
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "shop", Name: "huge-1"},
		Message:        "0/3 nodes are available: 3 Insufficient cpu. preemption: 0/3 nodes are available: 3 No preemption victims found for incoming pod."}
	snap := &k8s.Snapshot{Pods: []corev1.Pod{oom, crash}, Events: []corev1.Event{sched}}

	dir := writeBundle(t, map[string]string{
		"nodes/cp-1/pods/kube-system_etcd-cp-1_u1/etcd/1.log":                     etcdLog,
		"nodes/cp-1/pods/kube-system_kube-scheduler-cp-1_u2/kube-scheduler/0.log": schedLog,
		"cluster/pods/shop/crashy-7d9f-x/app.previous.log":                        at(2).Format(time.RFC3339Nano) + " starting\n" + at(2).Format(time.RFC3339Nano) + " FATAL: cannot connect to db:5432\n",
	}, snap, now)

	b, err := gather.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r, err := b.Replay(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	tl := Build(b, r)
	hs := Analyze(b, r, tl)

	find := func(title string) *Hypothesis {
		for i := range hs {
			if strings.Contains(hs[i].Title, title) {
				return &hs[i]
			}
		}
		t.Errorf("no hypothesis %q in %v", title, titles(hs))
		return nil
	}
	if h := find("etcd disk latency on cp-1"); h != nil {
		if h.Confidence() != "high" || len(h.Effects) < 2 || !h.First.Equal(at(40)) {
			t.Errorf("etcd chain: %s effects=%v first=%v", h.Confidence(), h.Effects, h.First)
		}
		if h.Evidence[0].Ref.File != "nodes/cp-1/pods/kube-system_etcd-cp-1_u1/etcd/1.log" || h.Evidence[0].Ref.Line != 1 {
			t.Errorf("evidence ref %v", h.Evidence[0].Ref)
		}
	}
	if h := find("OOMKilled"); h != nil && !strings.Contains(strings.Join(h.Effects, " "), "24Mi") {
		t.Errorf("OOM limit missing: %v", h.Effects)
	}
	if h := find("Container restarting: shop/deploy/crashy/app"); h != nil && !strings.Contains(h.Cause, "FATAL: cannot connect to db:5432") {
		t.Errorf("crash cause %q", h.Cause)
	}
	if h := find("Pods cannot be scheduled"); h != nil && h.Cause != "Insufficient cpu" {
		t.Errorf("scheduling cause %q", h.Cause)
	}
	// the OOMKilled container is memory's, not also a crash loop
	for _, h := range hs {
		if strings.Contains(h.Title, "hungry") {
			t.Errorf("OOMKilled container reported as a crash loop too: %s", h.Title)
		}
	}
	// the timeline is in order and every entry points into the bundle
	for i, e := range tl.Entries {
		if i > 0 && e.Time.Before(tl.Entries[i-1].Time) {
			t.Fatalf("timeline out of order at %d", i)
		}
		if e.Ref.File == "" {
			t.Errorf("entry without a reference: %+v", e)
		}
	}
}

// rke2's kubelet.log is klog: local time, no zone. A node at -0400 wrote
// "10:00" for 14:00 UTC.
func TestKlogInNodeZone(t *testing.T) {
	now := time.Date(2026, 9, 26, 15, 0, 0, 0, time.UTC)
	dir := writeBundle(t, map[string]string{
		"nodes/cp-1/system/node.txt":                   "hostname: cp-1\ntz: -0400\n",
		"nodes/cp-1/files/rke2/agent/logs/kubelet.log": `E0926 10:00:00.000000    1234 kubelet.go:100] "PLEG is not healthy: pleg was last seen active 3m0s ago"` + "\n",
	}, &k8s.Snapshot{}, now)
	b, err := gather.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r, _ := b.Replay(config.Default())
	tl := Build(b, r)
	if len(tl.Entries) != 1 || !tl.Entries[0].Time.Equal(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("klog line not read in the node's zone: %+v", tl.Entries)
	}
}

func titles(hs []Hypothesis) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Title)
	}
	return out
}

func TestClockFix(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	// the node's clock runs 90 s ahead: the probe saw its TIME 90 s after it was sent
	probe := "\n===TIME\n" + unixNano(now.Add(90*time.Second)) + "\n===END\n"
	meta, _ := json.Marshal(gather.ProbeMeta{Node: "cp-1", Host: "10.0.0.1", Started: now, Finished: now})
	logLine := cri(now.Add(-10*time.Minute+90*time.Second), `{"msg":"slow fdatasync"}`)
	dir := writeBundle(t, map[string]string{
		"nodes/cp-1/probe/node.txt":                          probe,
		"nodes/cp-1/probe/node.meta.json":                    string(meta),
		"nodes/cp-1/pods/kube-system_etcd-cp-1_u/etcd/0.log": logLine,
	}, &k8s.Snapshot{}, now)
	b, err := gather.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r, _ := b.Replay(config.Default())
	tl := Build(b, r)
	if tl.ClockFix["cp-1"] != 90*time.Second {
		t.Fatalf("clock fix %v", tl.ClockFix)
	}
	if len(tl.Entries) != 1 || !tl.Entries[0].Time.Equal(now.Add(-10*time.Minute)) {
		t.Errorf("entry time not corrected: %+v", tl.Entries)
	}
}

// unixNano is the probe's TIME section: date +%s.%N
func unixNano(t time.Time) string { return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond()) }
