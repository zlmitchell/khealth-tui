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
	hs := Analyze(NewBundleSource(b, r), tl)

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

// A noisy neighbour: the kubelet evicts victim (low priority, a little
// over its request) first and hog last; the evictions stop after hog, so
// hog is the one to blame even without usage in its eviction message.
func TestEvictionBlamesTheLastOfTheEpisode(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	t0 := now.Add(-10 * time.Minute)
	node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Gi")}}}
	mk := func(ns, name, rs string, prio int32, req string) corev1.Pod {
		yes := true
		p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{"pod-template-hash": "abc12345"},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs, Controller: &yes}}},
			Spec:   corev1.PodSpec{NodeName: "n1", Priority: &prio, Containers: []corev1.Container{{Name: "c", Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse(req)}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted", StartTime: &metav1.Time{Time: t0.Add(-time.Hour)}}}
		return p
	}
	victim := mk("shop", "api-abc12345-aaaaa", "api-abc12345", 0, "16Mi")
	hog := mk("batch", "report-abc12345-bbbbb", "report-abc12345", 1000, "64Mi")
	ev := func(p corev1.Pod, at time.Time, msg string) corev1.Event {
		return corev1.Event{Reason: "Evicted", Type: corev1.EventTypeWarning, LastTimestamp: metav1.NewTime(at), Source: corev1.EventSource{Host: "n1"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}, Message: msg}
	}
	snap := &k8s.Snapshot{Nodes: []corev1.Node{node}, Pods: []corev1.Pod{victim, hog}, Events: []corev1.Event{
		ev(victim, t0, "The node was low on resource: memory. Threshold quantity: 1Gi, available: 900Mi. Container c was using 40Mi, request is 16Mi, has larger consumption of memory."),
		ev(hog, t0.Add(3*time.Second), "The node was low on resource: memory. Threshold quantity: 1Gi, available: 800Mi. "),
	}}
	dir := writeBundle(t, map[string]string{}, snap, now)
	b, err := gather.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r, _ := b.Replay(config.Default())
	tl := Build(b, r)
	ins := Extract(tl, r.Snap)
	var target *Incident
	for i := range ins {
		if ins[i].Kind == KindEviction && ins[i].Namespace == "shop" {
			target = &ins[i]
		}
	}
	if target == nil {
		t.Fatalf("no eviction of shop/api in %+v", ins)
	}
	c := target.Context(NewBundleSource(b, r), tl, ins, DefaultWindow)
	if len(c.Suspects) == 0 || !strings.HasPrefix(c.Suspects[0].Who, "batch/report-") {
		t.Fatalf("suspects %+v, want batch/report first", c.Suspects)
	}
	if !strings.Contains(c.Verdict, "batch/report") {
		t.Errorf("verdict %q", c.Verdict)
	}
	// the hog's pod object gone (a drain or the terminated-pod GC deleted
	// it): the eviction events alone still name it
	r.Snap.Pods = []corev1.Pod{victim}
	c = target.Context(NewBundleSource(b, r), tl, ins, DefaultWindow)
	if len(c.Suspects) == 0 || !strings.HasPrefix(c.Suspects[0].Who, "batch/report-") {
		t.Fatalf("with the hog's pod deleted: suspects %+v", c.Suspects)
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

// kubectl drain: the node is cordoned (unschedulable taint with its time),
// pods on it are stopped through the Eviction API (Killing events, no
// Evicted), and their replacements cannot be scheduled. The drain is one
// incident listing the stopped pods, and it is what the pending pods blame.
// An OOMKilled container is its own limit, not a neighbour.
func TestDrainAndOwnLimit(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	cordon := now.Add(-10 * time.Minute)
	node := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Spec: corev1.NodeSpec{Unschedulable: true,
		Taints: []corev1.Taint{{Key: "node.kubernetes.io/unschedulable", Effect: corev1.TaintEffectNoSchedule, TimeAdded: &metav1.Time{Time: cordon}}}}}
	ev := func(reason, kind, ns, name, host, msg string, at time.Time) corev1.Event {
		return corev1.Event{Reason: reason, Type: corev1.EventTypeNormal, LastTimestamp: metav1.NewTime(at), Source: corev1.EventSource{Host: host},
			InvolvedObject: corev1.ObjectReference{Kind: kind, Namespace: ns, Name: name}, Message: msg}
	}
	pending := ev("FailedScheduling", "Pod", "shop", "web-abc12345-new01", "", "0/1 nodes are available: 1 node(s) were unschedulable. preemption: 0/1 nodes are available", cordon.Add(5*time.Second))
	pending.Type = corev1.EventTypeWarning
	limit := resource.MustParse("24Mi")
	oom := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "hungry-1"},
		Spec: corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: limit}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 2,
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: metav1.NewTime(now.Add(-time.Hour))}}}}}}
	snap := &k8s.Snapshot{Nodes: []corev1.Node{node}, Pods: []corev1.Pod{oom}, Events: []corev1.Event{
		ev("NodeNotSchedulable", "Node", "", "n1", "n1", "Node n1 status is now: NodeNotSchedulable", cordon),
		ev("Killing", "Pod", "shop", "web-abc12345-old01", "n1", "Stopping container web", cordon.Add(2*time.Second)),
		ev("Killing", "Pod", "kube-system", "coredns-1", "n1", "Stopping container coredns", cordon.Add(3*time.Second)),
		pending,
	}}
	dir := writeBundle(t, map[string]string{}, snap, now)
	b, err := gather.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	r, _ := b.Replay(config.Default())
	tl := Build(b, r)
	ins := Extract(tl, r.Snap)
	src := NewBundleSource(b, r)
	var drain, sched, oomIn *Incident
	for i := range ins {
		switch ins[i].Kind {
		case KindDrain:
			drain = &ins[i]
		case KindSchedule:
			sched = &ins[i]
		case KindOOM:
			oomIn = &ins[i]
		}
	}
	if drain == nil || drain.Node != "n1" || len(drain.Pods) != 2 || !strings.Contains(drain.Summary, "2 pods stopped") {
		t.Fatalf("drain incident %+v", drain)
	}
	if c := drain.Context(src, tl, ins, DefaultWindow); len(c.Suspects) != 0 || !strings.Contains(c.Verdict, "audit log") {
		t.Errorf("a drain is an action, not a symptom: suspects %+v verdict %q", c.Suspects, c.Verdict)
	}
	if sched == nil {
		t.Fatal("no scheduling incident")
	}
	if c := sched.Context(src, tl, ins, DefaultWindow); len(c.Suspects) == 0 || c.Suspects[0].Who != "node drain n1" || c.Suspects[0].Score < 0.85 {
		t.Errorf("pending pods should blame the drain: %+v", c.Suspects)
	}
	if oomIn == nil {
		t.Fatal("no OOM incident")
	}
	if c := oomIn.Context(src, tl, ins, DefaultWindow); !strings.Contains(c.Verdict, "its own memory limit of 24Mi") {
		t.Errorf("OOM verdict %q", c.Verdict)
	}
}
