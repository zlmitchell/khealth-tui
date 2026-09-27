package rca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// TestPerfLargeBundle times the analysis of a large synthetic bundle:
// KHT_PERF=1 go test -run TestPerfLargeBundle -v ./internal/rca
// (KHT_PERF_SCALE multiplies the sizes). Not a pass/fail benchmark: it
// prints the cost of each stage and the peak heap, for docs/PERFORMANCE.md.
func TestPerfLargeBundle(t *testing.T) {
	if os.Getenv("KHT_PERF") == "" {
		t.Skip("KHT_PERF not set")
	}
	scale := 1
	fmt.Sscan(os.Getenv("KHT_PERF_SCALE"), &scale)
	nodes, linesPerNode, pods, events, podLogs, ingressLines := 3, 250000*scale, 3000*scale, 20000*scale, 400*scale, 200000*scale
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	// journals: mostly routine kubelet lines, a few percent warnings/errors
	for n := 0; n < nodes; n++ {
		var b strings.Builder
		for i := 0; i < linesPerNode; i++ {
			ts := now.Add(-24 * time.Hour).Add(time.Duration(i) * (24 * time.Hour / time.Duration(linesPerNode))).Format("2006-01-02T15:04:05.000000-0700")
			switch {
			case i%97 == 0:
				fmt.Fprintf(&b, "%s cp-%d rke2[100]: time=\"x\" level=warn msg=\"slow fdatasync took 1.2s\"\n", ts, n)
			case i%131 == 0:
				fmt.Fprintf(&b, "%s cp-%d kubelet[200]: E0926 10:22:00.000 12 kubelet.go:100] \"Failed to update lease\" err=\"context deadline exceeded\"\n", ts, n)
			default:
				fmt.Fprintf(&b, "%s cp-%d kubelet[200]: I0926 10:22:00.000 12 reconciler.go:100] \"operationExecutor.VerifyControllerAttachedVolume started for volume\" pod=\"ns-%d/pod-%d\"\n", ts, n, i%50, i%pods)
			}
		}
		write(fmt.Sprintf("nodes/cp-%d/journal/kubelet.log", n), b.String())
	}
	// snapshot: pods (a slice of them OOMKilled / crash looping), events
	yes := true
	snap := &k8s.Snapshot{Taken: now}
	for n := 0; n < nodes; n++ {
		snap.Nodes = append(snap.Nodes, corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("cp-%d", n)}, Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Gi"), corev1.ResourceCPU: resource.MustParse("16")},
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}})
	}
	for i := 0; i < pods; i++ {
		p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: fmt.Sprintf("ns-%d", i%50), Name: fmt.Sprintf("app-%d-abc12345-x%04d", i%200, i), Labels: map[string]string{"pod-template-hash": "abc12345", "app": fmt.Sprintf("app-%d", i%200)},
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: fmt.Sprintf("app-%d-abc12345", i%200), Controller: &yes}}},
			Spec:   corev1.PodSpec{NodeName: fmt.Sprintf("cp-%d", i%nodes), Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: fmt.Sprintf("10.42.%d.%d", i/250, i%250), StartTime: &metav1.Time{Time: now.Add(-48 * time.Hour)}}}
		if i%40 == 0 {
			reason := "Error"
			if i%80 == 0 {
				reason = "OOMKilled"
			}
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", RestartCount: 5, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: 1, FinishedAt: metav1.NewTime(now.Add(-time.Duration(i) * time.Minute))}}}}
		}
		snap.Pods = append(snap.Pods, p)
	}
	reasons := []string{"BackOff", "Unhealthy", "FailedScheduling", "Pulled", "Created", "Started", "Evicted", "Killing"}
	for i := 0; i < events; i++ {
		p := snap.Pods[i%len(snap.Pods)]
		r := reasons[i%len(reasons)]
		msg := "event " + r
		if r == "Evicted" {
			msg = "The node was low on resource: memory. Threshold quantity: 1Gi, available: 900Mi. Container app was using 900Mi, request is 128Mi, has larger consumption of memory."
		}
		snap.Events = append(snap.Events, corev1.Event{Reason: r, Type: corev1.EventTypeWarning, LastTimestamp: metav1.NewTime(now.Add(-time.Duration(i%1440) * time.Minute)),
			Source: corev1.EventSource{Host: p.Spec.NodeName}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}, Message: msg})
	}
	tree, err := scrubSnapshotForTest(snap)
	if err != nil {
		t.Fatal(err)
	}
	write("snapshot.json", tree)
	write("manifest.json", fmt.Sprintf(`{"format":%d,"created":%q,"context":"perf","scope":"cluster"}`, gather.FormatVersion, now.Format(time.RFC3339)))
	for i := 0; i < podLogs; i++ {
		p := snap.Pods[i*len(snap.Pods)/podLogs]
		var b strings.Builder
		for j := 0; j < 2000; j++ {
			fmt.Fprintf(&b, "%s request handled id=%d\n", now.Add(-time.Duration(2000-j)*time.Second).Format(time.RFC3339Nano), j)
		}
		write("cluster/pods/"+p.Namespace+"/"+p.Name+"/app.log", b.String())
	}
	// an ingress-nginx controller and its access log
	ctrl := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ingress-nginx", Name: "ingress-nginx-controller-abc12345-zzzzz", Labels: map[string]string{"app.kubernetes.io/name": "ingress-nginx"}},
		Spec: corev1.PodSpec{NodeName: "cp-0", Containers: []corev1.Container{{Name: "controller"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	snap.Pods = append(snap.Pods, ctrl)
	tree, _ = scrubSnapshotForTest(snap)
	write("snapshot.json", tree)
	var ib strings.Builder
	for j := 0; j < ingressLines; j++ {
		st := 200
		if j%50 == 0 {
			st = 502
		}
		fmt.Fprintf(&ib, "%s 10.0.0.1 - - [26/Sep/2026:11:00:00 +0000] \"GET /api/%d HTTP/1.1\" %d 12 \"-\" \"curl\" 80 0.004 [ns-%d-app-%d-80] [] 10.42.0.1:80 12 0.004 %d abc\n",
			now.Add(-time.Duration(ingressLines-j)*100*time.Millisecond).Format(time.RFC3339Nano), j, st, j%50, j%200, st)
	}
	write("cluster/pods/ingress-nginx/"+ctrl.Name+"/controller.log", ib.String())
	fmt.Printf("generated %d nodes x %d journal lines, %d pods, %d events, %d pod logs, %d access-log lines in %s\n", nodes, linesPerNode, pods, events, podLogs, ingressLines, time.Since(start).Round(time.Millisecond))

	stage := func(name string, f func()) {
		runtime.GC()
		var m0 runtime.MemStats
		runtime.ReadMemStats(&m0)
		// peak: sample the heap while the stage runs
		stop, peak := make(chan struct{}), make(chan uint64)
		go func() {
			var hi uint64
			var m runtime.MemStats
			tk := time.NewTicker(10 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-stop:
					peak <- hi
					return
				case <-tk.C:
					runtime.ReadMemStats(&m)
					hi = max(hi, m.HeapAlloc)
				}
			}
		}()
		s := time.Now()
		f()
		d := time.Since(s)
		close(stop)
		hi := <-peak
		runtime.GC()
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		fmt.Printf("  %-24s %9s   allocated %6.0f MiB   peak heap %5.0f MiB   live after %5.0f MiB\n", name, d.Round(time.Millisecond),
			float64(m1.TotalAlloc-m0.TotalAlloc)/(1<<20), float64(max(hi, m1.HeapAlloc))/(1<<20), float64(m1.HeapAlloc)/(1<<20))
	}
	var b *gather.Bundle
	var r *gather.Replayed
	var tl *Timeline
	var ins []Incident
	stage("open (directory)", func() { b, err = gather.Open(dir) })
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	stage("replay (checks)", func() { r, err = b.Replay(config.Default()) })
	if err != nil {
		t.Fatal(err)
	}
	stage("timeline", func() { tl = Build(b, r) })
	stage("incidents", func() { ins = Extract(tl, r.Snap) })
	src := NewBundleSource(b, r)
	stage("probable causes", func() { Analyze(src, tl) })
	var target Incident
	for _, in := range ins {
		if in.Kind == KindEviction {
			target = in
			break
		}
	}
	stage("one incident's context", func() { target.Context(src, tl, ins, DefaultWindow) })
	fmt.Printf("  %d log lines, %d timeline entries, %d incidents\n", tl.Lines, len(tl.Entries), len(ins))
}

// scrubSnapshotForTest marshals the snapshot as gather writes it.
func scrubSnapshotForTest(s *k8s.Snapshot) (string, error) {
	b, err := jsonMarshal(s)
	return string(b), err
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
