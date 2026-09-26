package gather

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// A bundle written the way Run writes one (snapshot through the scrubber,
// probe output and meta, packed under a top directory) opens and replays
// to the findings its snapshot implies.
func TestOpenReplay(t *testing.T) {
	created := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "crashy-1", CreationTimestamp: metav1.NewTime(created.Add(-time.Hour))},
		Spec:       corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", RestartCount: 7, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		}}},
	}
	snap := &k8s.Snapshot{Taken: created, Distribution: "rke2", Pods: []corev1.Pod{pod}}
	st := stage{dir: t.TempDir()}
	tree, err := scrubSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	must(t, st.writeJSON("snapshot.json", tree))
	must(t, st.writeJSON("manifest.json", Manifest{Format: FormatVersion, Created: created, Context: "lab", Server: "https://10.0.0.1:6443", Scope: "cluster"}))
	must(t, st.write("nodes/n1/probe/node.txt", []byte("\n===HOST\nn1\n5.14.0\nx86_64\n===END\n")))
	must(t, st.writeJSON("nodes/n1/probe/node.meta.json", ProbeMeta{Node: "n1", Host: "10.0.0.1", Started: created, Finished: created, Status: "ok"}))
	must(t, st.write("report.json", []byte(`{"findings":[{"severity":"CRIT","area":"workload","object":"shop/crashy-1","message":"CrashLoopBackOff"}]}`)))

	out := filepath.Join(t.TempDir(), "b.tar.gz")
	if _, err := st.pack(out, "khealth-bundle-lab"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{out, st.dir} { // the tarball, and an unpacked directory
		b, err := Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		r, err := b.Replay(config.Default())
		b.Close()
		if err != nil {
			t.Fatalf("replay %s: %v", path, err)
		}
		if r.Input.Nodes["n1"] == nil || r.Input.Nodes["n1"].Host != "10.0.0.1" || !r.Input.Now.Equal(created) {
			t.Errorf("%s: input not rebuilt: nodes=%v now=%v", path, r.Input.Nodes, r.Input.Now)
		}
		found := false
		for _, f := range r.Findings {
			if f.Object == "shop/crashy-1" && strings.Contains(f.Message, "CrashLoopBackOff") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: replay lost the CrashLoopBackOff finding: %+v", path, r.Findings)
		}
		if onlyNow, onlyThen := r.Diff(); len(onlyThen) != 0 {
			t.Errorf("%s: recorded finding not reproduced: now-only %v then-only %v", path, onlyNow, onlyThen)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a khealth bundle") {
		t.Errorf("empty dir: %v", err)
	}
	st := stage{dir: t.TempDir()}
	must(t, st.writeJSON("manifest.json", Manifest{Format: FormatVersion + 1}))
	if _, err := Open(st.dir); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("future format: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
