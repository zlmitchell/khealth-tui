package gather

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

func tarOf(t *testing.T, gz bool, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("USG banner: authorized use only\n\n" + tarMarker + "\n")
	var zw *gzip.Writer
	tw := tar.NewWriter(&buf)
	if gz {
		zw = gzip.NewWriter(&buf)
		tw = tar.NewWriter(zw)
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	if zw != nil {
		zw.Close()
	}
	return buf.Bytes()
}

func TestReadNodeTar(t *testing.T) {
	for _, gz := range []bool{true, false} {
		dir := t.TempDir()
		b := tarOf(t, gz, map[string]string{
			"./journal/kubelet.log": "hello\n",
			"../escape":             "no",
			"/etc/passwd":           "no",
			"a/../../escape2":       "no",
		})
		files, n, err := readNodeTar(bytes.NewReader(b), dir, 1<<20)
		if err != nil {
			t.Fatalf("gz=%v: %v", gz, err)
		}
		if files != 1 || n != 6 { // only kubelet.log: the rest leave the dir or are absolute
			t.Errorf("gz=%v: files=%d bytes=%d", gz, files, n)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "journal", "kubelet.log")); string(got) != "hello\n" {
			t.Errorf("gz=%v: kubelet.log = %q", gz, got)
		}
		for _, bad := range []string{filepath.Join(filepath.Dir(dir), "escape"), filepath.Join(filepath.Dir(dir), "escape2")} {
			if _, err := os.Stat(bad); err == nil {
				t.Errorf("gz=%v: %s written outside the node dir", gz, bad)
			}
		}
	}
}

func TestReadNodeTarNoMarker(t *testing.T) {
	if _, _, err := readNodeTar(strings.NewReader("gather: tar is not installed on this node\n"), t.TempDir(), 1<<20); err == nil {
		t.Fatal("output without an archive was accepted")
	}
}

func TestReadNodeTarLimit(t *testing.T) {
	b := tarOf(t, true, map[string]string{"big": strings.Repeat("x", 100)})
	if _, _, err := readNodeTar(bytes.NewReader(b), t.TempDir(), 50); err != errTooBig {
		t.Fatalf("err = %v, want errTooBig", err)
	}
}

func TestOutPath(t *testing.T) {
	now := time.Date(2026, 9, 26, 10, 11, 12, 0, time.UTC)
	dir := t.TempDir()
	if got, want := outPath(dir, "rke2/prod", now), filepath.Join(dir, "khealth-bundle-rke2-prod-20260926-101112.tar.gz"); got != want {
		t.Errorf("dir: %s, want %s", got, want)
	}
	if got := outPath("x.tgz", "c", now); got != "x.tgz" {
		t.Errorf("tgz: %s", got)
	}
	if got := outPath("bundle", "c", now); got != "bundle.tar.gz" {
		t.Errorf("bare name: %s", got)
	}
}

func TestParseWorkload(t *testing.T) {
	for ref, want := range map[string]string{
		"shop/deploy/web": "deploy", "shop/Deployments/web": "deployment", "a/sts/db": "sts",
		"a/cronjobs/nightly": "cronjob", "a/po/x": "po",
	} {
		_, k, _, err := parseWorkload(ref)
		if err != nil || k != want {
			t.Errorf("%s: kind %q err %v, want %q", ref, k, err, want)
		}
	}
	for _, bad := range []string{"web", "shop/web", "shop/svc/web", "/deploy/web", "shop/deploy/"} {
		if _, _, _, err := parseWorkload(bad); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

func TestNeedsLogs(t *testing.T) {
	since := time.Now().Add(-time.Hour)
	ready := corev1.ContainerStatus{Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
	pod := func(ns string, phase corev1.PodPhase, cs ...corev1.ContainerStatus) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "p"}, Status: corev1.PodStatus{Phase: phase, ContainerStatuses: cs}}
	}
	oldRestart := ready
	oldRestart.RestartCount = 3
	oldRestart.LastTerminationState.Terminated = &corev1.ContainerStateTerminated{FinishedAt: metav1.NewTime(since.Add(-time.Hour))}
	newRestart := oldRestart
	newRestart.LastTerminationState.Terminated = &corev1.ContainerStateTerminated{FinishedAt: metav1.NewTime(time.Now())}
	notReady := ready
	notReady.Ready = false
	crash := corev1.ContainerStatus{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}
	for name, c := range map[string]struct {
		p    *corev1.Pod
		want bool
	}{
		"healthy app":           {pod("shop", corev1.PodRunning, ready), false},
		"system namespace":      {pod("kube-system", corev1.PodRunning, ready), true},
		"pending":               {pod("shop", corev1.PodPending), true},
		"succeeded":             {pod("shop", corev1.PodSucceeded), false},
		"not ready":             {pod("shop", corev1.PodRunning, notReady), true},
		"crashloop":             {pod("shop", corev1.PodRunning, crash), true},
		"restart before window": {pod("shop", corev1.PodRunning, oldRestart), false},
		"restart inside window": {pod("shop", corev1.PodRunning, newRestart), true},
	} {
		if got := needsLogs(c.p, since); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestNewest(t *testing.T) {
	if got := string(newest([]byte("aaa\nbbb\nccc\n"), 6)); got != "ccc\n" {
		t.Errorf("got %q", got)
	}
	if got := string(newest([]byte("short"), 10)); got != "short" {
		t.Errorf("got %q", got)
	}
}

func TestScrub(t *testing.T) {
	sec := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "s", "managedFields": []any{"x"}, "annotations": map[string]any{"kubectl.kubernetes.io/last-applied-configuration": "{secret}", "keep": "1"}},
		"data":     map[string]any{"password": "aHVudGVyMg=="},
	}}
	scrubCommon(sec)
	keysOnly("data", "stringData")(sec)
	if _, ok, _ := unstructured.NestedFieldNoCopy(sec.Object, "metadata", "managedFields"); ok {
		t.Error("managedFields kept")
	}
	if a := sec.GetAnnotations(); a["keep"] != "1" || a["kubectl.kubernetes.io/last-applied-configuration"] != "" {
		t.Errorf("annotations = %v", a)
	}
	if v, _, _ := unstructured.NestedString(sec.Object, "data", "password"); strings.Contains(v, "aHVudGVy") || !strings.Contains(v, "not collected") {
		t.Errorf("secret value = %q", v)
	}

	dep := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "app", "env": []any{
			map[string]any{"name": "DB_PASSWORD", "value": "hunter2"},
			map[string]any{"name": "LOG_LEVEL", "value": "debug"},
			map[string]any{"name": "API_TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "x"}}},
		}}},
	}}}}}
	scrubPodSpec("spec", "template", "spec")(dep)
	cs, _, _ := unstructured.NestedSlice(dep.Object, "spec", "template", "spec", "containers")
	env := cs[0].(map[string]any)["env"].([]any)
	if v := env[0].(map[string]any)["value"]; v != "<masked>" {
		t.Errorf("DB_PASSWORD = %v", v)
	}
	if v := env[1].(map[string]any)["value"]; v != "debug" {
		t.Errorf("LOG_LEVEL = %v", v)
	}
	if _, has := env[2].(map[string]any)["value"]; has {
		t.Error("a valueFrom entry grew a value")
	}
}

func TestScrubSnapshot(t *testing.T) {
	env := []corev1.EnvVar{{Name: "DB_PASSWORD", Value: "leak-env"}, {Name: "LOG_LEVEL", Value: "debug"}}
	dep := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Annotations: map[string]string{lastApplied: `{"env":"leak-annotation"}`, "keep": "1"}}}
	dep.Spec.Template.Spec.Containers = []corev1.Container{{Name: "web", Env: env}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "leak-managed"}}}}
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Env: env}}
	snap := &k8s.Snapshot{Deployments: []appsv1.Deployment{dep}, Pods: []corev1.Pod{pod}, HelmReleases: []k8s.HelmRelease{{Name: "r", ValuesYAML: "password: leak-values"}}}
	tree, err := scrubSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tree)
	if strings.Contains(string(b), "leak") {
		t.Errorf("scrubbed snapshot still holds a secret: %s", b)
	}
	if !strings.Contains(string(b), `"debug"`) || !strings.Contains(string(b), `"keep":"1"`) {
		t.Errorf("scrubbed too much: %s", b)
	}
	// the live snapshot is untouched
	if snap.Deployments[0].Spec.Template.Spec.Containers[0].Env[0].Value != "leak-env" || snap.HelmReleases[0].ValuesYAML == "" {
		t.Error("scrubSnapshot changed the snapshot it was given")
	}
}

func TestNodeScriptPlaceholders(t *testing.T) {
	s := nodeScript(nodeOpts{BudgetKB: 2048, FileBytes: 1 << 20, PodBytes: 1 << 20, Minutes: 60, PodGlobs: []string{"kube-system_etcd-*", "bad glob;rm -rf /"}})
	if i := strings.Index(s, "__"); i >= 0 && strings.Contains(s[i:], "__BUDGET") {
		t.Error("placeholder left in the script")
	}
	for _, p := range []string{"__BUDGET_KB__", "__FILE_BYTES__", "__POD_BYTES__", "__MINUTES__", "__PODGLOBS__"} {
		if strings.Contains(s, p) {
			t.Errorf("%s not replaced", p)
		}
	}
	if strings.Contains(s, "rm -rf /") {
		t.Error("an unsafe glob reached the script")
	}
	if !strings.Contains(s, "PODGLOBS='kube-system_etcd-*'") {
		t.Error("glob missing")
	}
}

// TestNodeScriptRuns runs gather.sh for real (no kubernetes on the test
// machine: most items come back empty or missing) and reads its archive
// back the way the SSH stream is read.
func TestNodeScriptRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh")
	}
	for _, tool := range []string{"sh", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	script := nodeScript(nodeOpts{BudgetKB: 4096, FileBytes: 64 << 10, PodBytes: 64 << 10, Minutes: 60, PodGlobs: staticPodGlobs})
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sh: %v\n%s", err, stderr.String())
	}
	dir := t.TempDir()
	files, _, err := readNodeTar(&stdout, dir, 64<<20)
	if err != nil {
		t.Fatalf("archive: %v (stderr: %s)", err, stderr.String())
	}
	env, err := os.ReadFile(filepath.Join(dir, "_gather", "node.env"))
	if err != nil || !strings.Contains(string(env), "budget_kb=4096") {
		t.Fatalf("node.env = %q, %v (%d files)", env, err, files)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "system", "node.txt")); err != nil || !strings.Contains(string(b), "hostname:") {
		t.Errorf("system/node.txt = %q, %v", b, err)
	}
	// the staging dir is removed on exit
	for _, l := range strings.Split(string(env), "\n") {
		if d, ok := strings.CutPrefix(l, "staging="); ok {
			if _, err := os.Stat(d); err == nil {
				t.Errorf("staging dir %s left behind", d)
			}
		}
	}
}
