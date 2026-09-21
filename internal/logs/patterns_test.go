package logs

import (
	"strings"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	now := time.Date(2024, 9, 18, 12, 0, 0, 0, time.UTC)
	lines := []string{
		`2024-09-18T10:00:01+00:00 cp-1 rke2[100]: time="2024-09-18T10:00:01Z" level=info msg="Waiting for API server to become available"`,
		`2024-09-18T10:00:30+00:00 cp-1 rke2[100]: time="2024-09-18T10:00:30Z" level=info msg="rke2 is up and running"`,
		`2024-09-18T10:20:00+00:00 cp-1 rke2[100]: time="2024-09-18T10:20:00Z" level=info msg="Waiting for API server to become available"`,
		`2024-09-18T10:21:00+00:00 cp-1 rke2[100]: time="2024-09-18T10:21:00Z" level=fatal msg="token does not match"`,
		`2024-09-18T10:22:00+00:00 cp-1 kubelet[200]: E0918 10:22:00.000 12 kubelet.go:100] "something broke" err="x509: certificate signed by unknown authority"`,
		`2024-09-18T10:23:00+00:00 cp-1 containerd[300]: time="..." level=warn msg="failed to pull image \"harbor/x:1\": failed to resolve reference"`,
		`2024-09-18T10:24:00+00:00 cp-1 rke2[100]: time="..." level=info msg="Defragmenting etcd"`,
	}
	s := Classify(lines, now)
	if s.Total != 7 {
		t.Fatalf("total %d", s.Total)
	}
	if s.Startup.IsZero() || s.Startup.Hour() != 10 || s.Startup.Minute() != 0 {
		t.Errorf("startup marker: %v", s.Startup)
	}
	if s.Matches[0].Class != ClassStartup {
		t.Errorf("first wait should be startup noise, got %v", s.Matches[0].Class)
	}
	// same pattern 20 minutes after the up-and-running marker must escalate
	if s.Matches[2].Class != ClassWarn {
		t.Errorf("persistent wait should escalate to warn, got %v", s.Matches[2].Class)
	}
	if s.Matches[3].Pattern == nil || s.Matches[3].Pattern.Name != "token-mismatch" || s.Matches[3].Class != ClassError {
		t.Errorf("token mismatch: %+v", s.Matches[3].Pattern)
	}
	if s.Matches[4].Pattern == nil || s.Matches[4].Pattern.Name != "ca-mismatch" {
		t.Errorf("ca mismatch: %+v", s.Matches[4].Pattern)
	}
	if s.Matches[5].Pattern == nil || s.Matches[5].Pattern.Name != "image-pull-fail" || s.Matches[5].Class != ClassWarn {
		t.Errorf("image pull: %+v", s.Matches[5].Pattern)
	}
	if s.Matches[6].Class != ClassInfo || s.Matches[6].Pattern.Name != "defrag" {
		t.Errorf("defrag should be info: %+v", s.Matches[6])
	}
	if s.Matches[4].Unit != "kubelet" {
		t.Errorf("unit parse: %q", s.Matches[4].Unit)
	}
	if s.Counts[ClassError] != 2 || s.Counts[ClassWarn] != 2 || s.Counts[ClassStartup] != 1 {
		t.Errorf("counts: %v", s.Counts)
	}
	top := s.TopPatterns(ClassError, 5)
	if len(top) != 2 {
		t.Errorf("top errors: %v", top)
	}
}

func TestPatternsCompile(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range patterns {
		if p.Re == nil || p.Name == "" || p.Explain == "" {
			t.Errorf("incomplete pattern %+v", p)
		}
		if seen[p.Name] {
			t.Errorf("duplicate pattern name %s", p.Name)
		}
		seen[p.Name] = true
	}
	if Find("etcd-nospace") == nil {
		t.Errorf("Find failed")
	}
}

func TestS3UploadFailPattern(t *testing.T) {
	lines := []string{
		`2026-09-18T01:00:00+00:00 cp-1 rke2[1]: time="2026-09-18T01:00:00Z" level=error msg="failed to upload snapshot etcd-snapshot-cp-1-1758100000 to S3: AccessDenied: Access Denied"`,
		`2026-09-18T01:00:01+00:00 cp-1 rke2[1]: time="2026-09-18T01:00:01Z" level=error msg="Unable to initialize S3 client: x509: certificate signed by unknown authority"`,
		`2026-09-18T01:00:02+00:00 cp-1 rke2[1]: time="2026-09-18T01:00:02Z" level=info msg="Saving etcd snapshot to /var/lib/rancher/rke2/server/db/snapshots/x"`,
	}
	s := Classify(lines, time.Now())
	if s.ByName["s3-upload-fail"] != 2 {
		t.Errorf("s3-upload-fail=%d byName=%v", s.ByName["s3-upload-fail"], s.ByName)
	}
}

func TestClassifySourcesFiles(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	srcs := []Source{
		{Lines: []string{`2026-01-02T10:00:30+00:00 cp-1 rke2[100]: time="2026-01-02T10:00:30Z" level=info msg="rke2 is up and running"`}},
		{Unit: "kubelet", Lines: []string{
			`I1231 23:59:00.123456    1234 kubelet.go:100] "Started kubelet"`,
			`E0102 10:05:00.000000    1234 kubelet.go:100] "PLEG is not healthy"`,
			``,
		}},
		{Unit: "containerd", Lines: []string{
			`time="2026-01-02T10:03:00.000000000Z" level=warn msg="failed to pull image \"harbor/x:1\": failed to resolve reference"`,
		}},
	}
	s := ClassifySources(srcs, now)
	if s.Total != 4 {
		t.Fatalf("total %d", s.Total)
	}
	// time ordered: kubelet start (last year), rke2 up, containerd, kubelet PLEG
	want := []string{"kubelet", "rke2", "containerd", "kubelet"}
	for i, u := range want {
		if s.Matches[i].Unit != u {
			t.Errorf("match %d unit %q want %q", i, s.Matches[i].Unit, u)
		}
	}
	if y := s.Matches[0].Time.Year(); y != 2025 {
		t.Errorf("klog line dated after now should roll back a year, got %d", y)
	}
	if s.Matches[2].Time.Hour() != 10 || s.Matches[2].Time.Minute() != 3 {
		t.Errorf("logfmt time: %v", s.Matches[2].Time)
	}
	if s.Matches[3].Pattern == nil || s.Matches[3].Pattern.Name != "pleg" || s.Matches[3].Time.Minute() != 5 {
		t.Errorf("pleg: %+v %v", s.Matches[3].Pattern, s.Matches[3].Time)
	}
	if s.Startup.IsZero() {
		t.Errorf("startup marker missing")
	}
}

func TestRancherSystemAgentPatterns(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	lines := []string{
		`2026-09-18T09:00:00+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T09:00:00Z" level=info msg="Rancher System Agent version v0.3.11 (2a0b2ba) is starting"`,
		`2026-09-18T09:00:01+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T09:00:01Z" level=info msg="[K8s] Processing secret custom-1a2b-machine-plan in namespace fleet-default at generation 7 with resource version 12345"`,
		`2026-09-18T09:00:02+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T09:00:02Z" level=info msg="[Applyinator] Applying one-time instructions for plan with checksum abc123"`,
		`2026-09-18T09:00:03+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T09:00:03Z" level=info msg="[Applyinator] Running command: sh [-c run.sh]"`,
		`2026-09-18T09:00:40+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T09:00:40Z" level=info msg="[Applyinator] Command sh [-c run.sh] finished with err: <nil> and exit code: 0"`,
		`2026-09-18T10:00:00+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T10:00:00Z" level=error msg="[Applyinator] Command sh [-c run.sh] finished with err: exit status 1 and exit code: 1"`,
		`2026-09-18T10:00:01+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T10:00:01Z" level=error msg="error while running probe kubelet: dial tcp 127.0.0.1:10248: connect: connection refused"`,
		`2026-09-18T10:00:02+00:00 w-1 rancher-system-agent[900]: time="2026-09-18T10:00:02Z" level=info msg="[Applyinator] Applying periodic instructions"`,
	}
	s := Classify(lines, now)
	want := []string{"rancher-agent-start", "rancher-plan-received", "rancher-plan-applied", "rancher-plan-periodic", "rancher-plan-periodic", "rancher-plan-failed", "rancher-probe-fail", "rancher-plan-periodic"}
	for i, name := range want {
		if s.Matches[i].Pattern == nil || s.Matches[i].Pattern.Name != name {
			t.Errorf("line %d: got %+v want %s", i, s.Matches[i].Pattern, name)
		}
	}
	if s.Matches[5].Class != ClassError || s.Matches[2].Class != ClassWarn || s.Matches[6].Class != ClassWarn {
		t.Errorf("classes: applied=%v failed=%v probe=%v", s.Matches[2].Class, s.Matches[5].Class, s.Matches[6].Class)
	}
	if m := s.Last("rancher-plan-failed"); m.Time.Hour() != 10 {
		t.Errorf("Last: %v", m.Time)
	}
	if m := s.Last("nope"); !m.Time.IsZero() {
		t.Errorf("Last unseen should be zero")
	}
}

// TestSupervisorPatterns: the rke2 supervisor's boot-time errors are
// startup noise with an explanation (escalated only when they persist), the
// leader-lease and KCM early-start lines carry their fix, and none of them
// fall through to the generic rules.
func TestSupervisorPatterns(t *testing.T) {
	now := time.Date(2026, 9, 20, 16, 30, 0, 0, time.UTC)
	lines := []string{
		`2026-09-20T12:15:09-0400 redhat9-test rke2[1236]: time="2026-09-20T12:15:09-04:00" level=error msg="Sending HTTP/1.1 503 response to 127.0.0.1:41984: runtime core not ready"`,
		`2026-09-20T12:15:53-0400 redhat9-test rke2[1236]: time="2026-09-20T12:15:53-04:00" level=warning msg="Failed to list nodes with etcd role: runtime core not ready"`,
		`2026-09-20T12:16:09-0400 redhat9-test rke2[1236]: time="2026-09-20T12:16:09-04:00" level=error msg="Sending HTTP/1.1 502 response to 127.0.0.1:55536: dial tcp 10.42.2.14:10250: operation was canceled"`,
		`2026-09-20T12:14:50-0400 redhat9-test-2 rke2[1200]: time="2026-09-20T12:14:50-04:00" level=warning msg="Unable to reconcile with remote datastore: Get \"https://10.0.0.143:9345/v1-rke2/server-bootstrap\": dial tcp 10.0.0.143:9345: connect: no route to host"`,
		`2026-09-20T12:15:09-0400 redhat9-test rke2[1236]: time="2026-09-20T12:15:09-04:00" level=warning msg="Bootstrap key already exists"`,
		`2026-09-20T13:43:09-0400 redhat9-test rke2[1236]: time="2026-09-20T13:43:09-04:00" level=warning msg="Proxy error: write failed: write tcp 127.0.0.1:49390->127.0.0.1:10250: write: broken pipe"`,
		`E0920 16:03:58.039783       1 leaderelection.go:452] "Error retrieving lease lock" err="Get \"https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/kube-scheduler?timeout=5s\": context deadline exceeded"`,
		`E0920 16:15:07.674131       1 run.go:72] "command failed" err="unable to load configmap based request-header-client-ca-file: Get \"https://127.0.0.1:6443/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication\": dial tcp 127.0.0.1:6443: connect: connection refused"`,
	}
	s := Classify(lines, now)
	want := []struct {
		name  string
		class Class
	}{
		{"supervisor-not-ready", ClassStartup}, {"supervisor-not-ready", ClassStartup}, {"supervisor-proxy-502", ClassStartup},
		{"supervisor-peer-down", ClassStartup}, {"bootstrap-exists", ClassInfo}, {"supervisor-proxy-eof", ClassInfo},
		{"lease-lost", ClassWarn}, {"kcm-early-start", ClassStartup},
	}
	for i, w := range want {
		m := s.Matches[i]
		if m.Pattern == nil || m.Pattern.Name != w.name || m.Class != w.class {
			t.Errorf("line %d: got %v/%v want %s/%v", i, m.Pattern, m.Class, w.name, w.class)
			continue
		}
		if !strings.Contains(m.Pattern.Explain, "config.yaml") && !strings.Contains(m.Pattern.Explain, "Normal") && !strings.Contains(m.Pattern.Explain, "Harmless") && !strings.Contains(m.Pattern.Explain, "normal") {
			t.Errorf("line %d: explanation carries neither a fix nor a verdict: %q", i, m.Pattern.Explain)
		}
	}
	if s.Counts[ClassError] != 0 {
		t.Errorf("boot noise counted as errors: %+v", s.Counts)
	}
	// the same 502s an hour after the supervisor came up are a warning
	late := []string{
		`2026-09-20T12:16:45-0400 redhat9-test rke2[1236]: time="2026-09-20T12:16:45-04:00" level=info msg="rke2 is up and running"`,
		`2026-09-20T13:30:00-0400 redhat9-test rke2[1236]: time="2026-09-20T13:30:00-04:00" level=error msg="Sending HTTP/1.1 502 response to 127.0.0.1:55536: dial tcp 10.42.2.14:10250: operation was canceled"`,
	}
	s = Classify(late, now)
	if s.Matches[1].Class != ClassWarn {
		t.Errorf("persistent 502 not escalated: %v", s.Matches[1].Class)
	}
}

// TestStartupNoise: the kubelet restart races have rules; an unmatched
// error inside a startup window that never recurs becomes startup noise,
// while the same shape seen again after the window stays a generic error
// with a recurrence the detail can show.
func TestStartupNoise(t *testing.T) {
	now := time.Date(2026, 9, 20, 18, 0, 0, 0, time.UTC)
	kubelet := []string{
		`I0920 12:02:40.000000  887086 kubelet.go:100] "Starting kubelet"`,
		`E0920 12:02:43.048339  887086 kubelet.go:3355] "Failed creating a mirror pod" err="pods \"kube-scheduler-redhat9-test\" already exists" pod="kube-system/kube-scheduler-redhat9-test"`,
		`W0920 12:02:44.000000  887086 kubelet_volumes.go:161] "Cleaned up orphaned pod volumes dir" podUID="5b30e113ffd0614a9756ecad79a77d1a" path="/var/lib/kubelet/pods/5b30e113"`,
		`E0920 12:02:45.000000  887086 log.go:32] "ContainerStatus from runtime service failed" err="rpc error: code = NotFound desc = an error occurred when try to find container \"abc\": not found" containerID="abc"`,
		`E0920 12:03:49.000000  887086 controller.go:251] "Failed to update lease" err="Put \"https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/redhat9-test?timeout=10s\": context deadline exceeded"`,
		`E0920 12:03:50.000000  887086 something.go:10] "Widget reconcile failed" err="widget \"a\" is on fire" widget="a"`,
		`E0920 12:03:51.000000  887086 other.go:10] "Gadget reconcile failed" err="gadget \"b\" is on fire" gadget="b"`,
		`E0920 12:40:00.000000  887086 other.go:10] "Gadget reconcile failed" err="gadget \"c\" is on fire" gadget="c"`,
	}
	journal := []string{
		`2026-09-20T12:02:38+00:00 redhat9-test rke2[1236]: time="2026-09-20T12:02:38Z" level=info msg="Starting rke2 v1.35.8+rke2r1 (0fec82ea)"`,
		`2026-09-20T12:04:30+00:00 redhat9-test rke2[1236]: time="2026-09-20T12:04:30Z" level=info msg="rke2 is up and running"`,
	}
	s := ClassifySources([]Source{{Lines: journal}, {Unit: "kubelet", Lines: kubelet}}, now)
	if w := s.StartupWindows(); len(w) != 1 || !w[0][0].Equal(time.Date(2026, 9, 20, 12, 2, 38, 0, time.UTC)) || !w[0][1].Equal(time.Date(2026, 9, 20, 12, 7, 40, 0, time.UTC)) {
		t.Fatalf("startup windows: %v", w)
	}
	byLine := map[string]Match{}
	for _, m := range s.Matches {
		byLine[m.Line] = m
	}
	want := map[int]struct {
		name  string
		class Class
	}{
		1: {"mirror-pod-exists", ClassStartup}, 2: {"orphaned-volumes-cleanup", ClassInfo}, 3: {"container-gone", ClassStartup},
		4: {"node-lease", ClassStartup}, 5: {"startup-unmatched", ClassStartup}, 6: {"generic-error", ClassError}, 7: {"generic-error", ClassError},
	}
	for i, w := range want {
		m := byLine[kubelet[i]]
		if m.Pattern == nil || m.Pattern.Name != w.name || m.Class != w.class {
			t.Errorf("kubelet line %d: got %v/%v want %s/%v", i, m.Pattern, m.Class, w.name, w.class)
		}
	}
	if s.Counts[ClassError] != 2 || s.ByName["generic-error"] != 2 || s.ByName["startup-unmatched"] != 1 {
		t.Errorf("counts: %v byName generic=%d unmatched=%d", s.Counts, s.ByName["generic-error"], s.ByName["startup-unmatched"])
	}
	r := s.Recur(byLine[kubelet[6]])
	if r.Count != 2 || r.First.Minute() != 3 || r.Last.Minute() != 40 || r.Ongoing {
		t.Errorf("recurrence: %+v", r)
	}
	if Signature(kubelet[6]) != Signature(kubelet[7]) || Signature(kubelet[5]) == Signature(kubelet[6]) {
		t.Errorf("signatures: %q %q %q", Signature(kubelet[5]), Signature(kubelet[6]), Signature(kubelet[7]))
	}
	// no start marker: nothing is demoted
	s = ClassifySources([]Source{{Unit: "kubelet", Lines: kubelet[5:6]}}, now)
	if s.Matches[0].Pattern.Name != "generic-error" {
		t.Errorf("without a start marker the line must stay generic: %v", s.Matches[0].Pattern.Name)
	}
}
