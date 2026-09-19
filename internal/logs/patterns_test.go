package logs

import (
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
	for _, p := range Patterns() {
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
