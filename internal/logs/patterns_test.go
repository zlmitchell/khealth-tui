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
