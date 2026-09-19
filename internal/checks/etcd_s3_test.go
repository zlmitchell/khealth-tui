package checks

import (
	"strings"
	"testing"
	"time"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
)

func s3Probe(node string, kv map[string]string) *etcd.Probe {
	cfg := map[string]string{}
	for k, v := range kv {
		cfg[k] = v
	}
	return &etcd.Probe{Node: node, Dist: "rke2", RKE2Config: cfg}
}

func s3Findings(in Input) []string {
	var out []string
	for _, f := range etcdFindings(in) {
		if strings.Contains(strings.ToLower(f.Message), "s3") || strings.Contains(f.Message, "skip-ssl") {
			out = append(out, f.Severity.String()+" "+f.Object+": "+f.Message)
		}
	}
	return out
}

func containsAll(t *testing.T, got []string, wants ...string) {
	t.Helper()
	all := strings.Join(got, "\n")
	for _, w := range wants {
		if !strings.Contains(all, w) {
			t.Errorf("missing %q in:\n%s", w, all)
		}
	}
}

func TestS3ConfigForInlineAndSecret(t *testing.T) {
	inline := s3Probe("cp-1", map[string]string{"etcd-s3": "true", "etcd-s3-endpoint": "minio.lab:9000", "etcd-s3-bucket": "b", "etcd-s3-folder": "prod", "etcd-s3-access-key": "<set>", "etcd-s3-secret-key": "<set>", "etcd-s3-endpoint-ca": "/etc/s3-ca.crt"})
	c := S3ConfigFor(inline, nil)
	if !c.Enabled || c.Source != "config.yaml" || !c.HasCredentials || c.URL() != "https://minio.lab:9000" || c.CAFile != "/etc/s3-ca.crt" || len(c.Missing()) != 0 {
		t.Errorf("inline: %+v missing=%v", c, c.Missing())
	}
	viaSecret := s3Probe("cp-2", map[string]string{"etcd-s3": "true", "etcd-s3-config-secret": "rke2-s3"})
	c = S3ConfigFor(viaSecret, nil)
	if c.Source != "secret rke2-s3" || c.SecretFound || c.Bucket != "" {
		t.Errorf("secret unread: %+v", c)
	}
	sec := &k8s.S3SecretInfo{Name: "rke2-s3", Found: true, Endpoint: "https://s3.example.com", Bucket: "b", Folder: "prod", HasCredentials: true, EndpointCA: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"}
	c = S3ConfigFor(viaSecret, sec)
	if !c.SecretFound || c.Bucket != "b" || !c.HasCredentials || c.CAPEM == "" || c.Key() != "https://s3.example.com/b/prod" {
		t.Errorf("secret merged: %+v", c)
	}
	if S3ConfigFor(inline, nil).Key() == c.Key() {
		t.Errorf("different endpoints must differ")
	}
}

func TestS3DriftAndCompleteness(t *testing.T) {
	in := baseInput()
	in.EtcdExec = healthyExec()
	in.Etcd["cp-1"] = s3Probe("cp-1", map[string]string{"etcd-s3": "true", "etcd-s3-endpoint": "minio.lab:9000", "etcd-s3-bucket": "b", "etcd-s3-access-key": "<set>", "etcd-s3-secret-key": "<set>"})
	in.Etcd["cp-2"] = s3Probe("cp-2", map[string]string{"etcd-s3": "true", "etcd-s3-endpoint": "minio.lab:9000", "etcd-s3-bucket": "other", "etcd-s3-skip-ssl-verify": "true"})
	in.Etcd["cp-3"] = s3Probe("cp-3", map[string]string{})
	in.Snap.RKE2Snapshots = []k8s.EtcdSnapshotRecord{{Name: "s1", Node: "cp-1", Created: now.Add(-time.Hour), S3: true, Status: "successful"}}
	got := s3Findings(in)
	containsAll(t, got,
		"S3 snapshots enabled on cp-1,cp-2 but not on cp-3",
		"different S3 destinations: cp-1 -> https://minio.lab:9000/b/; cp-2 -> https://minio.lab:9000/other/",
		"INFO cp-2: S3 snapshots enabled but credentials not configured (config.yaml)",
		"skip-ssl-verify is on",
	)
	for _, g := range got {
		if strings.Contains(g, "cp-1: S3 snapshots enabled but") {
			t.Errorf("cp-1 is complete: %s", g)
		}
	}
}

func TestS3UploadsStale(t *testing.T) {
	in := baseInput()
	in.EtcdExec = healthyExec()
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		in.Etcd[n] = s3Probe(n, map[string]string{"etcd-s3": "true", "etcd-s3-config-secret": "rke2-s3"})
	}
	in.S3 = &k8s.S3SecretInfo{Name: "rke2-s3", Found: true, Endpoint: "s3.example.com", Bucket: "b", HasCredentials: true}
	in.Snap.RKE2Snapshots = []k8s.EtcdSnapshotRecord{
		{Name: "local-new", Node: "cp-1", Created: now.Add(-time.Hour), Status: "successful"},
		{Name: "s3-old", Node: "cp-1", Created: now.Add(-49 * time.Hour), S3: true, Status: "successful"},
		{Name: "s3-fail", Node: "cp-2", Created: now.Add(-time.Hour), S3: true, Status: "failed", Message: "AccessDenied: bucket policy"},
	}
	in.Logs["cp-2"] = &logs.Summary{ByName: map[string]int{"s3-upload-fail": 4}}
	in.S3Reach = map[string]etcd.S3Check{
		"cp-1": {Node: "cp-1", URL: "https://s3.example.com", OK: true, HTTPCode: 403, Detail: "HTTP 403"},
		"cp-3": {Node: "cp-3", URL: "https://s3.example.com", Detail: "(60) SSL certificate problem: unable to get local issuer certificate"},
	}
	got := s3Findings(in)
	containsAll(t, got,
		"latest S3 snapshot upload is 2d",
		"1 snapshot record(s) failed to upload to S3: AccessDenied: bucket policy",
		"cp-2: 4 S3 upload error(s) in the journal",
		"CRIT cp-3: S3 endpoint https://s3.example.com unreachable from the node: (60) SSL certificate problem",
	)
	all := strings.Join(got, "\n")
	if strings.Contains(all, "cp-1: S3 endpoint") || strings.Contains(all, "not on") || strings.Contains(all, "different S3") {
		t.Errorf("unexpected:\n%s", all)
	}
	rows := S3Rows(in)
	if len(rows) != 3 || rows[0][6] != "ok HTTP 403" || !strings.HasPrefix(rows[2][6], "FAIL (60)") || rows[1][6] != "-" {
		t.Errorf("rows: %v", rows)
	}
}

func TestS3SecretMissing(t *testing.T) {
	in := baseInput()
	in.EtcdExec = healthyExec()
	in.Etcd["cp-1"] = s3Probe("cp-1", map[string]string{"etcd-s3": "true", "etcd-s3-config-secret": "rke2-s3"})
	in.S3 = &k8s.S3SecretInfo{Name: "rke2-s3", Err: `secrets "rke2-s3" not found`}
	containsAll(t, s3Findings(in), "etcd-s3-config-secret rke2-s3 not found in kube-system")
}
