package etcd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// scriptedExec answers etcdctl verbs from a table keyed by the first
// non-flag arguments ("member list", "endpoint health", ...) and records
// the --endpoints flag each call used.
type scriptedExec struct {
	out       map[string]string
	stderr    map[string]string
	fail      map[string]error
	endpoints map[string]string
	calls     []string
}

func (s *scriptedExec) ExecInPod(_ context.Context, ns, pod, container string, cmd []string) (string, string, error) {
	if ns != "kube-system" || container != "etcd" || cmd[0] != "etcdctl" {
		return "", "", errors.New("unexpected exec target")
	}
	var words []string
	eps := ""
	for _, c := range cmd[1:] {
		switch {
		case strings.HasPrefix(c, "--endpoints="):
			eps = strings.TrimPrefix(c, "--endpoints=")
		case strings.HasPrefix(c, "--") || c == "-w" || c == "json":
		default:
			words = append(words, c)
		}
	}
	key := strings.Join(words, " ")
	if len(words) > 1 && words[0] == "get" {
		key = "get " + words[1]
	}
	s.calls = append(s.calls, key)
	if s.endpoints == nil {
		s.endpoints = map[string]string{}
	}
	s.endpoints[key] = eps
	return s.out[key], s.stderr[key], s.fail[key]
}

const members2 = `{"header":{"cluster_id":1},"members":[{"ID":1,"name":"cp-1","peerURLs":["https://10.0.0.1:2380"],"clientURLs":["https://10.0.0.1:2379"]},{"ID":2,"name":"cp-2","peerURLs":["https://10.0.0.2:2380"],"clientURLs":["https://10.0.0.2:2379"]}]}`

func TestExecProbeHappyPath(t *testing.T) {
	ex := &scriptedExec{
		out: map[string]string{
			"member list":     members2,
			"endpoint health": "{\"level\":\"warn\",\"msg\":\"ignored\"}\n[{\"endpoint\":\"https://10.0.0.1:2379\",\"health\":true,\"took\":\"3ms\"},{\"endpoint\":\"https://10.0.0.2:2379\",\"health\":false,\"took\":\"5s\",\"error\":\"context deadline exceeded\"}]",
			"endpoint status": `[{"Endpoint":"https://10.0.0.1:2379","Status":{"header":{"member_id":1,"raft_term":7},"version":"3.5.9","dbSize":4096,"dbSizeInUse":2048,"leader":1,"raftIndex":100}}]`,
			"alarm list":      `{"alarms":[{"memberID":2,"alarm":1}]}`,
		},
		stderr: map[string]string{"endpoint status": "{\"level\":\"warn\",\"msg\":\"some warning\"}"},
		fail:   map[string]error{"endpoint health": errors.New("exit status 1")},
	}
	p := ExecProbe(context.Background(), ex, "cp-1", "etcd-cp-1", "rke2")
	if p.Err != nil || p.Node != "cp-1" || p.Dist != "rke2" || p.EtcdctlVia != "kubectl exec etcd-cp-1" || p.Duration <= 0 {
		t.Fatalf("probe: %+v", p)
	}
	if p.CA != "/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt" || !strings.HasSuffix(p.Cert, "server-client.crt") {
		t.Errorf("rke2 cert paths: %s %s", p.CA, p.Cert)
	}
	if len(p.Members) != 2 || p.Members[0].Name != "cp-1" || p.Members[0].ID != "1" || p.Members[1].ClientURLs[0] != "https://10.0.0.2:2379" {
		t.Errorf("members: %+v", p.Members)
	}
	// health/status went to every member; member list and alarms to localhost
	if ex.endpoints["member list"] != "https://127.0.0.1:2379" || ex.endpoints["endpoint health"] != "https://10.0.0.1:2379,https://10.0.0.2:2379" || ex.endpoints["alarm list"] != "https://127.0.0.1:2379" {
		t.Errorf("endpoints used: %v", ex.endpoints)
	}
	if p.Endpoint != "https://10.0.0.1:2379,https://10.0.0.2:2379" {
		t.Errorf("endpoint: %s", p.Endpoint)
	}
	// health: the down member fails the whole thing, the warning line before the JSON is skipped
	if len(p.EndpointHealth) != 2 || !p.EndpointHealth[0].Healthy || p.EndpointHealth[1].Healthy || p.EndpointHealth[1].Error != "context deadline exceeded" || p.EndpointHealth[1].Took != "5s" {
		t.Errorf("endpoint health: %+v", p.EndpointHealth)
	}
	if p.Health == nil || p.Health.Healthy || p.Health.Reason != "https://10.0.0.2:2379 context deadline exceeded" || !strings.HasPrefix(p.Health.Raw, `{"level"`) {
		t.Errorf("health: %+v", p.Health)
	}
	if len(p.Statuses) != 1 || p.Statuses[0].Endpoint != "https://10.0.0.1:2379" || p.Statuses[0].Version != "3.5.9" || p.Statuses[0].DBSize != 4096 {
		t.Errorf("statuses: %+v", p.Statuses)
	}
	if len(p.Alarms) != 1 || p.Alarms[0].Type != "NOSPACE" || p.Alarms[0].MemberID != "2" {
		t.Errorf("alarms: %+v", p.Alarms)
	}
	// the failed health call (output was still printed) is only a diagnostic; stderr is kept
	if p.EtcdctlDiag != "" || p.Stderr != `{"level":"warn","msg":"some warning"}` {
		t.Errorf("diag %q stderr %q", p.EtcdctlDiag, p.Stderr)
	}
	if !strings.Contains(p.EtcdctlOut, "member list:\n") || !strings.Contains(p.EtcdctlOut, "endpoint health:\n") || !strings.Contains(p.EtcdctlOut, "---STATUS") || !strings.Contains(p.EtcdctlOut, "---ALARMS") {
		t.Errorf("etcdctl out: %q", p.EtcdctlOut)
	}
	// no secret sampled when the key listing is empty
	if p.Encryption != nil {
		t.Errorf("encryption without keys: %+v", p.Encryption)
	}
	if m := p.MemberByEndpoint("https://10.0.0.2:2379"); m == nil || m.Name != "cp-2" {
		t.Errorf("member by endpoint: %+v", m)
	}
	if p.MemberByEndpoint("https://nowhere:2379") != nil {
		t.Error("unknown endpoint")
	}
}

func TestExecProbeFailures(t *testing.T) {
	// exec itself fails with nothing on stdout
	ex := &scriptedExec{fail: map[string]error{"member list": errors.New(`pods "etcd-cp-1" is forbidden`)}, stderr: map[string]string{"member list": "rbac denied\nsecond line"}}
	p := ExecProbe(context.Background(), ex, "cp-1", "etcd-cp-1", "kubeadm")
	if p.Err == nil || !strings.HasPrefix(p.Err.Error(), "member list: ") || !strings.Contains(p.Err.Error(), "is forbidden: rbac denied") || strings.Contains(p.Err.Error(), "second line") || p.EtcdctlDiag != p.Err.Error() {
		t.Errorf("exec failure: %v diag=%q", p.Err, p.EtcdctlDiag)
	}
	if len(ex.calls) != 1 {
		t.Errorf("must stop after member list: %v", ex.calls)
	}
	if p.CA != "/etc/kubernetes/pki/etcd/ca.crt" {
		t.Errorf("kubeadm cert paths: %s", p.CA)
	}

	// member list that parses to nothing
	ex = &scriptedExec{out: map[string]string{"member list": `{"members":[]}`}}
	p = ExecProbe(context.Background(), ex, "cp-1", "etcd-cp-1", "k3s")
	if p.Err == nil || !strings.Contains(p.Err.Error(), "returned no members") || len(ex.calls) != 1 {
		t.Errorf("no members: %v calls=%v", p.Err, ex.calls)
	}
	if !strings.HasPrefix(p.CA, "/var/lib/rancher/k3s/") {
		t.Errorf("k3s cert paths: %s", p.CA)
	}

	// members without client URLs fall back to localhost; every later call failing is reported as diagnostics
	ex = &scriptedExec{
		out:  map[string]string{"member list": `{"members":[{"ID":1,"name":"solo"}]}`},
		fail: map[string]error{"endpoint health": errors.New("h"), "endpoint status": errors.New("s"), "alarm list": errors.New("a"), "get /registry/secrets/": errors.New("g")},
	}
	p = ExecProbe(context.Background(), ex, "cp-1", "etcd-cp-1", "rke2")
	if p.Err != nil || p.Endpoint != "https://127.0.0.1:2379" || ex.endpoints["endpoint status"] != "https://127.0.0.1:2379" {
		t.Errorf("localhost fallback: %v %q", p.Err, p.Endpoint)
	}
	if p.EtcdctlDiag != "h: ; s: ; a: " {
		t.Errorf("diag: %q", p.EtcdctlDiag)
	}
	if p.Health == nil || p.Health.Healthy || len(p.EndpointHealth) != 0 || p.Encryption != nil {
		t.Errorf("empty health: %+v enc=%+v", p.Health, p.Encryption)
	}

	// the sampled value read fails: no sample, but the key listing is not retried
	ex = &scriptedExec{
		out:  map[string]string{"member list": members2, "get /registry/secrets/": "\n/registry/secrets/default/a\n/registry/secrets/default/b\n"},
		fail: map[string]error{"get /registry/secrets/default/a": errors.New("read failed")},
	}
	p = ExecProbe(context.Background(), ex, "cp-1", "etcd-cp-1", "rke2")
	if p.Encryption != nil {
		t.Errorf("failed value read: %+v", p.Encryption)
	}
	if strings.Join(ex.calls, ";") != "member list;endpoint health;endpoint status;alarm list;get /registry/secrets/;get /registry/secrets/default/a" {
		t.Errorf("calls: %v", ex.calls)
	}
}

func TestCertPathsAndHelpers(t *testing.T) {
	for _, dist := range []string{"rke2", "k3s", "kubeadm", "unknown"} {
		ca, cert, key := CertPaths(dist)
		if ca == "" || cert == "" || key == "" || !strings.HasSuffix(cert, ".crt") || !strings.HasSuffix(key, ".key") {
			t.Errorf("%s: %s %s %s", dist, ca, cert, key)
		}
	}
	if ca, _, _ := CertPaths("unknown"); ca != "/etc/kubernetes/pki/etcd/ca.crt" {
		t.Errorf("default paths: %s", ca)
	}
	if got := printablePrefix("k8s:enc:aescbc:v1:k:\x00\x01\xffabc", 24); got != "k8s:enc:aescbc:v1:k:...a" || len(got) != 24 {
		t.Errorf("printable prefix: %q", got)
	}
	if printablePrefix("short", 24) != "short" || printablePrefix("", 3) != "" {
		t.Error("short values")
	}
	if parseEndpointHealth("") != nil || parseEndpointHealth("not json") != nil || parseEndpointHealth("{\"not\":\"a list\"}") != nil {
		t.Error("unparsable health")
	}
	h := parseEndpointHealth("  warn\n[{\"endpoint\":\"e\",\"health\":true}]  ")
	if len(h) != 1 || h[0].Endpoint != "e" || !h[0].Healthy {
		t.Errorf("health with prefix: %+v", h)
	}
}
