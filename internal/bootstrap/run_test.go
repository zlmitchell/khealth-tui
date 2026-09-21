package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/sshrun/sshtest"
)

// apiserver is a TLS server answering /version; its certificate (valid for
// 127.0.0.1) doubles as the CA in the kubeconfigs the "node" hands out.
func apiserver(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" || r.Header.Get("Authorization") != "Bearer abc" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"major":"1","minor":"30","gitVersion":"v1.30.4+rke2r1"}`)
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv, base64.StdEncoding.EncodeToString(ca)
}

func nodeKubeconfig(port, caData string) string {
	return "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    certificate-authority-data: " + caData + "\n    server: https://127.0.0.1:" + port + "\ncontexts:\n- name: default\n  context:\n    cluster: default\n    user: default\ncurrent-context: default\nusers:\n- name: default\n  user:\n    token: abc\n"
}

func nodeOutput(kubeconfig, cert string) string {
	out := ""
	if kubeconfig != "" {
		out += "=== KUBECONFIG /etc/rancher/rke2/rke2.yaml\n" + kubeconfig + "\n=== END\n"
	}
	out += "=== CONFIG /etc/rancher/rke2/config.yaml\ntls-san:\n  - k8s-prod.example.invalid\n  - k8s-new.example.invalid\ntoken: x\n=== END\n" +
		"=== CERT /var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt\n" + cert + "=== END\n" +
		"=== HOSTNAME\ncp-1.example.com\n=== END\n=== NODEIPS\n10.0.0.11\n=== END\n"
	return out
}

// node is an SSH server whose bootstrap script prints out; it also accepts
// the client keys of the trusted servers so one runner reaches them all.
func node(t *testing.T, out string, trust ...*sshtest.Server) *sshtest.Server {
	t.Helper()
	srv := sshtest.New(t, func(cmd, stdin string) (string, string, int) {
		if strings.HasPrefix(stdin, "id -u;") {
			return "0\n", "", 0
		}
		if !strings.Contains(stdin, "=== KUBECONFIG") {
			return "", "unexpected script", 1
		}
		return out, "", 0
	})
	for _, o := range trust {
		srv.AcceptKey(o.ClientPub)
	}
	return srv
}

func runner(t *testing.T, srv *sshtest.Server) *sshrun.Runner {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	r, err := sshrun.New(config.SSH{User: "root", Key: srv.KeyPath, Timeout: 5 * time.Second, Concurrency: 1, Become: "auto", Sudo: true, Nice: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestFetchOverSSH(t *testing.T) {
	cert := servingCert(t, []string{"kubernetes", "cp-1"}, []string{"127.0.0.1", "10.0.0.11"})
	srv := node(t, nodeOutput(rke2yaml, cert))
	r := runner(t, srv)
	src, err := Fetch(context.Background(), r, srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if src.Host != srv.Addr || src.Path != "/etc/rancher/rke2/rke2.yaml" || src.Hostname != "cp-1.example.com" || len(src.CertDNS) != 2 || len(src.CertIPs) != 2 || len(src.TLSSAN) != 2 || len(src.NodeIPs) != 1 || len(src.ConfigDirs) != 1 {
		t.Errorf("source: %+v", src)
	}
	if !strings.HasSuffix(string(src.Kubeconfig), "\n") || !strings.Contains(string(src.Kubeconfig), "127.0.0.1:6443") {
		t.Errorf("kubeconfig: %q", src.Kubeconfig)
	}
	if src.Dist() != "rke2" {
		t.Errorf("dist %q", src.Dist())
	}

	// a worker (no kubeconfig on disk) is refused with the stderr attached
	worker := node(t, nodeOutput("", cert), srv)
	if _, err := Fetch(context.Background(), r, worker.Addr); err == nil || !strings.Contains(err.Error(), "no admin kubeconfig found") {
		t.Errorf("worker: %v", err)
	}
	// an unreachable host is an ssh error
	if _, err := Fetch(context.Background(), r, "127.0.0.1:1"); err == nil || !strings.HasPrefix(err.Error(), "ssh 127.0.0.1:1: ") {
		t.Errorf("unreachable: %v", err)
	}
	// a broken certificate on the node is a parse error
	broken := node(t, nodeOutput(rke2yaml, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), srv)
	if _, err := Fetch(context.Background(), r, broken.Addr); err == nil || !strings.Contains(err.Error(), "parse /var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt") {
		t.Errorf("bad cert: %v", err)
	}
	noPEM := &Source{}
	if err := noPEM.parse("=== CERT /x\nnot pem\n=== END\n"); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("no pem: %v", err)
	}
}

func TestRunEndToEnd(t *testing.T) {
	api, caData := apiserver(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(api.URL, "https://"))
	// the certificate offers a VIP name that does not resolve from here and
	// only in-cluster addresses, so the SSH host itself ends up being used
	cert := servingCert(t, []string{"kubernetes", "k8s-prod.example.invalid"}, []string{"127.0.0.1", "10.43.0.1"})
	srv := node(t, nodeOutput(nodeKubeconfig(port, caData), cert))
	r := runner(t, srv)
	home := t.TempDir()
	t.Setenv("HOME", home)
	var logs []string
	lookup := func(name string) []net.IP {
		if name == "k8s-prod.example.invalid" {
			return []net.IP{net.ParseIP("10.0.0.100")}
		}
		return nil
	}
	res, err := Run(context.Background(), r, Options{Hosts: []string{"127.0.0.1:1", srv.Addr}, Lookup: lookup, Log: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, strings.Join(logs, "\n"))
	}
	if res.Version != "v1.30.4+rke2r1" || res.Name != "cp-example-com" || res.Server != "https://127.0.0.1" || res.Endpoint.Host != "127.0.0.1" || res.Endpoint.Score != 10 {
		t.Errorf("result: %+v", res)
	}
	if res.Path != filepath.Join(home, ".kube", "khealth-cp-example-com.yaml") {
		t.Errorf("path %q", res.Path)
	}
	kc, err := clientcmd.LoadFromFile(res.Path)
	if err != nil || kc.CurrentContext != "cp-example-com" || kc.Clusters["cp-example-com"] == nil || kc.Clusters["cp-example-com"].Server != "https://127.0.0.1:"+port {
		t.Errorf("written kubeconfig: %v %+v", err, kc)
	}
	joined := strings.Join(res.Notes, "\n")
	if !strings.Contains(joined, `tls-san "k8s-new.example.invalid" is configured but not in the serving certificate yet: restart rke2-server`) {
		t.Errorf("pending tls-san note missing: %s", joined)
	}
	if !strings.Contains(joined, "add `tls-san: [127.0.0.1]` to /etc/rancher/rke2/config.yaml on every server so the certificate covers a stable name, then restart rke2-server") {
		t.Errorf("san hint missing: %s", joined)
	}
	all := strings.Join(logs, "\n")
	for _, want := range []string{"127.0.0.1:1: ssh 127.0.0.1:1", "rke2.yaml (cert serving-kube-apiserver.crt: 2 DNS, 2 IP SANs)", "k8s-prod.example.invalid", "does not resolve", "ok  v1.30.4+rke2r1"} {
		if !strings.Contains(all, want) {
			t.Errorf("log lacks %q:\n%s", want, all)
		}
	}
	// a second run to an explicit path keeps a backup of the old file
	out := filepath.Join(home, "explicit.yaml")
	_ = os.WriteFile(out, []byte("old"), 0o600)
	res, err = Run(context.Background(), r, Options{Hosts: []string{srv.Addr}, Out: out, Name: "prod", Lookup: lookup})
	if err != nil || res.Path != out || res.Name != "prod" {
		t.Fatalf("explicit out: %v %+v", err, res)
	}
	if b, _ := os.ReadFile(out + ".bak"); string(b) != "old" {
		t.Errorf("backup: %q", b)
	}
	if kc, _ := clientcmd.LoadFromFile(out); kc.CurrentContext != "prod" {
		t.Errorf("explicit name: %+v", kc.Contexts)
	}
}

func TestRunNothingVerifies(t *testing.T) {
	api, _ := apiserver(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(api.URL, "https://"))
	// a CA that did not sign the server certificate: every endpoint fails TLS
	other := servingCert(t, []string{"ca"}, nil)
	caData := base64.StdEncoding.EncodeToString([]byte(other))
	cert := servingCert(t, []string{"kubernetes"}, []string{"127.0.0.1"})
	srv := node(t, nodeOutput(nodeKubeconfig(port, caData), cert))
	r := runner(t, srv)
	out := filepath.Join(t.TempDir(), "kc.yaml")
	res, err := Run(context.Background(), r, Options{Hosts: []string{srv.Addr}, Out: out, Lookup: func(string) []net.IP { return nil }})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Version != "" || res.Endpoint.Score != 10 || !strings.Contains(strings.Join(res.Notes, "\n"), "no endpoint verified; wrote the SSH host - ") {
		t.Errorf("fallback result: %+v", res)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("file not written: %v", err)
	}
	// the SSH host is in the certificate but the apiserver is down (etcd
	// quorum lost): the SSH host is still written so khealth starts offline
	cert = servingCert(t, []string{"kubernetes"}, []string{"127.0.0.1"})
	down := node(t, nodeOutput(nodeKubeconfig("1", base64.StdEncoding.EncodeToString([]byte(cert))), cert), srv)
	res, err = Run(context.Background(), r, Options{Hosts: []string{down.Addr}, Out: out, Fresh: true, Lookup: func(string) []net.IP { return nil }})
	if err != nil {
		t.Fatalf("run with apiserver down: %v", err)
	}
	if res.Endpoint.Host != "127.0.0.1" || res.Version != "" || !strings.Contains(strings.Join(res.Notes, "\n"), "khealth starts offline") {
		t.Errorf("offline result: %+v", res)
	}

	// no host at all
	if _, err := Run(context.Background(), r, Options{Hosts: []string{"127.0.0.1:1"}}); err == nil || !strings.HasPrefix(err.Error(), "no host yielded a kubeconfig: ssh 127.0.0.1:1") {
		t.Errorf("no host: %v", err)
	}
	// a kubeconfig that cannot be rewritten
	bad := node(t, nodeOutput("apiVersion: v1\nkind: Config\nclusters: []\n", cert), srv)
	if _, err := Run(context.Background(), r, Options{Hosts: []string{bad.Addr}, Out: out}); err == nil || !strings.Contains(err.Error(), "no clusters") {
		t.Errorf("bad kubeconfig: %v", err)
	}
}

func TestVerify(t *testing.T) {
	api, caData := apiserver(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(api.URL, "https://"))
	v, err := Verify(context.Background(), []byte(nodeKubeconfig(port, caData)))
	if err != nil || v != "v1.30.4+rke2r1" {
		t.Errorf("verify: %v %q", err, v)
	}
	if _, err := Verify(context.Background(), []byte("not: [a kubeconfig")); err == nil {
		t.Error("garbage must fail")
	}
	if _, err := Verify(context.Background(), []byte(nodeKubeconfig("1", caData))); err == nil {
		t.Error("closed port must fail")
	}
	wrongToken := strings.Replace(nodeKubeconfig(port, caData), "token: abc", "token: xyz", 1)
	if _, err := Verify(context.Background(), []byte(wrongToken)); err == nil {
		t.Error("401 must fail")
	}
}

func TestRewriteEdgeCases(t *testing.T) {
	if _, err := Rewrite([]byte("clusters: ["), "h", "n"); err == nil || !strings.Contains(err.Error(), "parse kubeconfig") {
		t.Errorf("garbage: %v", err)
	}
	if _, err := Rewrite([]byte("apiVersion: v1\nkind: Config\n"), "h", "n"); err == nil || !strings.Contains(err.Error(), "no clusters") {
		t.Errorf("no clusters: %v", err)
	}
	// no port in the original server means 6443; an empty name keeps "default"
	out, err := Rewrite([]byte(strings.Replace(rke2yaml, "https://127.0.0.1:6443", "https://127.0.0.1", 1)), "vip.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := clientcmd.Load(out)
	if c := cfg.Clusters["default"]; c == nil || c.Server != "https://vip.example.com:6443" || cfg.CurrentContext != "default" {
		t.Errorf("default port / name: %+v", cfg.Clusters)
	}
	// several clusters: every server is repointed, the clusters keep their
	// names, the single user and context are still renamed
	multi := strings.Replace(rke2yaml, "  name: default\ncontexts:", "  name: default\n- cluster:\n    server: https://10.0.0.2:6443\n  name: second\ncontexts:", 1)
	out, err = Rewrite([]byte(multi), "vip", "prod")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = clientcmd.Load(out)
	if len(cfg.Clusters) != 2 || cfg.Clusters["default"] == nil || cfg.Clusters["second"] == nil || cfg.Clusters["second"].Server != "https://vip:6443" || cfg.Clusters["default"].Server != "https://vip:6443" {
		t.Errorf("multi: %+v", cfg.Clusters)
	}
	if ctx := cfg.Contexts["prod"]; ctx == nil || ctx.Cluster != "default" || ctx.AuthInfo != "prod" || cfg.CurrentContext != "prod" || cfg.AuthInfos["prod"] == nil {
		t.Errorf("multi contexts: %+v users=%v", cfg.Contexts, cfg.AuthInfos)
	}
	if _, err := Rewrite([]byte(strings.Replace(rke2yaml, "https://127.0.0.1:6443", "http://[::1", 1)), "h", "n"); err == nil {
		t.Error("unparsable server URL must fail")
	}
}

func TestRankAndNames(t *testing.T) {
	src := &Source{Host: "cp-1.example.com:22", Hostname: "cp-1", CertDNS: []string{"kubernetes.default.svc", "cp-1.example.com", "vip.example.com", "ghost.example.com"}, CertIPs: []string{"10.43.0.1", "10.0.0.11", "10.0.0.100"}, NodeIPs: []string{"10.0.0.11"}}
	lookup := func(name string) []net.IP {
		switch name {
		case "cp-1.example.com":
			return []net.IP{net.ParseIP("10.0.0.11")}
		case "vip.example.com":
			return []net.IP{net.ParseIP("10.0.0.100")}
		}
		return nil
	}
	eps := Rank(src, lookup)
	got := map[string]Endpoint{}
	for _, e := range eps {
		got[e.Host] = e
	}
	if e := got["vip.example.com"]; e.Score != 100 || eps[0].Host != "vip.example.com" {
		t.Errorf("vip name: %+v first=%+v", e, eps[0])
	}
	if e := got["10.0.0.100"]; e.Score != 80 {
		t.Errorf("vip address: %+v", e)
	}
	if e := got["cp-1.example.com"]; e.Score != 60 || !strings.Contains(e.Reason, "SSH host") {
		t.Errorf("ssh host name in cert: %+v", e)
	}
	if e := got["10.0.0.11"]; e.Score != 40 {
		t.Errorf("node address: %+v", e)
	}
	if e := got["ghost.example.com"]; e.Score != 20 {
		t.Errorf("unresolvable name: %+v", e)
	}
	if _, ok := got["kubernetes.default.svc"]; ok || len(eps) != 5 {
		t.Errorf("in-cluster SAN or duplicate: %+v", eps)
	}
	// the SSH host given as an IP in the certificate
	src2 := &Source{Host: "10.0.0.11", CertIPs: []string{"10.0.0.11"}, NodeIPs: []string{"10.0.0.11"}}
	if eps := Rank(src2, lookup); len(eps) != 1 || eps[0].Score != 50 {
		t.Errorf("ssh ip in cert: %+v", eps)
	}
	// an SSH name that resolves to a SAN address but is not a SAN itself
	src3 := &Source{Host: "cp-1.example.com", CertIPs: []string{"10.0.0.11"}, NodeIPs: []string{"10.0.0.11"}}
	eps = Rank(src3, lookup)
	if len(eps) != 2 || eps[1].Host != "cp-1.example.com" || eps[1].Score != 10 || !strings.Contains(eps[1].Reason, "the name itself is not a SAN") {
		t.Errorf("ssh name not a SAN: %+v", eps)
	}
	// the default resolver is used when none is given (localhost resolves)
	src4 := &Source{Host: "localhost", CertDNS: []string{"localhost"}}
	if eps := Rank(src4, nil); len(eps) != 1 || eps[0].Host != "localhost" {
		t.Errorf("default lookup: %+v", eps)
	}
	if defaultLookup("localhost") == nil {
		t.Error("localhost should resolve")
	}

	// names
	if ClusterName("", Endpoint{Host: "10.0.0.1"}, &Source{Hostname: ""}) != "cluster" {
		t.Error("empty hostname falls back to cluster")
	}
	if ClusterName("", Endpoint{Host: "10.0.0.1"}, &Source{Hostname: "Master_3.corp"}) != "master-corp" {
		t.Errorf("hostname index stripped, domain kept: %q", ClusterName("", Endpoint{Host: "10.0.0.1"}, &Source{Hostname: "Master_3.corp"}))
	}
	// the whole DNS name: api.prod.corp and api.dev.corp are two clusters
	if ClusterName("", Endpoint{Host: "K8S-Prod.example.com."}, nil) != "k8s-prod-example-com" {
		t.Error("dns name lowercased and kept whole")
	}
	if ClusterName("", Endpoint{Host: "api.dev.corp"}, nil) == ClusterName("", Endpoint{Host: "api.prod.corp"}, nil) {
		t.Error("clusters under one domain share a name")
	}
	if ClusterName("", Endpoint{}, &Source{Hostname: "node7"}) != "node" {
		t.Error("empty endpoint uses the hostname")
	}
}

func TestDistHints(t *testing.T) {
	cases := []struct{ path, dist, san, reissue string }{
		{"/etc/rancher/rke2/rke2.yaml", "rke2", "/etc/rancher/rke2/config.yaml", "restart rke2-server"},
		{"/etc/rancher/k3s/k3s.yaml", "k3s", "/etc/rancher/k3s/config.yaml", "restart k3s"},
		{"/etc/kubernetes/admin.conf", "kubeadm", "kubeadm-config ConfigMap", "kubeadm certs renew apiserver"},
	}
	for _, c := range cases {
		s := &Source{Path: c.path}
		if s.Dist() != c.dist || !strings.Contains(s.sanHint("vip"), c.san) || !strings.Contains(s.sanHint("vip"), "vip") || !strings.Contains(s.reissueHint(), c.reissue) {
			t.Errorf("%s: %s %q %q", c.path, s.Dist(), s.sanHint("vip"), s.reissueHint())
		}
	}
}

func TestShortErr(t *testing.T) {
	cases := map[string]string{
		"Get https://x: x509: certificate is valid for 10.0.0.1, not 10.0.0.2": "TLS: x509: certificate is valid for 10.0.0.1, not 10.0.0.2",
		"dial tcp: lookup vip: no such host":                                   "does not resolve",
		"dial tcp 10.0.0.1:6443: i/o timeout":                                  "timeout",
		"context deadline exceeded":                                            "timeout",
		"dial tcp 127.0.0.1:1: connect: connection refused":                    "connection refused",
		"short": "short",
	}
	for in, want := range cases {
		if got := shortErr(errors.New(in)); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
	long := strings.Repeat("e", 150)
	if got := shortErr(errors.New(long)); got != strings.Repeat("e", 120)+"..." {
		t.Errorf("long: %q", got)
	}
}

func TestWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deep", "dir", "kc.yaml")
	if err := writeFile(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	bak, _ := os.ReadFile(path + ".bak")
	if string(b) != "two" || string(bak) != "one" {
		t.Errorf("file %q backup %q", b, bak)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}

// A file bootstrapped earlier is reused while it connects (by server host
// before SSH, by cluster CA after the fetch) and replaced when it is stale.
func TestRunReusesExisting(t *testing.T) {
	api, caData := apiserver(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(api.URL, "https://"))
	cert := servingCert(t, []string{"kubernetes"}, []string{"127.0.0.1", "10.43.0.1"})
	srv := node(t, nodeOutput(nodeKubeconfig(port, caData), cert))
	r := runner(t, srv)
	home := t.TempDir()
	t.Setenv("HOME", home)
	kube := filepath.Join(home, ".kube")
	_ = os.MkdirAll(kube, 0o700)
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }

	// 1. same server host as the bootstrap host and it connects: no SSH at all
	good := filepath.Join(kube, "khealth-lab.yaml")
	_ = os.WriteFile(good, []byte(strings.ReplaceAll(nodeKubeconfig(port, caData), "default", "lab")), 0o600)
	res, err := Run(context.Background(), nil, Options{Hosts: []string{"127.0.0.1"}, Log: logf})
	if err != nil || res.Path != good || res.Name != "lab" || res.Version != "v1.30.4+rke2r1" {
		t.Fatalf("reuse by host: %v %+v\n%s", err, res, strings.Join(logs, "\n"))
	}

	// 2. same cluster (CA) reached through another host name, still connects: reused after the fetch
	_, sshPort, _ := net.SplitHostPort(srv.Addr)
	logs = nil
	res, err = Run(context.Background(), r, Options{Hosts: []string{"localhost:" + sshPort}, Log: logf})
	if err != nil || res.Path != good || !strings.Contains(strings.Join(logs, "\n"), "same CA") {
		t.Fatalf("reuse by CA: %v %+v\n%s", err, res, strings.Join(logs, "\n"))
	}

	// 3. stale: the file points at a dead port; it is replaced in place with a .bak
	_ = os.WriteFile(good, []byte(strings.ReplaceAll(nodeKubeconfig("1", caData), "default", "lab")), 0o600)
	logs = nil
	res, err = Run(context.Background(), r, Options{Hosts: []string{srv.Addr}, Log: logf})
	if err != nil || res.Path != good {
		t.Fatalf("replace stale: %v %+v\n%s", err, res, strings.Join(logs, "\n"))
	}
	if kc, _ := clientcmd.LoadFromFile(good); kc == nil || kc.Clusters[kc.CurrentContext] == nil || kc.Clusters[kc.CurrentContext].Server != "https://127.0.0.1:"+port {
		t.Errorf("replaced file: %+v", kc)
	}
	if _, err := os.Stat(good + ".bak"); err != nil {
		t.Errorf("no backup of the stale file")
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "replaced the stale") {
		t.Errorf("notes: %v", res.Notes)
	}

	// 4. --bootstrap-fresh ignores it and writes the derived name
	res, err = Run(context.Background(), r, Options{Hosts: []string{srv.Addr}, Fresh: true})
	if err != nil || res.Path == good {
		t.Fatalf("fresh: %v %+v", err, res)
	}
}
