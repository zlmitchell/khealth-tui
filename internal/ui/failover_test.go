package ui

import (
	"encoding/base64"

	"encoding/pem"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
)

// The kubeconfig's server is unreachable; a peer the etcd probe found on
// disk serves the API with the same CA, so khealth switches to it.
func TestAPIFailover(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"gitVersion":"v1.35.8+rke2r1"}`)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	kc := filepath.Join(t.TempDir(), "kc.yaml")
	if err := os.WriteFile(kc, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    certificate-authority-data: "+ca+"\n    server: https://unreachable.invalid:"+port+"\ncontexts:\n- name: c\n  context: {cluster: c, user: u}\ncurrent-context: c\nusers:\n- name: u\n  user: {token: abc}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := k8s.NewWithOptions(kc, "", k8s.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	a := testApp()
	a.cfg.Kubeconfig = kc
	a.client = client
	a.snap = &k8s.Snapshot{Errors: []string{"nodes: Get \"https://unreachable.invalid:" + port + "/api/v1/nodes\": dial tcp: lookup unreachable.invalid: no such host"}}
	a.etcd = map[string]*etcd.Probe{"10.0.0.143": etcd.Parse("10.0.0.143", "===DIST\nrke2\n===HEALTH\n{\"health\":\"true\"}\n===PEERS\ndb: {\"id\":2,\"peerURLs\":[\"https://127.0.0.1:2380\"],\"name\":\"cp-2-abcdef01\"}\n===END\n")}
	if !k8s.Unreachable(a.snap.Errors) {
		t.Fatal("errors should count as unreachable")
	}
	// the probe that discovered the peers triggers the attempt right away
	probe := a.etcd["10.0.0.143"]
	delete(a.etcd, "10.0.0.143")
	a.gen = 1
	_, cmd := a.Update(etcdMsg{gen: 1, probe: probe})
	if cmd == nil || !a.apiTrying {
		t.Fatal("an etcd probe with peers should start the failover")
	}
	// run the batch until the failover message arrives
	var msg tea.Msg
	for _, m := range runCmds(cmd) {
		if _, ok := m.(apiFailoverMsg); ok {
			msg = m
		}
	}
	if msg == nil {
		t.Fatal("no failover message")
	}
	a.Update(msg)
	if a.apiOverride != "https://127.0.0.1:"+port || a.client.Host != "https://127.0.0.1:"+port {
		t.Fatalf("override %q host %q status %q", a.apiOverride, a.client.Host, a.status)
	}
	if !strings.Contains(a.status, "switched to https://127.0.0.1:"+port) {
		t.Errorf("status %q", a.status)
	}
	if v := a.renderHeader(); !strings.Contains(v, "failover") {
		t.Errorf("header should show the failover: %s", v)
	}
	// once the API answers, the tried hosts are forgotten; a second dead
	// peer is skipped after being tried
	a.apiTried = map[string]bool{"10.0.0.9": true}
	a.snap = &k8s.Snapshot{Errors: []string{"nodes: dial tcp 127.0.0.1:1: connect: connection refused"}}
	a.etcd["10.0.0.143"].Peers = []etcd.Peer{{Host: "10.0.0.9"}}
	if a.apiFailoverCmd() != nil {
		t.Error("an already tried host must not be tried again")
	}
	// an API that refuses a request (RBAC) is not "unreachable"
	if k8s.Unreachable([]string{`nodes: nodes is forbidden: User "x" cannot list resource "nodes"`}) {
		t.Error("forbidden is not unreachable")
	}
}

// runCmds runs a tea.Cmd (possibly a Batch) and returns every message.
func runCmds(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	m := cmd()
	if b, ok := m.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range b {
			out = append(out, runCmds(c)...)
		}
		return out
	}
	return []tea.Msg{m}
}
