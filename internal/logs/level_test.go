package logs

import "testing"

// A catch-all defers to the line's own level; specific rules do not.
func TestOwnLevelBeatsCatchAll(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{`2026-09-26 19:35:19.123 [INFO][9] resources.go 350: Error getting resource Key=IPPool(default-ipv4-ippool) error=resource does not exist`, ""},
		{`2026-09-26 19:35:19.123 [WARNING][1] cni-installer/install.go 245: Failed to remove 10-calico.conflist error=remove /host/etc/cni/net.d/10-calico.conflist: no such file`, "generic-warn"},
		{`I0926 19:35:19.123456       1 controller.go:42] "sync failed" error="context canceled"`, ""},
		{`time="2026-09-26T19:35:19Z" level=error msg="apply failed" error="[INFO] nested"`, "generic-error"},
		{`E0926 19:35:19.123456       1 controller.go:42] "sync failed" error="context canceled"`, "generic-error"},
	} {
		got := ""
		if p := Lookup(c.line); p != nil {
			got = p.Name
		}
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
}

// token-mismatch is the supervisor refusing the join token, not any
// "Unauthorized" in a log.
func TestTokenMismatchNeedsTheSupervisor(t *testing.T) {
	for _, l := range []string{
		`2026-09-26 19:35:19.123 [INFO][1] startup/startup.go 432: Unauthorized to create tier default`,
		`E0926 19:35:19.123 1 reflector.go:147] failed to list *v1.Pod: Unauthorized`,
	} {
		if p := Lookup(l); p != nil && p.Name == "token-mismatch" {
			t.Errorf("%q matched token-mismatch", l)
		}
	}
	for _, l := range []string{
		`time="2026-09-26T19:35:19Z" level=info msg="Waiting to retrieve agent configuration; server is not ready: https://10.0.0.1:9345/v1-rke2/serving-kubelet.crt: 401 Unauthorized"`,
		`time="2026-09-26T19:35:19Z" level=error msg="Failed to retrieve agent config: https://10.0.0.1:9345/v1-rke2/serving-kubelet.crt: 401 Unauthorized"`,
		`time="2026-09-26T19:35:19Z" level=fatal msg="failed to get CA certs: https://10.0.0.1:9345/cacerts: 401 Unauthorized"`,
		`time="2026-09-26T19:35:19Z" level=fatal msg="token does not match"`,
	} {
		if p := Lookup(l); p == nil || p.Name != "token-mismatch" {
			t.Errorf("%q: got %v, want token-mismatch", l, p)
		}
	}
}

// The eviction manager's start-up filesystem check is not pressure; a real
// reclaim still is.
func TestEvictionFSCheckIsInfo(t *testing.T) {
	l := `E0928 02:17:57.254973     248 eviction_manager.go:267] "eviction manager: failed to check if we have separate container filesystem. Ignoring."`
	if p := Lookup(l); p == nil || p.Name != "eviction-fs-check" || p.Class != ClassInfo {
		t.Errorf("fs check: %+v", p)
	}
	l = `I0928 02:30:00.000000     248 eviction_manager.go:366] "Eviction manager: attempting to reclaim" resourceName="ephemeral-storage"`
	if p := Lookup(l); p == nil || p.Name != "eviction" {
		t.Errorf("reclaim: %+v", p)
	}
}

// Lines from a healthy Rancher node that named the wrong cause, and the
// lines those rules exist for.
func TestRealClusterMisattributions(t *testing.T) {
	for _, c := range []struct{ line, not, want string }{
		// kubelet housekeeping is not etcd
		{`E0927 21:59:52.167318    2130 kubelet.go:2618] "Housekeeping took longer than expected" err="housekeeping took too long" expected="1s" actual="1.2s"`, "etcd-slow-fsync", ""},
		{`{"level":"warn","ts":"2026-09-28T03:26:33.468567Z","caller":"txn/util.go:93","msg":"apply request took too long","took":"381.859958ms","expected-duration":"100ms"}`, "", "etcd-slow-fsync"},
		// flannel dumping the node's annotations names the flag, it is not the error
		{`I0920 16:11:27.983499       1 kube.go:737] List of node(rancher) annotations: map[string]string{"rke2.io/node-args":"[\"server\",\"--protect-kernel-defaults\",\"true\"]"}`, "kernel-defaults", ""},
		{`E0927 10:00:00.000000    2130 run.go:72] "command failed" err="failed to run Kubelet: invalid kernel flag: vm/overcommit_memory, expected value: 1, actual value: 0"`, "", "kernel-defaults"},
		// an app's own port, not a Kubernetes one
		{`timestamp=2026-09-28T02:03:18Z service=metrics_server level=ERROR message="Failed to start metrics server: [Errno 98] error while attempting to bind on address ('0.0.0.0', 9090): address already in use"`, "port-in-use", ""},
		{`E0927 10:00:00.000000 1 run.go:72] "command failed" err="failed to listen on 0.0.0.0:6443: listen tcp 0.0.0.0:6443: bind: address already in use"`, "", "port-in-use"},
		// a client's revoked token, not the join token
		{`E0928 03:03:43.261346       1 authentication.go:75] "Unable to authenticate the request" err="[invalid bearer token, Token has been invalidated]"`, "token-mismatch", "apiserver-auth-reject"},
	} {
		got := ""
		if p := Lookup(c.line); p != nil {
			got = p.Name
		}
		if c.not != "" && got == c.not {
			t.Errorf("%q matched %s", c.line, got)
		}
		if c.want != "" && got != c.want {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
}
