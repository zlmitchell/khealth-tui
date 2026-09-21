package sshrun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/sshrun/sshtest"
)

// hostHandler models a node: uid, installed tools, which of them work
// without a password and which accept pw. The script itself is echoed back
// so the tests can see exactly what reached the shell.
type hostHandler struct {
	uid       string
	tools     []string
	nopasswd  map[string]bool
	password  string
	scriptErr string // stderr for the script run itself (exit 1 when set)
}

func (h hostHandler) handle(cmd, stdin string) (string, string, int) {
	switch {
	case cmd == "/bin/sh -s" && strings.HasPrefix(stdin, "id -u;"):
		out := h.uid + "\n"
		for _, t := range h.tools {
			out += "tool=" + t + "\n"
		}
		return out, "", 0
	case strings.HasSuffix(cmd, " -n id -u"):
		tool := strings.Fields(cmd)[0]
		if h.nopasswd[tool] {
			return "0\n", "", 0
		}
		return "", tool + ": a password is required\n", 1
	case strings.HasSuffix(cmd, " -S -p '' id -u"):
		tool := strings.Fields(cmd)[0]
		if h.password != "" && stdin == h.password+"\n" {
			return "0\n", "", 0
		}
		return "", "Sorry, try again.\n" + tool + ": a password is required\n", 1
	case strings.HasSuffix(cmd, "/bin/sh -s"):
		if strings.Contains(cmd, " -S ") {
			pw, rest, _ := strings.Cut(stdin, "\n")
			if pw != h.password {
				return "", "sudo: a password is required\n", 1
			}
			stdin = rest
		}
		if h.scriptErr != "" {
			return "", h.scriptErr, 1
		}
		return "ran[" + cmd + "]:" + stdin, "", 0
	}
	return "", "sshtest: unexpected command " + cmd + "\n", 127
}

func testCfg(srv *sshtest.Server) config.SSH {
	return config.SSH{Enabled: true, User: "ops", Key: srv.KeyPath, Port: 22, Sudo: true, Become: "auto", Timeout: 5 * time.Second, Concurrency: 2, StrictHostKey: false, Nice: true}
}

func newRunner(t *testing.T, cfg config.SSH) *Runner {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestNewAuthSetup(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir()) // no ~/.ssh keys
	if _, err := New(config.SSH{}); err == nil || !strings.Contains(err.Error(), "user is not set") {
		t.Errorf("no user: %v", err)
	}
	if _, err := New(config.SSH{User: "ops"}); err == nil || !strings.Contains(err.Error(), "no SSH auth method") || !strings.Contains(err.Error(), "SSH_AUTH_SOCK not set") {
		t.Errorf("no auth: %v", err)
	}
	if _, err := New(config.SSH{User: "ops", Key: "/nonexistent/key"}); err == nil || !strings.Contains(err.Error(), "key: ") {
		t.Errorf("missing key: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad")
	_ = os.WriteFile(bad, []byte("not a key"), 0o600)
	if _, err := New(config.SSH{User: "ops", Key: bad}); err == nil || !strings.Contains(err.Error(), "key "+bad+": ") {
		t.Errorf("unparsable key: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(t.TempDir(), "enc")
	_ = os.WriteFile(enc, pem.EncodeToMemory(block), 0o600)
	if _, err := New(config.SSH{User: "ops", Key: enc}); err == nil || !strings.Contains(err.Error(), "is encrypted") {
		t.Errorf("encrypted key without passphrase: %v", err)
	}
	t.Setenv("KHT_SSH_PASSPHRASE", "wrong")
	if _, err := New(config.SSH{User: "ops", Key: enc}); err == nil || !strings.Contains(err.Error(), "key "+enc+": ") {
		t.Errorf("wrong passphrase: %v", err)
	}
	t.Setenv("KHT_SSH_PASSPHRASE", "secret")
	r, err := New(config.SSH{User: "ops", Key: enc, Concurrency: 1})
	if err != nil || strings.Join(r.Notes(), ";") != "agent: SSH_AUTH_SOCK not set;key "+enc {
		t.Errorf("decrypted key: %v %v", err, r.Notes())
	}
	// password alone is enough, and it is listed as a fallback
	r, err = New(config.SSH{User: "ops", Password: "pw", Concurrency: 1})
	if err != nil || len(r.auth) != 2 || !strings.Contains(strings.Join(r.Notes(), ";"), "password fallback") {
		t.Errorf("password auth: %v %v", err, r.Notes())
	}
	// strict host keys need a readable known_hosts
	_, err = New(config.SSH{User: "ops", Password: "pw", StrictHostKey: true, KnownHosts: "/nonexistent/known_hosts", Concurrency: 1})
	if err == nil || !strings.Contains(err.Error(), "known_hosts /nonexistent/known_hosts") || !strings.Contains(err.Error(), "--insecure-host-key") {
		t.Errorf("missing known_hosts: %v", err)
	}
	// default keys under ~/.ssh are picked up
	srv := sshtest.New(t, nil)
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	b, _ := os.ReadFile(srv.KeyPath)
	_ = os.WriteFile(filepath.Join(sshDir, "id_ed25519"), b, 0o600)
	r, err = New(config.SSH{User: "ops", Concurrency: 1})
	if err != nil || !strings.Contains(strings.Join(r.Notes(), ";"), "key "+filepath.Join(sshDir, "id_ed25519")) {
		t.Errorf("default key: %v %v", err, r.Notes())
	}
}

func TestRunAsRoot(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	r := newRunner(t, testCfg(srv))
	ctx := context.Background()
	res := r.Run(ctx, srv.Addr, "echo hi\n")
	if res.Err != nil {
		t.Fatalf("run: %v stderr=%q", res.Err, res.Stderr)
	}
	if res.Stdout != "ran[/bin/sh -s]:"+Prologue+"echo hi\n" {
		t.Errorf("stdout %q", res.Stdout)
	}
	if res.ScriptSize != len(Prologue)+len("echo hi\n") || res.Finished.Before(res.Started) {
		t.Errorf("result meta: %+v", res)
	}
	if r.Become(srv.Addr) != "root" {
		t.Errorf("become %q", r.Become(srv.Addr))
	}
	// the escalation probe ran once; the next run reuses the connection and the answer
	if srv.Execs() != 2 || srv.Dials() != 1 {
		t.Errorf("execs=%d dials=%d", srv.Execs(), srv.Dials())
	}
	r.Run(ctx, srv.Addr, "again\n")
	if srv.Execs() != 3 || srv.Dials() != 1 {
		t.Errorf("after second run: execs=%d dials=%d", srv.Execs(), srv.Dials())
	}
	// Close drops the connection; the next run dials again
	r.Close()
	if res := r.Run(ctx, srv.Addr, "x\n"); res.Err != nil || srv.Dials() != 2 {
		t.Errorf("after close: %v dials=%d", res.Err, srv.Dials())
	}
	// host without a port uses cfg.Port
	cfg := testCfg(srv)
	cfg.Port = srv.Port()
	cfg.Nice = true
	r2 := newRunner(t, cfg)
	host, _, _ := net.SplitHostPort(srv.Addr)
	if res := r2.Run(ctx, host, "y\n"); res.Err != nil || !strings.HasPrefix(res.Stdout, "ran[/bin/sh -s]:"+Prologue) {
		t.Errorf("port from config: %v %q", res.Err, res.Stdout)
	}
	if r2.Become(host) != "root" || r2.Become("nobody") != "" {
		t.Errorf("become by host: %q %q", r2.Become(host), r2.Become("nobody"))
	}
}

func TestRunWithoutNice(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	cfg := testCfg(srv)
	cfg.Nice = false
	r := newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "plain\n"); res.Err != nil || res.Stdout != "ran[/bin/sh -s]:plain\n" || res.ScriptSize != 6 {
		t.Errorf("%v %q %d", res.Err, res.Stdout, res.ScriptSize)
	}
}

func TestRunSudoNopasswd(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "1000", tools: []string{"dzdo", "sudo"}, nopasswd: map[string]bool{"sudo": true}}.handle)
	r := newRunner(t, testCfg(srv))
	res := r.Run(context.Background(), srv.Addr, "s\n")
	if res.Err != nil || !strings.HasPrefix(res.Stdout, "ran[sudo -n /bin/sh -s]:") {
		t.Errorf("%v %q", res.Err, res.Stdout)
	}
	if r.Become(srv.Addr) != "sudo (NOPASSWD)" {
		t.Errorf("become %q", r.Become(srv.Addr))
	}
}

func TestRunSudoPassword(t *testing.T) {
	h := hostHandler{uid: "1000", tools: []string{"sudo"}, password: "pw"}
	srv := sshtest.New(t, h.handle)
	cfg := testCfg(srv)
	cfg.Nice = false
	cfg.Password = "pw"
	r := newRunner(t, cfg)
	res := r.Run(context.Background(), srv.Addr, "s\n")
	if res.Err != nil || res.Stdout != "ran[sudo -S -p '' /bin/sh -s]:s\n" {
		t.Errorf("%v %q %q", res.Err, res.Stdout, res.Stderr)
	}
	if r.Become(srv.Addr) != "sudo (password)" {
		t.Errorf("become %q", r.Become(srv.Addr))
	}
	// a dedicated escalation password beats the SSH password
	cfg.Password, cfg.BecomePassword = "ssh-only", "pw"
	r2 := newRunner(t, cfg)
	if res := r2.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("become_password: %v", res.Err)
	}
	// the wrong password is reported as rejected
	cfg.Password, cfg.BecomePassword = "nope", ""
	r3 := newRunner(t, cfg)
	if res := r3.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "sudo: password rejected") || !strings.Contains(res.Err.Error(), "uid 1000") {
		t.Errorf("wrong password: %v", res.Err)
	}
	// no password at all names the ways to provide one
	cfg.Password = ""
	r4 := newRunner(t, cfg)
	if res := r4.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "--ask-pass") {
		t.Errorf("no password: %v", res.Err)
	}
}

func TestBecomeFailures(t *testing.T) {
	cases := []struct {
		name string
		h    hostHandler
		cfg  func(*config.SSH)
		want string
	}{
		{"no tools", hostHandler{uid: "1000"}, nil, "none of sudo, dzdo, doas is installed"},
		{"explicit tool missing", hostHandler{uid: "1000", tools: []string{"sudo"}}, func(c *config.SSH) { c.Become = "dzdo" }, "dzdo is not installed on this host (found: sudo)"},
		{"doas needs password", hostHandler{uid: "1000", tools: []string{"doas"}}, func(c *config.SSH) { c.Password = "pw" }, "doas cannot read one from stdin"},
		{"all refused", hostHandler{uid: "1000", tools: []string{"sudo", "dzdo"}}, func(c *config.SSH) { c.Password = "pw" }, "sudo: password rejected; dzdo: password rejected"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := sshtest.New(t, c.h.handle)
			cfg := testCfg(srv)
			if c.cfg != nil {
				c.cfg(&cfg)
			}
			r := newRunner(t, cfg)
			res := r.Run(context.Background(), srv.Addr, "s\n")
			if res.Err == nil || !strings.Contains(res.Err.Error(), c.want) {
				t.Errorf("got %v, want %q", res.Err, c.want)
			}
			if r.Become(srv.Addr) != "" {
				t.Errorf("failed probe cached: %q", r.Become(srv.Addr))
			}
		})
	}
	// become: none runs the script as the login user without probing
	srv := sshtest.New(t, hostHandler{uid: "1000"}.handle)
	cfg := testCfg(srv)
	cfg.Become = "none"
	r := newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil || !strings.HasPrefix(res.Stdout, "ran[/bin/sh -s]:") || srv.Execs() != 1 || r.Become(srv.Addr) != "root" {
		t.Errorf("become none: %v %q execs=%d", res.Err, res.Stdout, srv.Execs())
	}
	// an explicit tool that works
	srv2 := sshtest.New(t, hostHandler{uid: "1000", tools: []string{"sudo", "doas"}, nopasswd: map[string]bool{"doas": true, "sudo": true}}.handle)
	cfg = testCfg(srv2)
	cfg.Become = "doas"
	r = newRunner(t, cfg)
	if res := r.Run(context.Background(), srv2.Addr, "s\n"); res.Err != nil || !strings.HasPrefix(res.Stdout, "ran[doas -n /bin/sh -s]:") {
		t.Errorf("explicit doas: %v %q", res.Err, res.Stdout)
	}
}

func TestRunReprobesWhenEscalationStopsWorking(t *testing.T) {
	h := &hostHandler{uid: "1000", tools: []string{"sudo"}, nopasswd: map[string]bool{"sudo": true}}
	srv := sshtest.New(t, func(cmd, stdin string) (string, string, int) { return h.handle(cmd, stdin) })
	r := newRunner(t, testCfg(srv))
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Fatal(res.Err)
	}
	// sudo now asks for a password: the run fails and the method is forgotten
	h.scriptErr = "sudo: a password is required\n"
	res := r.Run(context.Background(), srv.Addr, "s\n")
	if res.Err == nil || !strings.Contains(res.Err.Error(), "sudo (NOPASSWD): sudo: a password is required (escalation will be re-probed)") {
		t.Errorf("err %v", res.Err)
	}
	if r.Become(srv.Addr) != "" {
		t.Errorf("method still cached: %q", r.Become(srv.Addr))
	}
	// an unrelated script failure keeps the method and returns the exit error
	h.scriptErr = "sh: line 3: syntax error\n"
	h.nopasswd["sudo"] = true
	res = r.Run(context.Background(), srv.Addr, "s\n")
	var exit *ssh.ExitError
	if !errors.As(res.Err, &exit) || exit.ExitStatus() != 1 || strings.Contains(res.Err.Error(), "re-probed") || res.Stderr != h.scriptErr {
		t.Errorf("script failure: %v stderr=%q", res.Err, res.Stderr)
	}
	if r.Become(srv.Addr) != "sudo (NOPASSWD)" {
		t.Errorf("method dropped on a script error: %q", r.Become(srv.Addr))
	}
}

func TestRunReconnectsAfterDrop(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	r := newRunner(t, testCfg(srv))
	if res := r.Run(context.Background(), srv.Addr, "a\n"); res.Err != nil {
		t.Fatal(res.Err)
	}
	// sshd restarts between two refresh cycles: the cached client notices
	// the EOF while idle, so the next session open fails with a connection
	// error and the runner reconnects
	r.mu.Lock()
	stale := r.clients[srv.Addr]
	r.mu.Unlock()
	srv.DropConnections()
	_ = stale.Wait()
	res := r.Run(context.Background(), srv.Addr, "b\n")
	if res.Err != nil || !strings.HasSuffix(res.Stdout, "b\n") {
		t.Errorf("after drop: %v %q", res.Err, res.Stdout)
	}
	if srv.Dials() != 2 {
		t.Errorf("dials %d", srv.Dials())
	}
	// the escalation method is re-probed on the new connection
	if srv.Execs() != 4 {
		t.Errorf("execs %d (probe+run, probe+run)", srv.Execs())
	}
	// a server that is gone is an error, not a hang
	srv.Close()
	if res := r.Run(context.Background(), srv.Addr, "c\n"); res.Err == nil {
		t.Error("closed server must fail")
	}
	if !isConnErr(errors.New("read: connection reset by peer")) || isConnErr(errors.New("exit status 1")) {
		t.Error("isConnErr")
	}
}

func TestRunContext(t *testing.T) {
	srv := sshtest.New(t, func(cmd, stdin string) (string, string, int) {
		if strings.HasPrefix(stdin, "id -u;") {
			return "0\n", "", 0
		}
		time.Sleep(2 * time.Second)
		return "late", "", 0
	})
	cfg := testCfg(srv)
	cfg.Concurrency = 1
	r := newRunner(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := r.Run(ctx, srv.Addr, "slow\n")
	if !errors.Is(res.Err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Errorf("cancel: %v after %s", res.Err, time.Since(start))
	}
	// the semaphore honors a canceled context too
	r.sem <- struct{}{}
	done, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if res := r.Run(done, srv.Addr, "x\n"); !errors.Is(res.Err, context.Canceled) {
		t.Errorf("sem wait: %v", res.Err)
	}
	<-r.sem
}

func TestKnownHosts(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(kh, []byte("# empty\n"), 0o600)
	cfg := testCfg(srv)
	cfg.StrictHostKey, cfg.KnownHosts = true, kh
	r := newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "not in known_hosts") {
		t.Errorf("unknown host: %v", res.Err)
	}
	// a different key for the host is a hard mismatch, not "not in known_hosts"
	other := sshtest.New(t, nil)
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, other.HostKey)+"\n"), 0o600)
	r = newRunner(t, cfg)
	host, _, _ := net.SplitHostPort(srv.Addr)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "changed since known_hosts recorded it: ssh-keygen -R "+host) {
		t.Errorf("mismatch: %v", res.Err)
	}
	_ = os.WriteFile(kh, []byte(srv.KnownHostsLine()+"\n"), 0o600)
	r = newRunner(t, cfg)
	res := r.Run(context.Background(), srv.Addr, "s\n")
	if res.Err != nil {
		t.Errorf("known host: %v", res.Err)
	}
	// the fingerprint of the key the server presented rides on the result
	if want := ssh.FingerprintSHA256(srv.HostKey); res.HostKey != want {
		t.Errorf("HostKey = %q, want %q", res.HostKey, want)
	}
}

// A host recorded in known_hosts with one key type (what a first ssh login
// stores) must connect to a server that also has other key types: the
// client offers only the recorded types instead of its own preference.
func TestKnownHostsSingleKeyType(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	srv.AddRSAHostKey(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	cfg := testCfg(srv)
	cfg.StrictHostKey, cfg.KnownHosts = true, kh

	// only the ed25519 key is known
	_ = os.WriteFile(kh, []byte(srv.KnownHostsLine()+"\n"), 0o600)
	r := newRunner(t, cfg)
	if got := r.hostKeyAlgorithms(srv.Addr); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("algorithms for ed25519-only host: %v", got)
	}
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("ed25519-only known host: %v", res.Err)
	}

	// only the RSA key is known: ssh-rsa entries are used with the SHA-2 signatures
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, srv.RSAKey)+"\n"), 0o600)
	r = newRunner(t, cfg)
	if got := strings.Join(r.hostKeyAlgorithms(srv.Addr), ","); got != "rsa-sha2-512,rsa-sha2-256,ssh-rsa" {
		t.Errorf("algorithms for rsa-only host: %v", got)
	}
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("rsa-only known host: %v", res.Err)
	}

	// unknown host: no restriction, and still refused
	_ = os.WriteFile(kh, []byte("# empty\n"), 0o600)
	r = newRunner(t, cfg)
	if got := r.hostKeyAlgorithms(srv.Addr); got != nil {
		t.Errorf("algorithms for unknown host: %v", got)
	}
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "not in known_hosts") {
		t.Errorf("unknown host: %v", res.Err)
	}
	// without strict checking nothing is restricted
	cfg.StrictHostKey = false
	if got := newRunner(t, cfg).hostKeyAlgorithms(srv.Addr); got != nil {
		t.Errorf("algorithms without strict checking: %v", got)
	}
}

// The TUI dials nodes by InternalIP while the operator's ssh recorded the
// name: a key known_hosts holds under any other name is accepted for a new
// address, and the key types on file are offered so the server presents it.
func TestKnownHostsByOtherName(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	srv.AddRSAHostKey(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	cfg := testCfg(srv)
	cfg.StrictHostKey, cfg.KnownHosts = true, kh

	// the server's ed25519 key under a name that is not the address dialed
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{"cp-1.corp"}, srv.HostKey)+"\n"), 0o600)
	r := newRunner(t, cfg)
	if got := r.hostKeyAlgorithms(srv.Addr); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("algorithms for an unrecorded address: %v (want the file's types)", got)
	}
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("key known under another name: %v", res.Err)
	}

	// a revoked key is not accepted, whatever name it is under
	_ = os.WriteFile(kh, []byte("@revoked "+knownhosts.Line([]string{"cp-1.corp"}, srv.HostKey)+"\n"), 0o600)
	r = newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil {
		t.Error("revoked key accepted")
	}

	// another machine's key on file does not vouch for this one
	other := sshtest.New(t, nil)
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{"cp-2.corp"}, other.HostKey)+"\n"), 0o600)
	r = newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "not in known_hosts") {
		t.Errorf("unrelated key on file: %v", res.Err)
	}

	// a VIP: the address is recorded with server A's key and answers with
	// server B's, which is on file under B's own name - not a changed key
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, other.HostKey)+"\n"+knownhosts.Line([]string{"cp-2.corp"}, srv.HostKey)+"\n"), 0o600)
	r = newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("VIP moved to a known server: %v", res.Err)
	}
	// a key nobody has seen is still a mismatch, and the message says what a VIP needs
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, other.HostKey)+"\n"), 0o600)
	r = newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "changed since known_hosts") || !strings.Contains(res.Err.Error(), "VIP") {
		t.Errorf("unknown key at a recorded address: %v", res.Err)
	}
}

// --accept-new-host-keys records an unknown address's key on first contact
// (the file then works for plain strict runs and for ssh) but never
// accepts a changed one.
func TestAcceptNewHostKeys(t *testing.T) {
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(kh, []byte("# empty"), 0o600) // no final newline: the appended line must still be its own line
	cfg := testCfg(srv)
	cfg.StrictHostKey, cfg.KnownHosts, cfg.AcceptNewHostKeys = true, kh, true
	r := newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Fatalf("first contact: %v", res.Err)
	}
	b, _ := os.ReadFile(kh)
	if !strings.Contains(string(b), "\n"+srv.KnownHostsLine()+"\n") {
		t.Errorf("known_hosts after first contact:\n%s", b)
	}
	// the same run dials it again after a reconnect without touching the file
	r.Close()
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("second dial: %v", res.Err)
	}
	if b2, _ := os.ReadFile(kh); string(b2) != string(b) {
		t.Errorf("recorded twice:\n%s", b2)
	}
	// plain strict checking now knows the host
	cfg.AcceptNewHostKeys = false
	if res := newRunner(t, cfg).Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("strict after recording: %v", res.Err)
	}
	// a different key for a recorded address is refused, accept-new or not
	other := sshtest.New(t, nil)
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{srv.Addr}, other.HostKey)+"\n"), 0o600)
	cfg.AcceptNewHostKeys = true
	if res := newRunner(t, cfg).Run(context.Background(), srv.Addr, "s\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "changed since known_hosts") {
		t.Errorf("changed key with accept-new: %v", res.Err)
	}
}

func TestPasswordAuth(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no default keys
	srv := sshtest.New(t, hostHandler{uid: "0"}.handle)
	srv.User, srv.Password = "ops", "hunter2"
	cfg := testCfg(srv)
	cfg.Key, cfg.Password = "", "hunter2"
	r := newRunner(t, cfg)
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("password: %v", res.Err)
	}
	srv.Interactive = true
	r.Close()
	if res := r.Run(context.Background(), srv.Addr, "s\n"); res.Err != nil {
		t.Errorf("keyboard-interactive: %v", res.Err)
	}
	cfg.Password = "wrong"
	r2 := newRunner(t, cfg)
	if res := r2.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil {
		t.Error("wrong password must fail")
	}
	cfg.Password, cfg.User = "hunter2", "someone-else"
	r3 := newRunner(t, cfg)
	if res := r3.Run(context.Background(), srv.Addr, "s\n"); res.Err == nil {
		t.Error("wrong user must fail")
	}
}

func TestBastion(t *testing.T) {
	bastion := sshtest.New(t, nil)
	bastion.User = "jump"
	target := sshtest.New(t, hostHandler{uid: "0"}.handle)
	bastion.AcceptKey(target.ClientPub)
	cfg := testCfg(target)
	cfg.Bastion = "jump@" + bastion.Addr
	r := newRunner(t, cfg)
	res := r.Run(context.Background(), target.Addr, "via\n")
	if res.Err != nil || !strings.HasSuffix(res.Stdout, "via\n") {
		t.Fatalf("through bastion: %v %q", res.Err, res.Stdout)
	}
	if bastion.Dials() != 1 || target.Dials() != 1 {
		t.Errorf("dials bastion=%d target=%d", bastion.Dials(), target.Dials())
	}
	// the bastion connection is reused for a second host
	target2 := sshtest.New(t, hostHandler{uid: "0"}.handle)
	target2.AcceptKey(target.ClientPub)
	if res := r.Run(context.Background(), target2.Addr, "two\n"); res.Err != nil || bastion.Dials() != 1 {
		t.Errorf("second host: %v bastion dials=%d", res.Err, bastion.Dials())
	}
	r.Close()
	if res := r.Run(context.Background(), target.Addr, "again\n"); res.Err != nil || bastion.Dials() != 2 {
		t.Errorf("after close: %v bastion dials=%d", res.Err, bastion.Dials())
	}
	// the bastion refusing the user, or the target unreachable through it
	cfg.Bastion = "wrong@" + bastion.Addr
	r2 := newRunner(t, cfg)
	if res := r2.Run(context.Background(), target.Addr, "x\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "bastion:") {
		t.Errorf("bastion auth: %v", res.Err)
	}
	cfg.Bastion = "jump@" + bastion.Addr
	r3 := newRunner(t, cfg)
	if res := r3.Run(context.Background(), "127.0.0.1:1", "x\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "via bastion:") {
		t.Errorf("target via bastion: %v", res.Err)
	}
	// a bastion without a user falls back to the SSH user; unreachable here
	cfg.Bastion = "127.0.0.1:1"
	r4 := newRunner(t, cfg)
	if res := r4.Run(context.Background(), target.Addr, "x\n"); res.Err == nil || !strings.Contains(res.Err.Error(), "bastion:") {
		t.Errorf("bastion down: %v", res.Err)
	}
}
