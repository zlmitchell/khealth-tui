// Package sshrun executes shell scripts on cluster nodes over SSH.
package sshrun

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"k8s-health-tui/internal/config"
)

// Runner holds SSH connections to nodes and runs scripts on them.
type Runner struct {
	cfg     config.SSH
	auth    []ssh.AuthMethod
	hostKey ssh.HostKeyCallback
	// knownKey is a throwaway key used to ask known_hosts which key types
	// it holds for a host (see hostKeyAlgorithms); nil without strict checking
	knownKey ssh.PublicKey
	notes    []string

	mu      sync.Mutex
	clients map[string]*ssh.Client
	bastion *ssh.Client
	sem     chan struct{}
	become  map[string]becomeMethod // per host: how to run as root (see become.go)

	// hostKeys is written from inside the handshake, which bastionClient
	// runs with mu held, so it has its own lock.
	hkMu     sync.Mutex
	hostKeys map[string]string // per addr: SHA256 fingerprint of the host key seen (see HostKey)
}

// Result is the outcome of running a script on a node.
type Result struct {
	Stdout     string
	Stderr     string
	Err        error
	Started    time.Time
	Finished   time.Time
	ScriptSize int    // bytes sent on stdin (prologue included)
	HostKey    string // SHA256 fingerprint of the node's SSH host key ("" when the dial failed)
}

// Prologue is prepended to every script when ssh.nice is on: the probe and
// everything it spawns run at the lowest CPU priority and in the lowest
// best-effort I/O class, so on a node that is already struggling the
// collection yields to the workloads and to etcd/kubelet instead of
// competing with them. Idle I/O class (-c 3) is deliberately not used: on a
// saturated disk it can starve the probe past its timeout, which loses the
// data exactly when it matters.
const Prologue = "command -v renice >/dev/null 2>&1 && renice -n 19 -p $$ >/dev/null 2>&1\n" +
	"command -v ionice >/dev/null 2>&1 && ionice -c 2 -n 7 -p $$ >/dev/null 2>&1\n"

// New prepares authentication and host key verification. It does not connect.
func New(cfg config.SSH) (*Runner, error) {
	r := &Runner{cfg: cfg, clients: map[string]*ssh.Client{}, hostKeys: map[string]string{}, become: map[string]becomeMethod{}, sem: make(chan struct{}, cfg.Concurrency)}
	if cfg.User == "" {
		return nil, errors.New("ssh user is not set (ssh.user / --ssh-user)")
	}
	auth, notes := buildAuth(cfg)
	if len(auth) == 0 {
		return nil, fmt.Errorf("no SSH auth method available (%s)", strings.Join(notes, "; "))
	}
	r.auth, r.notes = auth, notes

	if !cfg.StrictHostKey {
		r.hostKey = ssh.InsecureIgnoreHostKey() //nolint:gosec // explicit user opt-in
	} else {
		path := cfg.KnownHosts
		if path == "" {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".ssh", "known_hosts")
		}
		cb, err := knownhosts.New(path)
		if err != nil {
			return nil, fmt.Errorf("known_hosts %s: %w (set ssh.strict_host_key: false or --insecure-host-key to skip)", path, err)
		}
		r.hostKey = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := cb(hostname, remote, key)
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) {
				h := hostname
				if hp, _, err := net.SplitHostPort(hostname); err == nil {
					h = hp
				}
				if len(ke.Want) == 0 {
					return fmt.Errorf("host key for %s not in known_hosts (ssh to it once, or --insecure-host-key)", h)
				}
				// wrapped, not replaced: hostKeyAlgorithms reads ke.Want through it
				return fmt.Errorf("host key for %s changed since known_hosts recorded it: ssh-keygen -R %s, then ssh to it once (or --insecure-host-key): %w", h, h, err)
			}
			return err
		}
		if _, priv, err := ed25519.GenerateKey(rand.Reader); err == nil {
			r.knownKey, _ = ssh.NewPublicKey(priv.Public())
		}
	}
	return r, nil
}

// hostKeyAlgorithms returns the host key algorithms to offer for addr: the
// types known_hosts already holds for it. Without this the client negotiates
// its own preferred type (ecdsa/rsa) and a host recorded only with, say, an
// ed25519 key fails as "key mismatch" even though that key is right - the
// usual case for a host first reached with ssh, which stores one key type.
// Nil (any algorithm) for unknown hosts and without strict checking.
func (r *Runner) hostKeyAlgorithms(addr string) []string {
	if r.knownKey == nil {
		return nil
	}
	err := r.hostKey(addr, &net.TCPAddr{}, r.knownKey)
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) || len(ke.Want) == 0 {
		return nil
	}
	var algos []string
	seen := map[string]bool{}
	for _, k := range ke.Want {
		t := k.Key.Type()
		if seen[t] {
			continue
		}
		seen[t] = true
		if t == ssh.KeyAlgoRSA {
			// an ssh-rsa known_hosts entry is used with the SHA-2 signature algorithms
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		}
		algos = append(algos, t)
	}
	return algos
}

// Notes describes the auth methods that were set up.
func (r *Runner) Notes() []string { return r.notes }

func buildAuth(cfg config.SSH) ([]ssh.AuthMethod, []string) {
	var methods []ssh.AuthMethod
	var notes []string

	if ag, err := dialAgent(); err == nil && ag != nil {
		methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
		notes = append(notes, "ssh-agent")
	} else if err != nil {
		notes = append(notes, "agent: "+err.Error())
	}

	keyPaths := []string{}
	if cfg.Key != "" {
		keyPaths = append(keyPaths, cfg.Key)
	} else if home, err := os.UserHomeDir(); err == nil {
		for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			keyPaths = append(keyPaths, filepath.Join(home, ".ssh", n))
		}
	}
	for _, kp := range keyPaths {
		b, err := os.ReadFile(kp)
		if err != nil {
			if cfg.Key != "" {
				notes = append(notes, "key: "+err.Error())
			}
			continue
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			var pe *ssh.PassphraseMissingError
			if errors.As(err, &pe) {
				if pass := os.Getenv("KHT_SSH_PASSPHRASE"); pass != "" {
					signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(pass))
				} else {
					notes = append(notes, fmt.Sprintf("key %s is encrypted (set KHT_SSH_PASSPHRASE or use ssh-agent)", kp))
					continue
				}
			}
			if err != nil {
				notes = append(notes, fmt.Sprintf("key %s: %v", kp, err))
				continue
			}
		}
		methods = append(methods, ssh.PublicKeys(signer))
		notes = append(notes, "key "+kp)
	}
	if pw := cfg.Password; pw != "" {
		// password auth is tried after agent/key methods fail
		methods = append(methods, ssh.Password(pw))
		methods = append(methods, ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = pw
			}
			return answers, nil
		}))
		notes = append(notes, "password fallback")
	}
	return methods, notes
}

func (r *Runner) clientConfig(addr, user string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:              user,
		Auth:              r.auth,
		HostKeyCallback:   r.recordHostKey(addr),
		HostKeyAlgorithms: r.hostKeyAlgorithms(addr),
		Timeout:           r.cfg.Timeout,
	}
}

// recordHostKey wraps the verification callback to remember the fingerprint
// of the key addr presented, verified or not: the checks compare them across
// nodes to spot cloned machines that still share one host key.
func (r *Runner) recordHostKey(addr string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		r.hkMu.Lock()
		r.hostKeys[addr] = ssh.FingerprintSHA256(key)
		r.hkMu.Unlock()
		return r.hostKey(hostname, remote, key)
	}
}

// HostKey is the SHA256 fingerprint of the host key seen at host, or ""
// before any dial reached the key exchange.
func (r *Runner) HostKey(host string) string {
	r.hkMu.Lock()
	defer r.hkMu.Unlock()
	return r.hostKeys[r.addr(host)]
}

func (r *Runner) dial(addr, user string) (*ssh.Client, error) {
	cfg := r.clientConfig(addr, user)
	var conn net.Conn
	var err error
	if r.cfg.Bastion != "" {
		b, err := r.bastionClient()
		if err != nil {
			return nil, fmt.Errorf("bastion: %w", err)
		}
		conn, err = b.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("via bastion: %w", err)
		}
	} else {
		conn, err = net.DialTimeout("tcp", addr, r.cfg.Timeout)
		if err != nil {
			return nil, err
		}
	}
	_ = conn.SetDeadline(time.Now().Add(r.cfg.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func (r *Runner) bastionClient() (*ssh.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bastion != nil {
		return r.bastion, nil
	}
	user, host := r.cfg.User, r.cfg.Bastion
	if u, h, ok := strings.Cut(host, "@"); ok {
		user, host = u, h
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "22")
	}
	conn, err := net.DialTimeout("tcp", host, r.cfg.Timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(r.cfg.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, host, r.clientConfig(host, user))
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	r.bastion = ssh.NewClient(c, chans, reqs)
	return r.bastion, nil
}

func (r *Runner) client(host string) (*ssh.Client, error) {
	addr := r.addr(host)
	r.mu.Lock()
	c, ok := r.clients[addr]
	r.mu.Unlock()
	if ok {
		return c, nil
	}
	c, err := r.dial(addr, r.cfg.User)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.clients[addr] = c
	r.mu.Unlock()
	return c, nil
}

func (r *Runner) drop(host string) {
	addr := r.addr(host)
	r.mu.Lock()
	if c, ok := r.clients[addr]; ok {
		c.Close()
		delete(r.clients, addr)
	}
	delete(r.become, addr)
	r.mu.Unlock()
}

// Become reports how the runner escalates on a host once it has been
// probed ("root", "sudo (NOPASSWD)", "dzdo (password)", ...), or "".
func (r *Runner) Become(host string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.become[r.addr(host)]; ok {
		return m.String()
	}
	return ""
}

func (r *Runner) addr(host string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, strconv.Itoa(r.cfg.Port))
	}
	return host
}

// Run executes a POSIX sh script on the host (via stdin, so no quoting
// issues) as root, escalating with sudo / dzdo / doas as the host allows
// (see become.go).
func (r *Runner) Run(ctx context.Context, host, script string) Result {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	}
	defer func() { <-r.sem }()

	if r.cfg.Nice {
		script = Prologue + script
	}
	res := r.runOnce(ctx, host, script)
	if res.Err != nil && isConnErr(res.Err) {
		// stale cached connection: reconnect once
		r.drop(host)
		res = r.runOnce(ctx, host, script)
	}
	return res
}

func (r *Runner) runOnce(ctx context.Context, host, script string) Result {
	res := Result{Started: time.Now(), ScriptSize: len(script)}
	c, err := r.client(host)
	res.HostKey = r.HostKey(host)
	if err != nil {
		res.Err = err
		res.Finished = time.Now()
		return res
	}
	sess, err := c.NewSession()
	if err != nil {
		res.Err = fmt.Errorf("session: %w", err)
		res.Finished = time.Now()
		return res
	}
	defer sess.Close()

	// how to become root on this host (probed once, cached until reconnect)
	addr := r.addr(host)
	r.mu.Lock()
	method, known := r.become[addr]
	r.mu.Unlock()
	if !known {
		method, err = r.detectBecome(ctx, c)
		if err != nil {
			res.Err = err
			res.Finished = time.Now()
			return res
		}
		r.mu.Lock()
		r.become[addr] = method
		r.mu.Unlock()
	}
	cmd, needPass := method.command()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = strings.NewReader(script)
	if needPass {
		sess.Stdin = strings.NewReader(r.becomePassword() + "\n" + script)
	}
	res.Started = time.Now()
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		sess.Close()
		// Run returns once the closed channel drains; wait for it so the
		// stdout/stderr copies are finished before the buffers are read
		<-done
		err = ctx.Err()
	}
	res.Finished = time.Now()
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	if err != nil {
		if method.tool != "" && strings.Contains(strings.ToLower(res.Stderr), "password") {
			// the cached method stopped working (sudo timestamp policy changed,
			// password rotated): probe again on the next call
			r.mu.Lock()
			delete(r.become, addr)
			r.mu.Unlock()
			err = fmt.Errorf("%s: %s (escalation will be re-probed)", method, firstLine(res.Stderr))
		}
		res.Err = err
	}
	return res
}

func isConnErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "EOF") || strings.Contains(s, "broken pipe") || strings.Contains(s, "connection reset") || strings.Contains(s, "use of closed")
}

// Close closes all cached connections.
func (r *Runner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, c := range r.clients {
		c.Close()
		delete(r.clients, k)
	}
	if r.bastion != nil {
		r.bastion.Close()
		r.bastion = nil
	}
}

var _ = agent.NewClient
