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

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// Runner holds SSH connections to nodes and runs scripts on them.
type Runner struct {
	cfg     config.SSH
	auth    []ssh.AuthMethod
	hostKey ssh.HostKeyCallback
	// knownKey is a throwaway key used to ask known_hosts which key types
	// it holds for a host (see hostKeyAlgorithms); nil without strict checking
	knownKey ssh.PublicKey
	known    ssh.HostKeyCallback // the raw known_hosts lookup (strict only)
	// knownKeys are the host keys known_hosts holds under any name, and
	// knownTypes their key types in file order: a node reached by an address
	// the file does not list (the TUI dials InternalIPs; the operator's ssh
	// recorded the name) is still the machine whose key is on file
	knownKeys  map[string]bool
	knownTypes []string
	knownMu    sync.Mutex // knownKeys/knownTypes are written by recordNewHostKey from parallel dials
	notes      []string

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
		r.known = cb
		r.knownKeys, r.knownTypes = readKnownKeys(path)
		r.hostKey = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := cb(hostname, remote, key)
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) {
				h := hostname
				if hp, _, err := net.SplitHostPort(hostname); err == nil {
					h = hp
				}
				if len(ke.Want) == 0 {
					if r.hasKnownKey(key) {
						// the address is new, the key is not: the same host
						// under another name (ssh records the name it was
						// given, not the IP the node object carries)
						return nil
					}
					if cfg.AcceptNewHostKeys {
						// first contact: record it, as ssh does with
						// StrictHostKeyChecking=accept-new; from now on a
						// different key for this address is a mismatch
						return r.recordNewHostKey(path, hostname, key)
					}
					return fmt.Errorf("host key for %s not in known_hosts (ssh to it once, ssh-keyscan it, --accept-new-host-keys, or --insecure-host-key)", h)
				}
				if r.hasKnownKey(key) {
					// recorded with one node's key, answering with another
					// node's known key: the name is a VIP that moved to a
					// different server (each has its own host key)
					return nil
				}
				// wrapped, not replaced: hostKeyAlgorithms reads ke.Want through it
				return fmt.Errorf("host key for %s changed since known_hosts recorded it: ssh-keygen -R %s, then ssh to it once (or --insecure-host-key); a VIP that moves between servers needs every server's key in known_hosts (--accept-new-host-keys records them): %w", h, h, err)
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
// An address the file does not list gets the types it holds for any host,
// so a node recorded under its name presents the key that is on file when
// dialed by IP. Nil (any algorithm) with nothing on file and without
// strict checking.
func (r *Runner) hostKeyAlgorithms(addr string) []string {
	if r.knownKey == nil {
		return nil
	}
	err := r.known(addr, &net.TCPAddr{}, r.knownKey)
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return nil
	}
	// the types recorded for this address first, then every type the file
	// holds: a VIP recorded with one server's key may answer with another's
	var types []string
	for _, k := range ke.Want {
		types = append(types, k.Key.Type())
	}
	r.knownMu.Lock()
	types = append(types, r.knownTypes...)
	r.knownMu.Unlock()
	var algos []string
	seen := map[string]bool{}
	for _, t := range types {
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

func (r *Runner) hasKnownKey(key ssh.PublicKey) bool {
	r.knownMu.Lock()
	defer r.knownMu.Unlock()
	return r.knownKeys[string(key.Marshal())]
}

// recordNewHostKey appends the key an unknown address presented to the
// known_hosts file (one line, the form ssh writes) and remembers it for
// the dials that follow in this run.
func (r *Runner) recordNewHostKey(path, hostname string, key ssh.PublicKey) error {
	r.knownMu.Lock()
	defer r.knownMu.Unlock()
	k := string(key.Marshal())
	if !r.knownKeys[k] {
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 && b[len(b)-1] != '\n' {
			line = "\n" + line // a file ssh left without a final newline
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return fmt.Errorf("record host key for %s: %w", hostname, err)
		}
		_, err = f.WriteString(line)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("record host key for %s: %w", hostname, err)
		}
		r.knownTypes = append(r.knownTypes, key.Type())
	}
	r.knownKeys[k] = true
	return nil
}

// readKnownKeys collects every host key in a known_hosts file (hashed
// entries included: the key is in the clear, only the name is hashed) and
// their key types in file order. @revoked keys are left out, @cert-authority
// entries are not host keys.
func readKnownKeys(path string) (map[string]bool, []string) {
	keys := map[string]bool{}
	revoked := map[string]bool{}
	var types []string
	data, err := os.ReadFile(path)
	if err != nil {
		return keys, nil
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		marker, _, key, _, _, err := ssh.ParseKnownHosts(line)
		if err != nil || key == nil {
			continue
		}
		k := string(key.Marshal())
		switch marker {
		case "revoked":
			revoked[k] = true
		case "":
			if !keys[k] {
				types = append(types, key.Type())
			}
			keys[k] = true
		}
	}
	for k := range revoked {
		delete(keys, k)
	}
	return keys, types
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

// explainDial turns the library's "unable to authenticate" into what was
// tried: the user and the credentials (ssh.user defaults to the local
// login, which is rarely the node's; a kubeconfig without a khealth hint
// gives no better default), so the fix is in the message.
func (r *Runner) explainDial(err error) error {
	if !strings.Contains(err.Error(), "unable to authenticate") {
		return err
	}
	user := r.cfg.User
	prefix := ""
	if strings.HasPrefix(err.Error(), "bastion:") {
		// the jump host refused, possibly its own user
		prefix = "bastion: "
		if u, _, ok := strings.Cut(r.cfg.Bastion, "@"); ok {
			user = u
		}
	}
	var creds []string
	for _, n := range r.notes {
		if strings.HasPrefix(n, "key ") || n == "ssh-agent" || n == "password fallback" {
			creds = append(creds, n)
		}
	}
	tried := strings.Join(creds, ", ")
	if tried == "" {
		tried = "no key, no agent, no password"
	}
	return fmt.Errorf("%sssh: authentication refused for user %s (offered: %s): set --ssh-user / --ssh-key (or ssh.user / ssh.key in the config, --ask-pass for a password); khealth user@host remembers them per cluster", prefix, user, tried)
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
		res.Err = r.explainDial(err)
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
			err = fmt.Errorf("%s: %s (escalation will be re-probed)", method, strutil.FirstLine(res.Stderr))
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
