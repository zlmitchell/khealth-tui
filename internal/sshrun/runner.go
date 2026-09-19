// Package sshrun executes shell scripts on cluster nodes over SSH.
package sshrun

import (
	"bytes"
	"context"
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
	notes   []string

	mu       sync.Mutex
	clients  map[string]*ssh.Client
	bastion  *ssh.Client
	sem      chan struct{}
	sudoPass bool // sudo needed a password on at least one host; use sudo -S from now on
}

// Result is the outcome of running a script on a node.
type Result struct {
	Stdout   string
	Stderr   string
	Err      error
	Started  time.Time
	Finished time.Time
}

// New prepares authentication and host key verification. It does not connect.
func New(cfg config.SSH) (*Runner, error) {
	r := &Runner{cfg: cfg, clients: map[string]*ssh.Client{}, sem: make(chan struct{}, cfg.Concurrency)}
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
			if errors.As(err, &ke) && len(ke.Want) == 0 {
				return fmt.Errorf("host key for %s not in known_hosts (ssh to it once, or --insecure-host-key)", hostname)
			}
			return err
		}
	}
	return r, nil
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

func (r *Runner) clientConfig(user string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            r.auth,
		HostKeyCallback: r.hostKey,
		Timeout:         r.cfg.Timeout,
	}
}

func (r *Runner) dial(addr, user string) (*ssh.Client, error) {
	cfg := r.clientConfig(user)
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
	c, chans, reqs, err := ssh.NewClientConn(conn, host, r.clientConfig(user))
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	r.bastion = ssh.NewClient(c, chans, reqs)
	return r.bastion, nil
}

func (r *Runner) client(host string) (*ssh.Client, error) {
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, strconv.Itoa(r.cfg.Port))
	}
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
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, strconv.Itoa(r.cfg.Port))
	}
	r.mu.Lock()
	if c, ok := r.clients[addr]; ok {
		c.Close()
		delete(r.clients, addr)
	}
	r.mu.Unlock()
}

// Run executes a POSIX sh script on the host (via stdin, so no quoting
// issues), optionally under passwordless sudo.
func (r *Runner) Run(ctx context.Context, host, script string) Result {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	}
	defer func() { <-r.sem }()

	res := r.runOnce(ctx, host, script)
	if res.Err != nil && isConnErr(res.Err) {
		// stale cached connection: reconnect once
		r.drop(host)
		res = r.runOnce(ctx, host, script)
	}
	return res
}

func (r *Runner) runOnce(ctx context.Context, host, script string) Result {
	res := Result{Started: time.Now()}
	c, err := r.client(host)
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

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = strings.NewReader(script)

	cmd := "/bin/sh -s"
	if r.cfg.Sudo && r.cfg.User != "root" {
		cmd = "sudo -n /bin/sh -s"
		r.mu.Lock()
		usePass := r.sudoPass
		r.mu.Unlock()
		if usePass {
			// sudo needs a password on this host: feed it on stdin ahead of the script
			cmd = "sudo -S -p '' /bin/sh -s"
			sess.Stdin = strings.NewReader(r.cfg.Password + "\n" + script)
		}
	}
	res.Started = time.Now()
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		sess.Close()
		err = ctx.Err()
	}
	res.Finished = time.Now()
	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
	if err != nil {
		if strings.Contains(res.Stderr, "sudo") && strings.Contains(res.Stderr, "password") {
			r.mu.Lock()
			retry := r.cfg.Password != "" && !r.sudoPass
			if retry {
				r.sudoPass = true
			}
			r.mu.Unlock()
			if retry {
				// retry once with the SSH password fed to sudo -S
				return r.runOnce(ctx, host, script)
			}
			err = fmt.Errorf("sudo requires a password (configure NOPASSWD, use --ask-pass, or ssh.sudo: false)")
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
