package sshrun

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"k8s-health-tui/internal/strutil"

	"golang.org/x/crypto/ssh"
)

// Privilege escalation. The SSH user is normally not root; the probes need
// root (sshd -T, auditctl, /etc/shadow, etcd certs). On first use of a host
// the runner works out how to become root there and caches the answer:
//
//   - already uid 0 (root or a root-equivalent login): run the script directly
//   - sudo / dzdo / doas with NOPASSWD: "<tool> -n /bin/sh -s"
//   - sudo / dzdo with a password: "<tool> -S -p '' /bin/sh -s", the password
//     fed on stdin ahead of the script (doas has no -S, so it needs NOPASSWD)
//
// The order for become: auto is sudo, dzdo (Centrify / Delinea), doas.

var becomeTools = []string{"sudo", "dzdo", "doas"}

// becomeMethod is the cached escalation for one host.
type becomeMethod struct {
	tool     string // "" = run directly (root already)
	withPass bool   // feed the password on stdin
}

// command returns the remote command for a script and whether the password
// must be fed on stdin ahead of it.
func (m becomeMethod) command() (cmd string, needPass bool) {
	switch {
	case m.tool == "":
		return "/bin/sh -s", false
	case m.withPass:
		return m.tool + " -S -p '' /bin/sh -s", true
	}
	return m.tool + " -n /bin/sh -s", false
}

func (m becomeMethod) String() string {
	switch {
	case m.tool == "":
		return "root"
	case m.withPass:
		return m.tool + " (password)"
	}
	return m.tool + " (NOPASSWD)"
}

// probeScript reports the caller's uid and which escalation tools exist.
// The trailing `exit 0` matters: the script's status is that of the last
// `command -v`, which fails on every host without doas.
const becomeProbe = "id -u; for t in sudo dzdo doas; do command -v $t >/dev/null 2>&1 && echo tool=$t; done; exit 0\n"

// parseBecomeProbe returns uid and the tools found, in becomeTools order.
func parseBecomeProbe(out string) (uid string, tools []string) {
	have := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "tool="):
			have[strings.TrimPrefix(l, "tool=")] = true
		case l != "" && uid == "":
			uid = l
		}
	}
	for _, t := range becomeTools {
		if have[t] {
			tools = append(tools, t)
		}
	}
	return uid, tools
}

// classifyBecomeFailure turns a tool's stderr into a short reason.
func classifyBecomeFailure(tool, stderr string) (needsPassword bool, reason string) {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "password"):
		return true, "password required"
	case strings.Contains(s, "not in the sudoers") || strings.Contains(s, "not allowed") || strings.Contains(s, "operation not permitted") || strings.Contains(s, "no authorization") || strings.Contains(s, "not authorized"):
		return false, "not permitted for this user"
	case strings.Contains(s, "no tty") || strings.Contains(s, "have a tty") || strings.Contains(s, "terminal is required") || strings.Contains(s, "askpass"):
		return false, "needs a terminal (requiretty?)"
	}
	if line := strutil.FirstLine(stderr); line != "" {
		return false, line
	}
	return false, tool + " did not return uid 0"
}

// detectBecome probes one host and returns the method to use, or an error
// naming every tool tried and why it failed.
func (r *Runner) detectBecome(ctx context.Context, c *ssh.Client) (becomeMethod, error) {
	if r.cfg.Become == "none" {
		return becomeMethod{}, nil
	}
	out, _, err := r.exec(ctx, c, "/bin/sh -s", becomeProbe)
	if err != nil {
		return becomeMethod{}, fmt.Errorf("become probe: %w", err)
	}
	uid, available := parseBecomeProbe(out)
	if uid == "0" {
		return becomeMethod{}, nil
	}
	candidates := available
	if r.cfg.Become != "auto" {
		found := false
		for _, t := range available {
			if t == r.cfg.Become {
				found = true
			}
		}
		if !found {
			return becomeMethod{}, fmt.Errorf("ssh.become: %s is not installed on this host (found: %s)", r.cfg.Become, orNone(available))
		}
		candidates = []string{r.cfg.Become}
	}
	if len(candidates) == 0 {
		return becomeMethod{}, fmt.Errorf("uid %s and none of sudo, dzdo, doas is installed; log in as root or set ssh.sudo: false", uid)
	}
	password := r.becomePassword()
	var reasons []string
	for _, tool := range candidates {
		out, stderr, err := r.exec(ctx, c, tool+" -n id -u", "")
		if err == nil && strings.TrimSpace(out) == "0" {
			return becomeMethod{tool: tool}, nil
		}
		needsPass, reason := classifyBecomeFailure(tool, stderr)
		if needsPass {
			switch {
			case tool == "doas":
				reason = "password required (doas cannot read one from stdin: grant nopass)"
			case password == "":
				reason = "password required (none configured: use --ask-pass, KHT_BECOME_PASSWORD or ssh.become_password)"
			default:
				out, stderr, err = r.exec(ctx, c, tool+" -S -p '' id -u", password+"\n")
				if err == nil && strings.TrimSpace(out) == "0" {
					return becomeMethod{tool: tool, withPass: true}, nil
				}
				_, reason = classifyBecomeFailure(tool, stderr)
				if reason == "password required" {
					reason = "password rejected"
				}
			}
		}
		reasons = append(reasons, tool+": "+reason)
	}
	return becomeMethod{}, fmt.Errorf("cannot become root as uid %s: %s", uid, strings.Join(reasons, "; "))
}

func (r *Runner) becomePassword() string {
	if r.cfg.BecomePassword != "" {
		return r.cfg.BecomePassword
	}
	return r.cfg.Password
}

// exec runs one command on an established client with the given stdin.
func (r *Runner) exec(ctx context.Context, c *ssh.Client, cmd, stdin string) (string, string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("session: %w", err)
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	sess.Stdin = strings.NewReader(stdin)
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		err = ctx.Err()
	}
	return stdout.String(), stderr.String(), err
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}
