// Command khealth is a terminal dashboard with health checks for upstream
// Kubernetes and RKE2 clusters (kubeconfig + SSH to nodes).
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof" // --pprof: CPU/heap profiles of the running TUI
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
	"k8s.io/klog/v2"

	"github.com/zlmitchell/khealth-tui/internal/bootstrap"
	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/export"
	"github.com/zlmitchell/khealth-tui/internal/headless"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/ui"
)

func main() {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	k8s.SetSystemNamespaces(cfg.Namespaces.System)
	k8s.SetCNINames(cfg.Namespaces.CNI)
	if cfg.Diag {
		client, err := k8s.New(cfg.Kubeconfig, cfg.Context)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		k8s.SetEtcdDiag(func(ctx context.Context, c *k8s.Client, node, pod string, w io.Writer) {
			p := etcd.ExecProbe(ctx, c, node, pod, "rke2")
			if p.Err != nil {
				fmt.Fprintf(w, "  probe: ERROR %v\n", p.Err)
				return
			}
			fmt.Fprintf(w, "  probe: %d members, %d endpoint health entries, %d statuses, %d alarms (%s)\n", len(p.Members), len(p.EndpointHealth), len(p.Statuses), len(p.Alarms), p.Duration.Round(time.Millisecond))
			for _, m := range p.Members {
				fmt.Fprintf(w, "    member %s %s %v\n", m.ID, m.Name, m.ClientURLs)
			}
			for _, h := range p.EndpointHealth {
				fmt.Fprintf(w, "    health %s healthy=%v took=%s %s\n", h.Endpoint, h.Healthy, h.Took, h.Error)
			}
			for _, st := range p.Statuses {
				fmt.Fprintf(w, "    status %s v%s db=%d leader=%s raftTerm=%d\n", st.Endpoint, st.Version, st.DBSize, st.Leader, st.RaftTerm)
			}
			if p.EtcdctlDiag != "" {
				fmt.Fprintf(w, "    diag: %s\n", p.EtcdctlDiag)
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		client.Diag(ctx, os.Stdout)
		return
	}
	if cfg.SSH.Enabled && cfg.SSH.AskPass && cfg.SSH.Password == "" {
		fmt.Fprintf(os.Stderr, "SSH/sudo password for %s@<nodes> (used only if public key auth fails): ", cfg.SSH.User)
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: cannot read password:", err)
			os.Exit(2)
		}
		cfg.SSH.Password = string(pw)
	}
	if err := bootstrapKubeconfig(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	// klog (client-go throttling notices etc.) writes to stderr, which lands on
	// top of the alt-screen; silence it while the TUI owns the terminal.
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)
	if cfg.Export.Out != "" {
		if err := exportOnce(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if cfg.Perf.Pprof != "" {
		// go tool pprof http://<addr>/debug/pprof/profile?seconds=30
		go func() { _ = http.ListenAndServe(cfg.Perf.Pprof, nil) }()
	}
	// Settle light/dark before bubbletea owns the terminal. Left to lipgloss,
	// the background query runs on the first render, while bubbletea reads
	// stdin, and loses the reply; Windows cannot be asked at all.
	switch cfg.Theme {
	case "light":
		lipgloss.SetHasDarkBackground(false)
	case "dark":
		lipgloss.SetHasDarkBackground(true)
	default:
		lipgloss.SetHasDarkBackground(lipgloss.HasDarkBackground())
	}
	app, err := ui.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exportOnce is --export: one collection cycle (with the security scan and
// the heavy tiers when asked), the report written where --export points,
// no TUI. The same files `e` writes from inside the app.
func exportOnce(cfg config.Config) error {
	what := "findings"
	if cfg.Export.Scan {
		what += " + security scan"
	}
	if cfg.Export.Heavy {
		what += " + heavy tiers"
	}
	fmt.Fprintf(os.Stderr, "collecting %s ...\n", what)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	res, err := headless.Run(ctx, cfg, headless.Options{Heavy: cfg.Export.Heavy, Scan: cfg.Export.Scan, Log: os.Stderr})
	if err != nil {
		return err
	}
	rep := export.Build(export.Input{Snap: res.Snap, Nodes: res.Input.Nodes, Findings: res.Findings, Stig: res.Stig, StigRun: cfg.Export.Scan, Context: res.Client.Context, Server: res.Client.Host, Version: config.Version, Now: time.Now()})
	out := cfg.Export.Out
	switch strings.ToLower(filepath.Ext(out)) {
	case ".json":
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		if err := export.WriteJSON(f, rep); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println("wrote", out)
	case ".xlsx":
		if err := export.WriteXLSX(out, rep); err != nil {
			return err
		}
		fmt.Println("wrote", out)
	default:
		jsonPath, xlsxPath, err := export.WriteFiles(out, rep)
		if err != nil {
			return err
		}
		fmt.Println("wrote", jsonPath)
		fmt.Println("wrote", xlsxPath)
	}
	fmt.Printf("%d nodes, %d findings (%d crit, %d warn, %d info)", rep.Cluster.Nodes, len(rep.Findings), rep.Summary.Crit, rep.Summary.Warn, rep.Summary.Info)
	if rep.Security != nil {
		fmt.Printf(", %d benchmarks: ", len(rep.Security.Benchmarks))
		for i, b := range rep.Security.Benchmarks {
			if i > 0 {
				fmt.Print(", ")
			}
			score := "n/a"
			if b.Score != nil {
				score = fmt.Sprintf("%.1f%%", *b.Score)
			}
			fmt.Printf("%s %s (%d rules)", b.Sheet, score, len(b.Rules))
		}
	}
	fmt.Println()
	return nil
}

// bootstrapKubeconfig builds a kubeconfig over SSH when asked to
// (--bootstrap-kubeconfig), or offers to when the configured kubeconfig does
// not load and ssh.hosts names nodes to try. On success cfg points at the
// written file.
func bootstrapKubeconfig(cfg *config.Config) error {
	hosts := cfg.Bootstrap.Hosts
	if len(hosts) == 0 {
		loadErr := k8s.CheckKubeconfig(cfg.Kubeconfig, cfg.Context)
		interactive := term.IsTerminal(int(os.Stdin.Fd()))
		// 0. clusters bootstrapped earlier (~/.kube/khealth-*.yaml): offer
		// them whenever nothing was chosen explicitly on the command line
		if interactive && !cfg.Flags["kubeconfig"] && !cfg.Flags["context"] {
			if done, err := chooseContext(cfg, loadErr); err != nil || done {
				return err
			}
		}
		if loadErr == nil {
			return nil
		}
		if !interactive {
			return fmt.Errorf("kubeconfig: %v\n  pass --kubeconfig, or --bootstrap-kubeconfig user@server-node to fetch the admin kubeconfig over SSH", loadErr)
		}
		fmt.Fprintf(os.Stderr, "kubeconfig: %v\n", loadErr)
		// 1. running on a cluster node: the admin kubeconfig is right here
		if path, err := useLocalKubeconfig(); err != nil {
			return err
		} else if path != "" {
			cfg.Kubeconfig, cfg.Context = path, ""
			return nil
		}
		// 2. fetch it over SSH: the configured node addresses, or ask for one
		if !cfg.SSH.Enabled {
			return errors.New("no kubeconfig found; pass --kubeconfig, or run without --no-ssh so khealth can fetch the admin kubeconfig from a server node")
		}
		hosts = append(hosts, sortedValues(cfg.SSH.Hosts)...)
		if len(hosts) > 0 {
			fmt.Fprintf(os.Stderr, "Fetch the admin kubeconfig over SSH from %s and write it under ~/.kube? [Y/n] ", strings.Join(hosts, ", "))
			if !yes(readLine()) {
				return errors.New("no kubeconfig; pass --kubeconfig or --bootstrap-kubeconfig user@server-node")
			}
		} else {
			fmt.Fprint(os.Stderr, "No kubeconfig on this machine. Fetch the admin kubeconfig over SSH from a server node?\n  server node [user@]host (blank to abort): ")
			h := readLine()
			if h == "" {
				return errors.New("no kubeconfig; pass --kubeconfig or --bootstrap-kubeconfig user@server-node")
			}
			if u, rest, ok := strings.Cut(h, "@"); ok {
				cfg.SSH.User, h = u, rest
				cfg.Flags["ssh-user"] = true
			}
			if cfg.SSH.User == "" {
				fmt.Fprint(os.Stderr, "  ssh user: ")
				cfg.SSH.User = readLine()
				cfg.Flags["ssh-user"] = true
			}
			if !sshKeyAvailable(cfg.SSH.Key) && cfg.SSH.Password == "" && os.Getenv("SSH_AUTH_SOCK") == "" {
				where := cfg.SSH.Key
				if where == "" {
					where = "~/.ssh/id_ed25519, id_ecdsa or id_rsa"
				}
				fmt.Fprintf(os.Stderr, "  no key at %s and no agent; password for %s@%s: ", where, cfg.SSH.User, h)
				pw, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				cfg.SSH.Password = string(pw)
			}
			hosts = []string{h}
		}
	}
	if !cfg.SSH.Enabled {
		return errors.New("--bootstrap-kubeconfig needs SSH (remove --no-ssh / set ssh.enabled)")
	}
	r, err := sshrun.New(cfg.SSH)
	if err != nil {
		return err
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fmt.Fprintln(os.Stderr, "bootstrapping kubeconfig over SSH:")
	res, err := bootstrap.Run(ctx, r, bootstrap.Options{
		Hosts: hosts, Out: cfg.Bootstrap.Out, Name: cfg.Bootstrap.Name, Fresh: cfg.Bootstrap.Fresh,
		SSH: k8s.SSHHint{User: cfg.SSH.User, Key: cfg.SSH.Key, Port: cfg.SSH.Port, Become: cfg.SSH.Become},
		Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s  (context %q, server %s)\n", res.Path, res.Name, res.Server)
	for _, n := range res.Notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	fmt.Fprintf(os.Stderr, "next time just run: khealth   (the context picker lists it; ssh user %s is remembered in the context)\n", cfg.SSH.User)
	cfg.Kubeconfig, cfg.Context = res.Path, res.Name
	applySSHHint(cfg, res.SSH)
	// a reused file carries the user from an earlier run; khealth root@host
	// names a new one, so the context is updated to it
	rememberSSH(cfg, res.Path, res.Name, res.SSH)
	return nil
}

// sshKeyAvailable reports whether a private key will be offered: the one
// configured, else any of the default ones under ~/.ssh (what
// sshrun.New loads when ssh.key is empty).
func sshKeyAvailable(key string) bool {
	if key != "" {
		_, err := os.Stat(key)
		return err == nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		if _, err := os.Stat(filepath.Join(home, ".ssh", n)); err == nil {
			return true
		}
	}
	return false
}

// rememberSSH stores the SSH user given on the command line (--ssh-user or
// user@host) in the context when it differs from what the file remembers.
// A user that merely defaulted to the local login is never stored: it is
// as likely wrong as right, and once stored it would silently override
// the next run's user@host.
func rememberSSH(cfg *config.Config, file, ctxName string, stored k8s.SSHHint) {
	if file == "" || !cfg.SSH.Enabled || !cfg.Flags["ssh-user"] || cfg.SSH.User == "" || cfg.SSH.User == stored.User {
		return
	}
	h := k8s.SSHHint{User: cfg.SSH.User, Key: cfg.SSH.Key, Port: cfg.SSH.Port, Become: cfg.SSH.Become}
	if err := bootstrap.RememberSSH(file, ctxName, h); err == nil {
		fmt.Fprintf(os.Stderr, "remembered ssh user %s for %s in %s\n", cfg.SSH.User, ctxName, filepath.Base(file))
	}
}

// chooseContext lists the contexts khealth knows (the kubeconfig in use plus
// every ~/.kube/khealth-*.yaml) and lets the operator pick one, or start a
// new bootstrap. Returns done=true when a context was chosen. Nothing is
// asked when only the current context exists.
func chooseContext(cfg *config.Config, loadErr error) (bool, error) {
	list := k8s.Contexts(cfg.Kubeconfig, cfg.Context)
	if len(list) == 0 || (len(list) == 1 && list[0].Current && loadErr == nil) {
		return false, nil
	}
	fmt.Fprintln(os.Stderr, "Clusters:")
	for i, c := range list {
		mark := " "
		if c.Current && loadErr == nil {
			mark = "*"
		}
		src := "kubeconfig"
		if c.File != "" {
			src = filepath.Base(c.File)
		}
		ssh := ""
		if c.SSH.User != "" {
			ssh = "  ssh " + c.SSH.User
			if c.SSH.Host != "" {
				ssh += "@" + c.SSH.Host
			}
		}
		fmt.Fprintf(os.Stderr, " %s%2d) %-24s %-36s %s%s\n", mark, i+1, c.Name, c.Server, src, ssh)
	}
	fmt.Fprintf(os.Stderr, "  %2s) bootstrap another cluster from [user@]server-node\n", "n")
	def := "1"
	for i, c := range list {
		if c.Current && loadErr == nil {
			def = fmt.Sprint(i + 1)
		}
	}
	fmt.Fprintf(os.Stderr, "context [%s]: ", def)
	ans := readLine()
	if ans == "" {
		ans = def
	}
	if strings.EqualFold(ans, "n") {
		fmt.Fprint(os.Stderr, "  server node [user@]host: ")
		h := readLine()
		if h == "" {
			return false, errors.New("no cluster chosen")
		}
		if u, rest, ok := strings.Cut(h, "@"); ok && u != "" {
			cfg.SSH.User, h = u, rest
			cfg.Flags["ssh-user"] = true
		}
		cfg.Bootstrap.Hosts = []string{h}
		return false, nil
	}
	n, err := strconv.Atoi(ans)
	if err != nil || n < 1 || n > len(list) {
		return false, fmt.Errorf("no such context %q", ans)
	}
	c := list[n-1]
	if c.File != "" {
		cfg.Kubeconfig = c.File
	}
	cfg.Context = c.Name
	applySSHHint(cfg, c.SSH)
	fmt.Fprintf(os.Stderr, "using context %s (%s)%s\n", c.Name, c.Server, sshNote(cfg, c.SSH))
	// an ssh user typed for this run: remember it in the context for next time
	rememberSSH(cfg, c.File, c.Name, c.SSH)
	return true, nil
}

// applySSHHint adopts the SSH settings remembered for a cluster unless the
// operator set them on the command line.
func applySSHHint(cfg *config.Config, h k8s.SSHHint) {
	if h.Empty() {
		return
	}
	if h.User != "" && !cfg.Flags["ssh-user"] {
		cfg.SSH.User = h.User
	}
	if h.Key != "" && !cfg.Flags["ssh-key"] {
		cfg.SSH.Key = h.Key
	}
	if h.Port != 0 && !cfg.Flags["ssh-port"] {
		cfg.SSH.Port = h.Port
	}
	if h.Become != "" && !cfg.Flags["become"] {
		cfg.SSH.Become = h.Become
	}
	// the bootstrap host is one of a node's own addresses: dial that node
	// there (ssh.hosts semantics), even when the node object reports another
	// address - a node that changed address keeps reporting the old one
	if h.Node != "" && h.Host != "" {
		if cfg.SSH.Hosts == nil {
			cfg.SSH.Hosts = map[string]string{}
		}
		if _, set := cfg.SSH.Hosts[h.Node]; !set {
			cfg.SSH.Hosts[h.Node] = h.Host
		}
	}
	cfg.SSH.AddFallbackHost(h.Host)
}

func sshNote(cfg *config.Config, h k8s.SSHHint) string {
	if h.User == "" {
		return ""
	}
	return fmt.Sprintf(", ssh as %s (remembered in the context)", cfg.SSH.User)
}

// localKubeconfigs are the admin kubeconfigs a cluster node keeps.
var localKubeconfigs = []string{"/etc/rancher/rke2/rke2.yaml", "/etc/rancher/k3s/k3s.yaml", "/etc/kubernetes/admin.conf"}

// useLocalKubeconfig offers a kubeconfig found on this machine (khealth
// started on a cluster node). A root-only file is copied through sudo into
// ~/.kube/khealth-local.yaml. Returns "" when there is none or the user
// declines.
func useLocalKubeconfig() (string, error) {
	for _, p := range localKubeconfigs {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "Found %s on this host. Use it? [Y/n] ", p)
		if !yes(readLine()) {
			return "", nil
		}
		if k8s.CheckKubeconfig(p, "") == nil {
			return p, nil
		}
		// not readable as this user: copy it through sudo (prompts on the tty)
		fmt.Fprintf(os.Stderr, "%s is not readable as %s; copying it with sudo to ~/.kube/khealth-local.yaml\n", p, currentUser())
		cmd := exec.Command("sudo", "cat", p)
		cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
		b, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("sudo cat %s: %v (run khealth as root, or: sudo cp %s ~/.kube/config && sudo chown $USER ~/.kube/config)", p, err, p)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		out := filepath.Join(home, ".kube", "khealth-local.yaml")
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(out, b, 0o600); err != nil {
			return "", err
		}
		if err := k8s.CheckKubeconfig(out, ""); err != nil {
			return "", fmt.Errorf("%s copied to %s but it does not load: %v", p, out, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (server as on the node, usually https://127.0.0.1:6443); use it later with --kubeconfig %s\n", out, out)
		return out, nil
	}
	return "", nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "this user"
}

var stdin = bufio.NewReader(os.Stdin)

func readLine() string {
	l, _ := stdin.ReadString('\n')
	return strings.TrimSpace(l)
}

func yes(ans string) bool {
	a := strings.ToLower(strings.TrimSpace(ans))
	return a == "" || a == "y" || a == "yes"
}

func sortedValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
