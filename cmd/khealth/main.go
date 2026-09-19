// Command khealth is a terminal dashboard with health checks for upstream
// Kubernetes and RKE2 clusters (kubeconfig + SSH to nodes).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof" // --pprof: CPU/heap profiles of the running TUI
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
	"k8s.io/klog/v2"

	"k8s-health-tui/internal/bootstrap"
	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/sshrun"
	"k8s-health-tui/internal/ui"
)

func main() {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
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
	if cfg.Perf.Pprof != "" {
		// go tool pprof http://<addr>/debug/pprof/profile?seconds=30
		go func() { _ = http.ListenAndServe(cfg.Perf.Pprof, nil) }()
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

// bootstrapKubeconfig builds a kubeconfig over SSH when asked to
// (--bootstrap-kubeconfig), or offers to when the configured kubeconfig does
// not load and ssh.hosts names nodes to try. On success cfg points at the
// written file.
func bootstrapKubeconfig(cfg *config.Config) error {
	hosts := cfg.Bootstrap.Hosts
	if len(hosts) == 0 {
		loadErr := k8s.CheckKubeconfig(cfg.Kubeconfig, cfg.Context)
		if loadErr == nil || !cfg.SSH.Enabled || len(cfg.SSH.Hosts) == 0 || !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil // the TUI reports the kubeconfig error itself
		}
		for _, h := range sortedValues(cfg.SSH.Hosts) {
			hosts = append(hosts, h)
		}
		fmt.Fprintf(os.Stderr, "kubeconfig: %v\nFetch the admin kubeconfig over SSH from %s and write it under ~/.kube? [Y/n] ", loadErr, strings.Join(hosts, ", "))
		var ans string
		fmt.Fscanln(os.Stdin, &ans)
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "" && a != "y" && a != "yes" {
			return nil
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
		Hosts: hosts, Out: cfg.Bootstrap.Out, Name: cfg.Bootstrap.Name,
		Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s  (context %q, server %s)\n", res.Path, res.Name, res.Server)
	for _, n := range res.Notes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	fmt.Fprintf(os.Stderr, "use it later with --kubeconfig %s, or merge: KUBECONFIG=~/.kube/config:%s kubectl config view --flatten\n", res.Path, res.Path)
	cfg.Kubeconfig, cfg.Context = res.Path, res.Name
	return nil
}

func sortedValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
