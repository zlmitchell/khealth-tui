// Command khealth is a terminal dashboard with health checks for upstream
// Kubernetes and RKE2 clusters (kubeconfig + SSH to nodes).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
	"k8s.io/klog/v2"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
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
	// klog (client-go throttling notices etc.) writes to stderr, which lands on
	// top of the alt-screen; silence it while the TUI owns the terminal.
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)
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
