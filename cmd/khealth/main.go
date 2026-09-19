// Command khealth is a terminal dashboard with health checks for upstream
// Kubernetes and RKE2 clusters (kubeconfig + SSH to nodes).
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/ui"
)

func main() {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
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
