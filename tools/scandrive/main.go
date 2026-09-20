// Command scandrive runs the real TUI model headlessly against a cluster:
// every tea.Cmd the model returns is executed and its message fed back, so
// the refresh cycle, the node/etcd probes and the Security scan run exactly
// as in the terminal. It presses 0 then Shift+S a given time after the
// first snapshot and logs each message with the header line, then prints
// the OS STIG sub-tab once the scan has finished. Meant for reproducing
// timing-dependent behaviour of the update loop (a probe that straddles a
// refresh tick, a scan pressed mid-cycle) without a terminal.
//
// Usage:
//
//	scandrive [-press 23s] [-timeout 6m] -- [khealth flags]
//	scandrive -press 23s -- --kubeconfig ~/.kube/x.yaml --ssh-user root --ssh-key ~/.ssh/id_rsa
//	KHT_SSH_PASSWORD=... scandrive -- --kubeconfig ~/.kube/x.yaml --ssh-user ops --become sudo
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"k8s.io/klog/v2"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/ui"
)

type pressMsg struct{}

func main() {
	bf := flag.NewFlagSet("scandrive", flag.ExitOnError)
	press := bf.Duration("press", 0, "delay after the first snapshot before 0 + Shift+S are pressed")
	timeout := bf.Duration("timeout", 6*time.Minute, "give up (and print the current view) after this long")
	bf.Usage = func() {
		fmt.Fprintf(bf.Output(), "Usage: scandrive [-press D] [-timeout D] -- [khealth flags]\n\n")
		bf.PrintDefaults()
	}
	args := os.Args[1:]
	var rest []string
	for i, a := range args {
		if a == "--" {
			args, rest = args[:i], args[i+1:]
			break
		}
	}
	if err := bf.Parse(args); err != nil {
		os.Exit(2)
	}
	cfg, err := config.Load(rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	klog.SetOutput(io.Discard)
	klog.LogToStderr(false)
	app, err := ui.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var model tea.Model = app
	msgs := make(chan tea.Msg, 1024)
	start := time.Now()
	var run func(c tea.Cmd)
	run = func(c tea.Cmd) {
		if c == nil {
			return
		}
		go func() {
			m := c()
			if b, ok := m.(tea.BatchMsg); ok {
				for _, cc := range b {
					run(cc)
				}
				return
			}
			if m != nil {
				msgs <- m
			}
		}()
	}
	update := func(m tea.Msg) {
		var cmd tea.Cmd
		model, cmd = model.Update(m)
		run(cmd)
	}
	update(tea.WindowSizeMsg{Width: 220, Height: 60})
	run(app.Init())

	scanRe := regexp.MustCompile(`(security )?scan[^\n"]*`)
	pressed := false
	last := ""
	deadline := time.After(*timeout)
	for {
		select {
		case m := <-msgs:
			t := fmt.Sprintf("%T", m)
			if _, ok := m.(pressMsg); ok {
				update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
				update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'S'}})
			} else {
				update(m)
			}
			if strings.Contains(t, "spinner") {
				continue
			}
			v := ansi.Strip(model.View())
			lines := strings.Split(v, "\n")
			head := strings.TrimSpace(lines[0])
			status := ""
			for _, l := range lines {
				if strings.Contains(l, "scan") || strings.Contains(l, "stages") || strings.Contains(l, "failed") {
					status = strings.TrimSpace(l)
				}
			}
			fmt.Printf("%6.1fs %-22s %s\n", time.Since(start).Seconds(), t, head)
			if status != "" && status != last {
				fmt.Println("        " + status)
				last = status
			}
			if !pressed && strings.Contains(t, "snapshotMsg") {
				pressed = true
				go func() {
					time.Sleep(*press)
					msgs <- pressMsg{}
				}()
			}
			if strings.Contains(scanRe.FindString(v), "finished") {
				// the OS STIG sub-tab, once the recompute has landed
				update(tea.KeyMsg{Type: tea.KeyRight})
				update(tea.KeyMsg{Type: tea.KeyRight})
				time.Sleep(500 * time.Millisecond)
				for len(msgs) > 0 {
					update(<-msgs)
				}
				fmt.Println(ansi.Strip(model.View()))
				return
			}
		case <-deadline:
			fmt.Println("timeout")
			fmt.Println(ansi.Strip(model.View()))
			os.Exit(1)
		}
	}
}
