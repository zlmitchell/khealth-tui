// Command findings runs one khealth collection cycle headlessly (API snapshot,
// node probe with the config tier - the heavy tier too with -heavy: journal,
// images, the registry pull dry run - full etcd probe on etcd nodes) and prints
// the findings the TUI would show, plus each etcd node's newest snapshot and
// backup hints. Meant for scripted verification, e.g. after configuring etcd
// backups. -json / -xlsx write the same report the TUI exports with `e`
// (-stig adds the STIG/CIS scan: the API-side rules plus the OS STIG facts
// collected over SSH, one sheet per benchmark).
//
// Usage:
//
//	findings [-area etcd] [-heavy] [-stig] [-json out.json] [-xlsx out.xlsx] -- [khealth flags]
//	findings -- --kubeconfig ~/.kube/x.yaml --ssh-user root --ssh-key ~/.ssh/id_rsa
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/export"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/sshrun"
	"k8s-health-tui/internal/stig"
)

func main() {
	bf := flag.NewFlagSet("findings", flag.ExitOnError)
	area := bf.String("area", "", "only print findings of this area (etcd, node, ...)")
	heavy := bf.Bool("heavy", false, "run the heavy node tier too (journal, images, registry pull dry run)")
	withStig := bf.Bool("stig", false, "evaluate the STIG/CIS rules too (API data + the OS STIG facts collected over SSH)")
	jsonOut := bf.String("json", "", "write the report as JSON to this file (- = stdout)")
	xlsxOut := bf.String("xlsx", "", "write the report as an Excel workbook to this file")
	bf.Usage = func() {
		fmt.Fprintf(bf.Output(), "Usage: findings [-area X] [-heavy] [-stig] [-json out.json] [-xlsx out.xlsx] -- [khealth flags]\n\n")
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

	opts := k8s.Options{WatchCache: cfg.Perf.WatchCache, Protobuf: cfg.Perf.Protobuf, DiscoveryTTL: cfg.Perf.DiscoveryTTL, ConfigzTTL: cfg.Perf.ConfigzTTL, DeniedTTL: cfg.Perf.DeniedTTL}
	client, err := k8s.NewWithOptions(cfg.Kubeconfig, cfg.Context, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx := context.Background()
	snap := client.Fetch(ctx)
	fmt.Printf("cluster %s: %d nodes, distribution %q\n", client.Host, len(snap.Nodes), snap.Distribution)

	in := checks.Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{}, Etcd: map[string]*etcd.Probe{}, Cfg: cfg, Now: time.Now(), APIServer: client.Host, SSHEnabled: cfg.SSH.Enabled}
	if cfg.SSH.Enabled {
		runner, err := sshrun.New(cfg.SSH)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ssh:", err)
			os.Exit(1)
		}
		defer runner.Close()
		var wg sync.WaitGroup
		var mu sync.Mutex
		o := nodeinfo.Options{LogLines: cfg.Logs.Lines, LogSince: cfg.Logs.Since, Config: true, Journal: *heavy, Images: *heavy, PVs: *heavy, OSStig: *withStig, CPUSample: true}
		setNet := func(o nodeinfo.Options, node string) nodeinfo.Options {
			for _, t := range snap.PodTargetList() {
				if !strings.HasPrefix(t, node+"=") {
					o.NetTargets = append(o.NetTargets, t)
				}
			}
			for i := range snap.Pods {
				p := &snap.Pods[i]
				if p.Namespace == "kube-system" && strings.Contains(p.Name, "coredns") && !strings.Contains(p.Name, "autoscaler") && p.Status.PodIP != "" && len(o.DNSPods) < 2 {
					o.DNSPods = append(o.DNSPods, p.Status.PodIP)
				}
			}
			o.DNSIP, o.APISvcIP = snap.ClusterDNSIP(), snap.APIServiceIP()
			return o
		}
		for i := range snap.Nodes {
			n := &snap.Nodes[i]
			host := cfg.SSH.Hosts[n.Name]
			if host == "" {
				host = k8s.NodeAddress(n, cfg.SSH.Address)
			}
			wg.Add(1)
			go func(name, host string) {
				defer wg.Done()
				c, cancel := context.WithTimeout(ctx, 3*cfg.SSH.Timeout)
				defer cancel()
				res := runner.Run(c, host, nodeinfo.Script(setNet(o, name)))
				if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
					fmt.Fprintf(os.Stderr, "node probe %s: %v %s\n", name, res.Err, res.Stderr)
				}
				info := nodeinfo.Parse(name, host, res.Stdout, res.Started)
				info.HostKey = res.HostKey
				mu.Lock()
				in.Nodes[name] = info
				mu.Unlock()
			}(n.Name, host)
			if k8s.IsEtcdNode(snap.Nodes, n) {
				wg.Add(1)
				go func(name, host string) {
					defer wg.Done()
					c, cancel := context.WithTimeout(ctx, 3*cfg.SSH.Timeout)
					defer cancel()
					res := runner.Run(c, host, etcd.Script(cfg.Etcd, true, true))
					if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
						fmt.Fprintf(os.Stderr, "etcd probe %s: %v %s\n", name, res.Err, res.Stderr)
					}
					p := etcd.Parse(name, res.Stdout)
					mu.Lock()
					in.Etcd[name] = p
					mu.Unlock()
				}(n.Name, host)
			}
		}
		wg.Wait()
	}

	for name, p := range in.Etcd {
		fmt.Printf("\netcd node %s:\n", name)
		if f, dir, ok := p.LatestSnapshot(); ok {
			fmt.Printf("  latest snapshot: %s/%s  %d bytes  %s ago (%d files)\n", dir, f.Name, f.Size, time.Since(f.ModTime).Round(time.Second), p.SnapshotCount())
		} else {
			fmt.Println("  latest snapshot: none found")
		}
		for _, h := range p.BackupHints {
			fmt.Printf("  %s\n", h)
		}
	}

	var stigRes []stig.Result
	if *withStig {
		stigRes = stig.Evaluate(stig.Input{Snap: snap, Nodes: in.Nodes, Etcd: in.Etcd})
		in.Stig = stigRes
	}
	fs := checks.Evaluate(in)
	if *jsonOut != "" || *xlsxOut != "" {
		rep := export.Build(export.Input{Snap: snap, Nodes: in.Nodes, Findings: fs, Stig: stigRes, StigRun: *withStig, Context: cfg.Context, Server: client.Host, Version: config.Version, Now: time.Now()})
		if *jsonOut == "-" {
			if err := export.WriteJSON(os.Stdout, rep); err != nil {
				fmt.Fprintln(os.Stderr, "json:", err)
				os.Exit(1)
			}
		} else if *jsonOut != "" {
			f, err := os.Create(*jsonOut)
			if err == nil {
				err = export.WriteJSON(f, rep)
				f.Close()
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "json:", err)
				os.Exit(1)
			}
			fmt.Println("wrote", *jsonOut)
		}
		if *xlsxOut != "" {
			if err := export.WriteXLSX(*xlsxOut, rep); err != nil {
				fmt.Fprintln(os.Stderr, "xlsx:", err)
				os.Exit(1)
			}
			fmt.Println("wrote", *xlsxOut)
		}
		if *jsonOut == "-" {
			return
		}
	}
	fmt.Printf("\n%d findings", len(fs))
	if *area != "" {
		fmt.Printf(" (showing area %q)", *area)
	}
	fmt.Println(":")
	for _, f := range fs {
		if *area != "" && f.Area != *area {
			continue
		}
		fmt.Printf("  %-5s %-8s %-20s %s\n", f.Severity, f.Area, f.Object, f.Message)
		if f.Hint != "" {
			fmt.Printf("        hint: %s\n", f.Hint)
		}
	}
}
