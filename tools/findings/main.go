// Command findings runs one khealth collection cycle headlessly (API snapshot,
// node probe with the config tier - the heavy tiers too with -heavy: journal,
// images, the registry pull dry run - full etcd probe on etcd nodes) and prints
// the findings the TUI would show, plus each etcd node's newest snapshot and
// backup hints. Meant for scripted verification, e.g. after configuring etcd
// backups. -json / -xlsx write the same report the TUI exports with `e`
// (-stig adds the STIG/CIS scan: the API-side rules plus the OS STIG facts
// collected over SSH, one sheet per benchmark). `khealth --export` does the
// same from the main binary.
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
	"time"

	"k8s.io/klog/v2"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/export"
	"k8s-health-tui/internal/headless"
)

func main() {
	bf := flag.NewFlagSet("findings", flag.ExitOnError)
	area := bf.String("area", "", "only print findings of this area (etcd, node, ...)")
	heavy := bf.Bool("heavy", false, "run the heavy node tiers too (journal, images, registry pull dry run)")
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

	res, err := headless.Run(context.Background(), cfg, headless.Options{Heavy: *heavy, Scan: *withStig, Log: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	quiet := *jsonOut == "-"
	if !quiet {
		fmt.Printf("cluster %s: %d nodes, distribution %q\n", res.Client.Host, len(res.Snap.Nodes), res.Snap.Distribution)
		for name, p := range res.Input.Etcd {
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
	}

	if *jsonOut != "" || *xlsxOut != "" {
		rep := export.Build(export.Input{Snap: res.Snap, Nodes: res.Input.Nodes, Findings: res.Findings, Stig: res.Stig, StigRun: *withStig, Context: res.Client.Context, Server: res.Client.Host, Version: config.Version, Now: time.Now()})
		if quiet {
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
			if !quiet {
				fmt.Println("wrote", *xlsxOut)
			}
		}
		if quiet {
			return
		}
	}
	fmt.Printf("\n%d findings", len(res.Findings))
	if *area != "" {
		fmt.Printf(" (showing area %q)", *area)
	}
	fmt.Println(":")
	for _, f := range res.Findings {
		if *area != "" && f.Area != *area {
			continue
		}
		fmt.Printf("  %-5s %-8s %-20s %s\n", f.Severity, f.Area, f.Object, f.Message)
		if f.Hint != "" {
			fmt.Printf("        hint: %s\n", f.Hint)
		}
	}
}
