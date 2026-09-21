// Package headless runs one khealth collection cycle without the TUI: the
// API snapshot, the node probes over SSH (config tier, optionally the heavy
// tiers and the OS STIG facts), the etcd probes on etcd nodes, then the
// checks and, when asked, the STIG/CIS rules. `khealth --export` and
// tools/findings are built on it.
package headless

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/stig"
)

// Options select what one cycle collects.
type Options struct {
	Heavy bool      // journal, image inventories, PV du, registry pull dry run
	Scan  bool      // the security scan: STIG/CIS rules from the API data and the OS STIG facts over SSH
	Log   io.Writer // probe errors (nil: discarded)
}

// Result is what one cycle produced.
type Result struct {
	Client   *k8s.Client
	Snap     *k8s.Snapshot
	Input    checks.Input
	Findings []checks.Finding
	Stig     []stig.Result // nil unless Options.Scan
}

// Run performs the cycle.
func Run(ctx context.Context, cfg config.Config, o Options) (*Result, error) {
	log := o.Log
	if log == nil {
		log = io.Discard
	}
	opts := k8s.Options{WatchCache: cfg.Perf.WatchCache, Protobuf: cfg.Perf.Protobuf, DiscoveryTTL: cfg.Perf.DiscoveryTTL, ConfigzTTL: cfg.Perf.ConfigzTTL, DeniedTTL: cfg.Perf.DeniedTTL}
	client, err := k8s.NewWithOptions(cfg.Kubeconfig, cfg.Context, opts)
	if err != nil {
		return nil, err
	}
	snap := client.Fetch(ctx)
	res := &Result{Client: client, Snap: snap}
	in := checks.Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{}, Etcd: map[string]*etcd.Probe{}, Cfg: cfg, Now: time.Now(), APIServer: client.Host, SSHEnabled: cfg.SSH.Enabled}
	if cfg.SSH.Enabled {
		runner, err := sshrun.New(cfg.SSH)
		if err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		}
		defer runner.Close()
		var wg sync.WaitGroup
		var mu sync.Mutex
		base := nodeinfo.Options{LogLines: cfg.Logs.Lines, LogSince: cfg.Logs.Since, Config: true, Journal: o.Heavy, Images: o.Heavy, PVs: o.Heavy, OSStig: o.Scan, CPUSample: true}
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
				r := runner.Run(c, host, nodeinfo.Script(withNetTargets(base, snap, name)))
				if r.Err != nil && !strings.Contains(r.Stdout, "===END") {
					fmt.Fprintf(log, "node probe %s: %v %s\n", name, r.Err, r.Stderr)
				}
				info := nodeinfo.Parse(name, host, r.Stdout, r.Started)
				info.HostKey = r.HostKey
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
					r := runner.Run(c, host, etcd.Script(cfg.Etcd, true, true))
					if r.Err != nil && !strings.Contains(r.Stdout, "===END") {
						fmt.Fprintf(log, "etcd probe %s: %v %s\n", name, r.Err, r.Stderr)
					}
					p := etcd.Parse(name, r.Stdout)
					mu.Lock()
					in.Etcd[name] = p
					mu.Unlock()
				}(n.Name, host)
			}
		}
		wg.Wait()
	}
	if o.Scan {
		res.Stig = stig.Evaluate(stig.Input{Snap: snap, Nodes: in.Nodes, Etcd: in.Etcd})
		in.Stig = res.Stig
	}
	res.Input = in
	res.Findings = checks.Evaluate(in)
	return res, nil
}

// withNetTargets adds the CNI probe targets of a node (one pod on every
// other node, the CoreDNS pods, the DNS and API service IPs) as the TUI does.
func withNetTargets(o nodeinfo.Options, snap *k8s.Snapshot, node string) nodeinfo.Options {
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
