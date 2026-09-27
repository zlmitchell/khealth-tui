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
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/stig"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// Options select what one cycle collects.
type Options struct {
	Heavy bool      // journal, image inventories, PV du, registry pull dry run
	Scan  bool      // the security scan: STIG/CIS rules from the API data and the OS STIG facts over SSH
	Log   io.Writer // probe errors (nil: discarded)
	// Runner is the SSH runner to use; nil creates one for the cycle (and
	// closes it). A caller that goes on using SSH passes its own.
	Runner *sshrun.Runner
	// Raw, when set, receives every probe's output as it came off the node
	// ("node" or "etcd"), before parsing: the log bundle keeps it so the
	// findings can be computed again from the bundle alone.
	Raw func(kind string, t Target, r sshrun.Result)
}

// Result is what one cycle produced.
type Result struct {
	Client   *k8s.Client
	Snap     *k8s.Snapshot
	Input    checks.Input
	Findings []checks.Finding
	Stig     []stig.Result // nil unless Options.Scan
	Targets  []Target      // the nodes probed over SSH
	Offline  bool          // the API listed no nodes: Targets came from ssh.hosts
}

// Target is one node to reach over SSH.
type Target struct {
	Name, Host   string
	Etcd         bool // gets the etcd probe (every target when the API is down: roles are unknown)
	ControlPlane bool
}

// Targets lists the nodes to probe: the API's node list, or, when it
// returned none (apiserver or etcd down), the ssh.hosts map, as the TUI
// falls back to it. ssh.nodes narrows either list.
func Targets(cfg config.Config, snap *k8s.Snapshot) ([]Target, bool) {
	want := map[string]bool{}
	for _, n := range cfg.SSH.Nodes {
		want[n] = true
	}
	keep := func(name string) bool { return len(want) == 0 || want[name] }
	var out []Target
	if len(snap.Nodes) > 0 {
		for i := range snap.Nodes {
			n := &snap.Nodes[i]
			if !keep(n.Name) {
				continue
			}
			host := cfg.SSH.Hosts[n.Name]
			if host == "" {
				host = k8s.NodeAddress(n, cfg.SSH.Address)
			}
			out = append(out, Target{Name: n.Name, Host: host, Etcd: k8s.IsEtcdNode(snap.Nodes, n), ControlPlane: k8s.IsControlPlane(n)})
		}
		return out, false
	}
	for _, name := range strutil.SortedKeys(cfg.SSH.Hosts) {
		if keep(name) {
			out = append(out, Target{Name: name, Host: cfg.SSH.Hosts[name], Etcd: true, ControlPlane: true})
		}
	}
	return out, true
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
	in := checks.Input{Snap: snap, Nodes: map[string]*nodeinfo.Info{}, Etcd: map[string]*etcd.Probe{}, Logs: map[string]*logs.Summary{}, Cfg: cfg, Now: time.Now(), APIServer: client.Host, SSHEnabled: cfg.SSH.Enabled}
	if cfg.SSH.Enabled {
		runner := o.Runner
		if runner == nil {
			runner, err = sshrun.New(cfg.SSH)
			if err != nil {
				return nil, fmt.Errorf("ssh: %w", err)
			}
			defer runner.Close()
		}
		raw := o.Raw
		if raw == nil {
			raw = func(string, Target, sshrun.Result) {}
		}
		res.Targets, res.Offline = Targets(cfg, snap)
		var wg sync.WaitGroup
		var mu sync.Mutex
		base := nodeinfo.Options{LogLines: cfg.Logs.Lines, LogSince: cfg.Logs.Since, Config: true, Journal: o.Heavy, Images: o.Heavy, PVs: o.Heavy, OSStig: o.Scan, CPUSample: true}
		for _, t := range res.Targets {
			wg.Add(1)
			go func(t Target) {
				defer wg.Done()
				c, cancel := context.WithTimeout(ctx, 3*cfg.SSH.Timeout)
				defer cancel()
				r := runner.Run(c, t.Host, nodeinfo.Script(withNetTargets(base, snap, t.Name)))
				raw("node", t, r)
				if r.Err != nil && !strings.Contains(r.Stdout, "===END") {
					fmt.Fprintf(log, "node probe %s: %v %s\n", t.Name, r.Err, r.Stderr)
				}
				info := nodeinfo.Parse(t.Name, t.Host, r.Stdout, r.Started)
				info.HostKey = r.HostKey
				ls := info.ClassifyLogs(in.Now)
				mu.Lock()
				in.Nodes[t.Name] = info
				if ls != nil {
					in.Logs[t.Name] = ls
				}
				mu.Unlock()
			}(t)
			if t.Etcd {
				wg.Add(1)
				go func(t Target) {
					defer wg.Done()
					c, cancel := context.WithTimeout(ctx, 3*cfg.SSH.Timeout)
					defer cancel()
					r := runner.Run(c, t.Host, etcd.Script(cfg.Etcd, true, true))
					raw("etcd", t, r)
					if r.Err != nil && !strings.Contains(r.Stdout, "===END") {
						fmt.Fprintf(log, "etcd probe %s: %v %s\n", t.Name, r.Err, r.Stderr)
					}
					p := etcd.Parse(t.Name, r.Stdout)
					mu.Lock()
					in.Etcd[t.Name] = p
					mu.Unlock()
				}(t)
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
