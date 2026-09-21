// Command perfbench measures what khealth costs the systems it inspects,
// without the TUI: the API server (requests, bytes, wall time per refresh),
// every node (wall time, remote CPU seconds and output bytes of the light,
// heavy, OS STIG and etcd probes) and this host (CPU seconds, heap). With
// -monitor it also samples CPU and load on each node over a second SSH
// session, before the probes start (baseline) and while they run, so the
// tool's share of the node can be read off directly.
//
// Usage:
//
//	perfbench [bench flags] -- [khealth flags]
//	perfbench -cycles 5 -monitor -- --kubeconfig ~/.kube/config --ssh-user ubuntu
//	perfbench -cycles 3 -api-compare -- --context prod
//	perfbench -cycles 5 -- --no-nice          # A/B: renice/ionice off
//
// docs/PERFORMANCE.md explains the numbers.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"k8s.io/klog/v2"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/perf"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

type probeResult struct {
	Node   string          `json:"node"`
	Kind   string          `json:"kind"`
	Cycle  int             `json:"cycle"`
	Wall   time.Duration   `json:"wall_ns"`
	Cost   perf.RemoteCost `json:"cost"`
	Out    int             `json:"out_bytes"`
	Script int             `json:"script_bytes"`
	Err    string          `json:"err,omitempty"`
}

type apiResult struct {
	Label    string        `json:"label"`
	Cycle    int           `json:"cycle"`
	Wall     time.Duration `json:"wall_ns"`
	Traffic  k8s.Stats     `json:"traffic"`
	Pods     int           `json:"pods"`
	Nodes    int           `json:"nodes"`
	Errors   []string      `json:"errors,omitempty"`
	LocalCPU float64       `json:"local_cpu_s"`
}

type monitorSample struct {
	At   time.Time
	CPU  float64 // % busy over the previous second (-1 for the first sample)
	Load float64
}

type report struct {
	Cluster   string                    `json:"cluster"`
	Nodes     int                       `json:"nodes"`
	Refresh   time.Duration             `json:"refresh_ns"`
	Options   k8s.Options               `json:"api_options"`
	Nice      bool                      `json:"ssh_nice"`
	API       []apiResult               `json:"api"`
	Probes    []probeResult             `json:"probes"`
	Monitor   map[string]monitorSummary `json:"monitor,omitempty"`
	LocalCPUS float64                   `json:"local_cpu_s"`
	LocalHeap uint64                    `json:"local_heap_bytes"`
	Started   time.Time                 `json:"started"`
	Finished  time.Time                 `json:"finished"`
}

type monitorSummary struct {
	BaselineCPU  float64 `json:"baseline_cpu_pct"`
	ActiveCPU    float64 `json:"active_cpu_pct"`
	BaselineLoad float64 `json:"baseline_load1"`
	ActiveLoad   float64 `json:"active_load1"`
	PeakCPU      float64 `json:"peak_cpu_pct"`
	Samples      int     `json:"samples"`
}

func main() {
	bf := flag.NewFlagSet("perfbench", flag.ExitOnError)
	cycles := bf.Int("cycles", 3, "number of light cycles to run")
	interval := bf.Duration("interval", 0, "pause between cycles (0 = back to back; the report still uses the configured refresh for %-of-core)")
	heavy := bf.Bool("heavy", true, "run one heavy cycle (journal, images, tarballs) as cycle 1")
	stig := bf.Bool("stig", true, "include the OS STIG facts in cycle 1 (first-contact cost)")
	doEtcd := bf.Bool("etcd", true, "run the etcd probe on control-plane nodes each cycle")
	monitor := bf.Bool("monitor", false, "sample CPU/load on every node over a second SSH session (baseline before, then during)")
	baseline := bf.Duration("baseline", 10*time.Second, "with -monitor: idle sampling time before the probes start")
	apiCompare := bf.Bool("api-compare", false, "also fetch the API snapshot with watch-cache and protobuf off, for comparison")
	noSSH := bf.Bool("no-ssh", false, "API only")
	jsonOut := bf.String("json", "", "write the full report as JSON to this file")
	bf.Usage = func() {
		fmt.Fprintf(bf.Output(), "Usage: perfbench [bench flags] -- [khealth flags]\n\n")
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
	rep := &report{Cluster: client.Host, Refresh: cfg.Refresh, Options: opts, Nice: cfg.SSH.Nice, Started: time.Now()}
	start := perf.SampleLocal()
	ctx := context.Background()

	fmt.Printf("perfbench: %s, refresh %s, watch-cache=%v protobuf=%v ssh nice=%v\n\n", client.Host, cfg.Refresh, opts.WatchCache, opts.Protobuf, cfg.SSH.Nice)

	// --- API server -------------------------------------------------------
	var snap *k8s.Snapshot
	fmt.Println("API snapshot (all lists of one refresh):")
	for i := 1; i <= *cycles; i++ {
		r, s := fetchOnce(ctx, client, "configured", i)
		rep.API = append(rep.API, r)
		printAPI(r)
		if i == 1 {
			snap = s
		}
	}
	if *apiCompare {
		plain, err := k8s.NewWithOptions(cfg.Kubeconfig, cfg.Context, k8s.Options{})
		if err == nil {
			for i := 1; i <= *cycles; i++ {
				r, _ := fetchOnce(ctx, plain, "quorum+json", i)
				rep.API = append(rep.API, r)
				printAPI(r)
			}
		}
	}
	if snap == nil || len(snap.Nodes) == 0 {
		fmt.Println("no nodes from the API; SSH phase skipped")
		finish(rep, start, *jsonOut)
		return
	}
	rep.Nodes = len(snap.Nodes)
	if !cfg.SSH.Enabled || *noSSH {
		finish(rep, start, *jsonOut)
		return
	}

	// --- nodes ------------------------------------------------------------
	runner, err := sshrun.New(cfg.SSH)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ssh:", err)
		finish(rep, start, *jsonOut)
		return
	}
	defer runner.Close()
	type target struct {
		name, host string
		etcd       bool
	}
	var targets []target
	only := map[string]bool{}
	for _, n := range cfg.SSH.Nodes {
		only[n] = true
	}
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if len(only) > 0 && !only[n.Name] {
			continue
		}
		host := cfg.SSH.Hosts[n.Name]
		if host == "" {
			host = k8s.NodeAddress(n, cfg.SSH.Address)
		}
		targets = append(targets, target{name: n.Name, host: host, etcd: *doEtcd && k8s.IsEtcdNode(snap.Nodes, n)})
	}

	// node monitors: their own runner so they never take a probe slot
	var monRunner *sshrun.Runner
	monCtx, monCancel := context.WithCancel(ctx)
	monOut := map[string]*sshrun.Result{}
	var monWG sync.WaitGroup
	var monMu sync.Mutex
	var probesStart time.Time
	if *monitor {
		mcfg := cfg.SSH
		mcfg.Concurrency = len(targets) + 1
		mcfg.Nice = false
		monRunner, err = sshrun.New(mcfg)
		if err == nil {
			fmt.Printf("\nmonitoring %d nodes (1 sample/s), %s baseline first...\n", len(targets), *baseline)
			for _, t := range targets {
				t := t
				monWG.Add(1)
				go func() {
					defer monWG.Done()
					res := monRunner.Run(monCtx, t.host, monitorScript)
					monMu.Lock()
					monOut[t.name] = &res
					monMu.Unlock()
				}()
			}
			time.Sleep(*baseline)
		}
	}
	probesStart = time.Now()

	var pvPaths []string
	for i := range snap.PVs {
		pv := &snap.PVs[i]
		if pv.Spec.HostPath != nil {
			pvPaths = append(pvPaths, pv.Spec.HostPath.Path)
		} else if pv.Spec.Local != nil {
			pvPaths = append(pvPaths, pv.Spec.Local.Path)
		}
	}
	known := map[string][]string{}
	fmt.Printf("\nSSH probes on %d nodes, %d cycles (cycle 1: heavy=%v stig=%v):\n", len(targets), *cycles, *heavy, *stig)
	for cyc := 1; cyc <= *cycles; cyc++ {
		if cyc > 1 && *interval > 0 {
			time.Sleep(*interval)
		}
		o := nodeinfo.Options{LogLines: cfg.Logs.Lines, LogSince: cfg.Logs.Since, PVPaths: pvPaths, Journal: cyc == 1 && *heavy, Images: cyc == 1 && *heavy, PVs: cyc == 1 && *heavy, OSStig: cyc == 1 && *stig, Config: cyc == 1, CPUSample: cyc == 1}
		kind := "node"
		if o.Heavy() {
			kind += "+heavy"
		} else if o.Config {
			kind += "+config"
		}
		if o.OSStig {
			kind += "+stig"
		}
		timeout := 3 * cfg.SSH.Timeout
		if o.Heavy() {
			timeout = 6 * cfg.SSH.Timeout
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		cycStart := perf.SampleLocal()
		t0 := time.Now()
		for _, t := range targets {
			t := t
			opts := o
			opts.KnownTarballs = known[t.name]
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				res := runner.Run(c, t.host, nodeinfo.Script(opts))
				info := nodeinfo.Parse(t.name, t.host, res.Stdout, res.Started)
				pr := probeResult{Node: t.name, Kind: kind, Cycle: cyc, Wall: res.Finished.Sub(res.Started), Cost: info.Cost, Out: len(res.Stdout), Script: res.ScriptSize}
				if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
					pr.Err = strutil.FirstLine(res.Err.Error() + " " + res.Stderr)
				}
				mu.Lock()
				rep.Probes = append(rep.Probes, pr)
				known[t.name] = info.TarballKeys()
				mu.Unlock()
			}()
			if t.etcd {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, cancel := context.WithTimeout(ctx, timeout)
					defer cancel()
					res := runner.Run(c, t.host, etcd.Script(cfg.Etcd, o.Heavy(), o.Heavy()))
					p := etcd.Parse(t.name, res.Stdout)
					pr := probeResult{Node: t.name, Kind: "etcd", Cycle: cyc, Wall: res.Finished.Sub(res.Started), Cost: p.Cost, Out: len(res.Stdout), Script: res.ScriptSize}
					if res.Err != nil && !strings.Contains(res.Stdout, "===END") {
						pr.Err = strutil.FirstLine(res.Err.Error() + " " + res.Stderr)
					}
					mu.Lock()
					rep.Probes = append(rep.Probes, pr)
					mu.Unlock()
				}()
			}
		}
		wg.Wait()
		cycEnd := perf.SampleLocal()
		fmt.Printf("  cycle %d (%s): %s wall, local cpu %.2fs\n", cyc, kind, time.Since(t0).Round(10*time.Millisecond), cycEnd.CPUSeconds-cycStart.CPUSeconds)
	}
	probesEnd := time.Now()
	if *monitor && monRunner != nil {
		time.Sleep(2 * time.Second) // let the last samples land
		monCancel()
		monWG.Wait()
		monRunner.Close()
		rep.Monitor = map[string]monitorSummary{}
		for node, res := range monOut {
			rep.Monitor[node] = summarizeMonitor(parseMonitor(res.Stdout), probesStart, probesEnd)
		}
	} else {
		monCancel()
	}

	printProbes(rep, cfg.Refresh)
	if rep.Monitor != nil {
		printMonitor(rep)
	}
	finish(rep, start, *jsonOut)
}

func fetchOnce(ctx context.Context, c *k8s.Client, label string, cycle int) (apiResult, *k8s.Snapshot) {
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	l0 := perf.SampleLocal()
	s := c.Fetch(cctx)
	l1 := perf.SampleLocal()
	return apiResult{Label: label, Cycle: cycle, Wall: s.FetchDuration, Traffic: s.Traffic, Pods: len(s.Pods), Nodes: len(s.Nodes), Errors: s.Errors, LocalCPU: l1.CPUSeconds - l0.CPUSeconds}, s
}

func printAPI(r apiResult) {
	fmt.Printf("  %-12s cycle %d: %6s  %3d requests  %9s in  %7s out  local cpu %.2fs  (%d pods, %d nodes, %d errors)\n",
		r.Label, r.Cycle, r.Wall.Round(10*time.Millisecond), r.Traffic.Requests, strutil.HumanBytes(float64(r.Traffic.BytesIn)), strutil.HumanBytes(float64(r.Traffic.BytesOut)), r.LocalCPU, r.Pods, r.Nodes, len(r.Errors))
	for _, e := range r.Errors {
		fmt.Printf("               error: %s\n", e)
	}
}

func printProbes(rep *report, refresh time.Duration) {
	type agg struct {
		n        int
		wall     time.Duration
		cpu, out float64
		maxCPU   float64
		errs     int
		unparsed int
	}
	byKey := map[string]*agg{}
	var keys []string
	for _, p := range rep.Probes {
		k := p.Node + "\x00" + p.Kind
		a := byKey[k]
		if a == nil {
			a = &agg{}
			byKey[k] = a
			keys = append(keys, k)
		}
		a.n++
		a.wall += p.Wall
		a.cpu += p.Cost.CPU()
		a.out += float64(p.Out)
		if p.Cost.CPU() > a.maxCPU {
			a.maxCPU = p.Cost.CPU()
		}
		if p.Err != "" {
			a.errs++
		}
		if !p.Cost.Parsed {
			a.unparsed++
		}
	}
	sort.Strings(keys)
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tPROBE\tRUNS\tAVG WALL\tAVG REMOTE CPU\tMAX\t% OF ONE CORE @refresh\tAVG OUTPUT\tERRORS")
	for _, k := range keys {
		node, kind, _ := strings.Cut(k, "\x00")
		a := byKey[k]
		n := float64(a.n)
		cpuS := fmt.Sprintf("%.2fs", a.cpu/n)
		pct := fmt.Sprintf("%.2f%%", a.cpu/n/refresh.Seconds()*100)
		if a.unparsed == a.n {
			cpuS, pct = "n/a", "n/a"
		}
		note := ""
		if a.errs > 0 {
			note = strconv.Itoa(a.errs)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%.2fs\t%s\t%s\t%s\n", node, kind, a.n, (a.wall / time.Duration(a.n)).Round(10*time.Millisecond), cpuS, a.maxCPU, pct, strutil.HumanBytes(float64(a.out/n)), note)
	}
	tw.Flush()
	fmt.Println("\n% of one core = remote CPU seconds per probe / refresh interval: the steady-state share of a single core the probe takes on that node.")
	fmt.Println("node+heavy / node+stig are the expensive first-contact / R cycles; 'node' and 'etcd' are what every refresh costs.")
}

// monitorScript samples /proc/stat and /proc/loadavg once per second until
// the session is killed.
const monitorScript = `export LC_ALL=C
while :; do
  echo "T $(date +%s) $(head -1 /proc/stat) L $(cut -d' ' -f1 /proc/loadavg)"
  sleep 1
done
`

func parseMonitor(out string) []monitorSample {
	var samples []monitorSample
	var prevBusy, prevTotal float64
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		// T <ts> cpu user nice system idle iowait irq softirq steal ... L <load1>
		if len(f) < 12 || f[0] != "T" || f[2] != "cpu" {
			continue
		}
		ts, _ := strconv.ParseInt(f[1], 10, 64)
		var vals []float64
		for _, x := range f[3:] {
			if x == "L" {
				break
			}
			v, err := strconv.ParseFloat(x, 64)
			if err != nil {
				break
			}
			vals = append(vals, v)
		}
		if len(vals) < 5 {
			continue
		}
		var total float64
		for _, v := range vals {
			total += v
		}
		idle := vals[3]
		if len(vals) > 4 {
			idle += vals[4] // iowait counts as idle for "busy"
		}
		busy := total - idle
		s := monitorSample{At: time.Unix(ts, 0), CPU: -1}
		if prevTotal > 0 && total > prevTotal {
			s.CPU = (busy - prevBusy) / (total - prevTotal) * 100
		}
		if i := strings.LastIndex(l, " L "); i >= 0 {
			s.Load, _ = strconv.ParseFloat(strings.TrimSpace(l[i+3:]), 64)
		}
		prevBusy, prevTotal = busy, total
		samples = append(samples, s)
	}
	return samples
}

func summarizeMonitor(samples []monitorSample, activeFrom, activeTo time.Time) monitorSummary {
	var m monitorSummary
	var bCPU, bLoad, aCPU, aLoad float64
	var bn, an int
	for _, s := range samples {
		if s.CPU < 0 {
			continue
		}
		m.Samples++
		if s.At.Before(activeFrom) {
			bCPU += s.CPU
			bLoad += s.Load
			bn++
		} else if !s.At.After(activeTo.Add(time.Second)) {
			aCPU += s.CPU
			aLoad += s.Load
			an++
			if s.CPU > m.PeakCPU {
				m.PeakCPU = s.CPU
			}
		}
	}
	if bn > 0 {
		m.BaselineCPU, m.BaselineLoad = bCPU/float64(bn), bLoad/float64(bn)
	}
	if an > 0 {
		m.ActiveCPU, m.ActiveLoad = aCPU/float64(an), aLoad/float64(an)
	}
	return m
}

func printMonitor(rep *report) {
	fmt.Println("\nNode CPU sampled independently (1/s over a separate SSH session), baseline = before the probes started:")
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE\tBASELINE CPU%\tDURING CPU%\tDELTA\tPEAK 1s\tLOAD1 BEFORE/DURING\tSAMPLES")
	nodes := make([]string, 0, len(rep.Monitor))
	for n := range rep.Monitor {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		m := rep.Monitor[n]
		fmt.Fprintf(tw, "%s\t%.1f\t%.1f\t%+.1f\t%.1f\t%.2f / %.2f\t%d\n", n, m.BaselineCPU, m.ActiveCPU, m.ActiveCPU-m.BaselineCPU, m.PeakCPU, m.BaselineLoad, m.ActiveLoad, m.Samples)
	}
	tw.Flush()
	fmt.Println("CPU% is of the whole node (all cores); DELTA is the probe's cost while it runs back to back, not the steady-state share.")
}

func finish(rep *report, start perf.Local, jsonOut string) {
	end := perf.SampleLocal()
	rep.LocalCPUS = end.CPUSeconds - start.CPUSeconds
	rep.LocalHeap = end.HeapBytes
	rep.Finished = time.Now()
	fmt.Printf("\nthis host: %.2fs CPU total, heap %s, %s elapsed\n", rep.LocalCPUS, strutil.HumanBytes(float64(rep.LocalHeap)), rep.Finished.Sub(rep.Started).Round(time.Second))
	if jsonOut != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(jsonOut, b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write json:", err)
		} else {
			fmt.Println("report written to", jsonOut)
		}
	}
}
