package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/perf"
)

// footprint tracks what khealth itself costs the cluster and this machine
// per refresh cycle (docs/PERFORMANCE.md): API traffic of the snapshot,
// wall/remote CPU/bytes of every SSH probe, local CPU/heap and the recompute
// work. One record per cycle goes to the perf log (--perf-log) and the last
// few are shown by the P overlay.
type footprint struct {
	logger *perf.Logger
	cur    *perf.CycleRecord
	hist   []perf.CycleRecord // finished cycles, oldest first (perfHistory max)
	local  perf.Local         // sample at the start of the current cycle

	skipUntil map[string]int // node -> cycle number until which probes are skipped (backoff)
	skips     map[string]int // node -> probes skipped so far (still running / backoff)

	recomputeTimer bool // a coalesced recompute is scheduled
}

const (
	perfHistory    = 20
	recomputeDelay = 250 * time.Millisecond
)

type recomputeMsg struct{}

func newFootprint() footprint {
	return footprint{skipUntil: map[string]int{}, skips: map[string]int{}}
}

// beginCycle closes the record of the previous cycle and opens the next one
// with the API cost of the snapshot that just landed.
func (a *App) beginCycle(heavy bool) {
	a.endCycle()
	f := &a.fp
	f.local = perf.SampleLocal()
	rec := &perf.CycleRecord{Cycle: a.cycle, At: time.Now(), Heavy: heavy}
	if s := a.snap; s != nil {
		rec.API = perf.APIRecord{
			FetchMS: s.FetchDuration.Milliseconds(), Requests: s.Traffic.Requests, BytesIn: s.Traffic.BytesIn,
			BytesOut: s.Traffic.BytesOut, Errors: len(s.Errors), Pods: len(s.Pods), Nodes: len(s.Nodes), Events: len(s.Events),
		}
	}
	f.cur = rec
}

// endCycle finalises the current record (local CPU delta, heap) and appends
// it to the history and the log.
func (a *App) endCycle() {
	f := &a.fp
	if f.cur == nil {
		return
	}
	now := perf.SampleLocal()
	f.cur.LocalCPUS = now.CPUSeconds - f.local.CPUSeconds
	f.cur.LocalHeap, f.cur.LocalSys, f.cur.Goroutines = now.HeapBytes, now.SysBytes, now.Goroutines
	sort.Slice(f.cur.Probes, func(i, j int) bool {
		if f.cur.Probes[i].Node != f.cur.Probes[j].Node {
			return f.cur.Probes[i].Node < f.cur.Probes[j].Node
		}
		return f.cur.Probes[i].Kind < f.cur.Probes[j].Kind
	})
	f.hist = append(f.hist, *f.cur)
	if len(f.hist) > perfHistory {
		f.hist = f.hist[len(f.hist)-perfHistory:]
	}
	f.logger.Write(*f.cur)
	f.cur = nil
}

func (a *App) addProbe(p perf.ProbeRecord) {
	if a.fp.cur == nil {
		return
	}
	a.fp.cur.Probes = append(a.fp.cur.Probes, p)
}

func (a *App) recordNodeProbe(info *nodeinfo.Info, opts nodeinfo.Options) {
	kind := "node"
	if opts.Heavy {
		kind += "+heavy"
	}
	if opts.OSStig {
		kind += "+stig"
	}
	if opts.Config && !opts.Heavy {
		kind += "+config"
	}
	p := perf.ProbeRecord{Node: info.Node, Kind: kind, WallMS: info.Duration.Milliseconds(), RemoteCPU: info.Cost.CPU(),
		RemoteUser: info.Cost.User, RemoteSys: info.Cost.Sys, Load1: info.Cost.Load1, OutBytes: info.OutBytes, ScriptSize: info.ScriptSize}
	if info.Err != nil {
		p.Err = info.Err.Error()
	}
	a.addProbe(p)
}

func (a *App) recordEtcdProbe(pr *etcd.Probe) {
	p := perf.ProbeRecord{Node: pr.Node, Kind: "etcd", WallMS: pr.Duration.Milliseconds(), RemoteCPU: pr.Cost.CPU(),
		RemoteUser: pr.Cost.User, RemoteSys: pr.Cost.Sys, Load1: pr.Cost.Load1, OutBytes: pr.OutBytes, ScriptSize: pr.ScriptSize}
	if pr.Err != nil {
		p.Err = pr.Err.Error()
	}
	a.addProbe(p)
}

// skipProbe decides whether this cycle's probes for a node are skipped:
// the previous probe is still running (never stack sessions on a slow
// node) or the node is in backoff. Returns the reason, "" to run.
func (a *App) skipProbe(name string) string {
	reason := ""
	switch {
	case a.pending[name] || a.etcdPend[name]:
		reason = "previous probe still running"
	case a.cfg.SSH.Backoff && a.fp.skipUntil[name] > a.cycle:
		reason = "backoff: last probe took longer than half the refresh interval"
	}
	if reason != "" {
		a.fp.skips[name]++
		a.addProbe(perf.ProbeRecord{Node: name, Kind: "node", Skipped: reason})
	}
	return reason
}

// noteProbeDuration arms the backoff when a probe took longer than half
// the interval: the node (or the path to it) is slow, so the next cycle is
// skipped rather than adding a second session on top of a struggling host.
func (a *App) noteProbeDuration(name string, d time.Duration) {
	if a.cfg.SSH.Backoff && d > a.cfg.Refresh/2 {
		a.fp.skipUntil[name] = a.cycle + 2 // the cycle counter advances before collectCmds runs
	}
}

// scheduleRecompute coalesces the recompute (STIG + checks over every node)
// that each node/etcd message would otherwise trigger: with N nodes
// answering within a second that is N full evaluations, so they are merged
// into one a short delay later.
func (a *App) scheduleRecompute() tea.Cmd {
	if a.fp.recomputeTimer {
		return nil
	}
	a.fp.recomputeTimer = true
	return tea.Tick(recomputeDelay, func(time.Time) tea.Msg { return recomputeMsg{} })
}

// timedRecompute runs recompute and accounts it to the current cycle.
func (a *App) timedRecompute() {
	t := time.Now()
	a.recompute()
	if a.fp.cur != nil {
		a.fp.cur.Recomputes++
		a.fp.cur.RecomputeMS += time.Since(t).Milliseconds()
	}
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func fmtSecs(s float64) string {
	if s < 0 {
		return "-"
	}
	return fmt.Sprintf("%.2fs", s)
}

// perfLines renders the footprint overlay (P).
func (a *App) perfLines() []string {
	f := &a.fp
	var out []string
	refresh := a.cfg.Refresh.Seconds()
	out = append(out, fmt.Sprintf("Refresh %s, heavy every %d cycles, ssh nice=%v backoff=%v, api watch-cache=%v protobuf=%v",
		a.cfg.Refresh, a.cfg.HeavyEvery, a.cfg.SSH.Nice, a.cfg.SSH.Backoff, a.cfg.Perf.WatchCache, a.cfg.Perf.Protobuf))
	if a.cfg.Perf.Log != "" {
		out = append(out, "perf log: "+a.cfg.Perf.Log)
	}
	out = append(out, "")
	recs := f.hist
	if f.cur != nil {
		recs = append(append([]perf.CycleRecord{}, recs...), *f.cur)
	}
	if len(recs) == 0 {
		return append(out, "no completed refresh yet")
	}
	last := recs[len(recs)-1]
	if f.cur != nil {
		now := perf.SampleLocal()
		last.LocalCPUS = now.CPUSeconds - f.local.CPUSeconds
		last.LocalHeap, last.LocalSys, last.Goroutines = now.HeapBytes, now.SysBytes, now.Goroutines
	}

	// averages over the history
	n := float64(len(recs))
	var apiMS, apiReq, apiIn, cpu float64
	remote := map[string][]float64{} // node -> remote CPU seconds per cycle
	for _, r := range recs {
		apiMS += float64(r.API.FetchMS)
		apiReq += float64(r.API.Requests)
		apiIn += float64(r.API.BytesIn)
		cpu += r.LocalCPUS
		per := map[string]float64{}
		for _, p := range r.Probes {
			per[p.Node] += p.RemoteCPU
		}
		for node, v := range per {
			remote[node] = append(remote[node], v)
		}
	}
	out = append(out, fmt.Sprintf("API server   last cycle: %d requests, %s in, %s out, fetch %s   (avg over %d cycles: %.0f req, %s, %.1fs)",
		last.API.Requests, fmtBytes(last.API.BytesIn), fmtBytes(last.API.BytesOut), time.Duration(last.API.FetchMS)*time.Millisecond,
		len(recs), apiReq/n, fmtBytes(int64(apiIn/n)), apiMS/n/1000))
	out = append(out, fmt.Sprintf("             %d pods, %d nodes, %d events per snapshot; %d list errors", last.API.Pods, last.API.Nodes, last.API.Events, last.API.Errors))
	out = append(out, fmt.Sprintf("This host    CPU %s per cycle (%.1f%% of one core at %.0fs refresh), heap %s, rss-ish %s, %d goroutines, recompute %dx %dms",
		fmtSecs(last.LocalCPUS), cpu/n/refresh*100, refresh, fmtBytes(int64(last.LocalHeap)), fmtBytes(int64(last.LocalSys)), last.Goroutines, last.Recomputes, last.RecomputeMS))
	out = append(out, "")
	out = append(out, "Nodes, last cycle (remote CPU = user+sys seconds the probe and everything it ran consumed on the node)")
	out = append(out, fmt.Sprintf("  %-24s %-12s %8s %10s %7s %9s  %s", "NODE", "PROBE", "WALL", "REMOTE CPU", "LOAD1", "OUTPUT", "NOTE"))
	for _, p := range last.Probes {
		note := p.Skipped
		if p.Err != "" {
			note = "error: " + p.Err
		}
		if p.Skipped != "" {
			out = append(out, fmt.Sprintf("  %-24s %-12s %8s %10s %7s %9s  skipped: %s", p.Node, p.Kind, "-", "-", "-", "-", note))
			continue
		}
		cpuS := "-"
		if p.RemoteCPU > 0 || p.RemoteUser > 0 {
			cpuS = fmtSecs(p.RemoteCPU)
		}
		load := "-"
		if p.Load1 >= 0 {
			load = fmt.Sprintf("%.2f", p.Load1)
		}
		out = append(out, fmt.Sprintf("  %-24s %-12s %8s %10s %7s %9s  %s", p.Node, p.Kind, (time.Duration(p.WallMS)*time.Millisecond).Round(10*time.Millisecond), cpuS, load, fmtBytes(int64(p.OutBytes)), note))
	}
	out = append(out, "")
	out = append(out, fmt.Sprintf("Per node over the last %d cycles: average remote CPU per cycle and what that is as a share of one core", len(recs)))
	nodes := make([]string, 0, len(remote))
	for k := range remote {
		nodes = append(nodes, k)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		vals := remote[node]
		var sum, max float64
		for _, v := range vals {
			sum += v
			if v > max {
				max = v
			}
		}
		avg := sum / float64(len(vals))
		line := fmt.Sprintf("  %-24s avg %s  max %s  = %.2f%% of one core", node, fmtSecs(avg), fmtSecs(max), avg/refresh*100)
		if s := f.skips[node]; s > 0 {
			line += fmt.Sprintf("   (%d probes skipped)", s)
		}
		out = append(out, line)
	}
	out = append(out, "")
	out = append(out, "Reducing the footprint: longer --refresh, larger heavy_every, ssh.nodes to limit hosts, --no-ssh for API only;")
	out = append(out, "R (full refresh) and the first contact with a node are the expensive cycles. See docs/PERFORMANCE.md.")
	return out
}

// perfSummary is the one-line status shown after a cycle when the perf log
// is on, so the cost is visible without opening the overlay.
func (a *App) perfSummary() string {
	if len(a.fp.hist) == 0 {
		return ""
	}
	r := a.fp.hist[len(a.fp.hist)-1]
	var remote float64
	for _, p := range r.Probes {
		remote += p.RemoteCPU
	}
	return strings.TrimSpace(fmt.Sprintf("cycle %d: api %d req %s, nodes %s remote cpu, local %s", r.Cycle, r.API.Requests, fmtBytes(r.API.BytesIn), fmtSecs(remote), fmtSecs(r.LocalCPUS)))
}
