// Package gather writes a log bundle for root-cause analysis: what the
// rke2 log collector gathers from one node, for every node of an rke2,
// k3s or kubeadm cluster at once, plus the API's view (objects, events,
// pod logs) and khealth's own probes and findings.
//
// The raw probe output is kept next to the logs (nodes/<node>/probe), so
// the findings can be computed again from the bundle alone, and a later
// analysis can line the journals, events and pod logs up on one timeline.
// docs/GATHER.md describes the layout.
package gather

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/export"
	"github.com/zlmitchell/khealth-tui/internal/headless"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// FormatVersion is bumped when the bundle layout changes incompatibly.
const FormatVersion = 1

// Manifest is manifest.json: what the bundle holds and what could not be
// collected, so an analysis can tell "no errors" from "no data".
type Manifest struct {
	Format       int             `json:"format"`
	Tool         string          `json:"tool"`
	Created      time.Time       `json:"created"`
	Context      string          `json:"context"`
	Server       string          `json:"server"`
	Distribution string          `json:"distribution"`
	K8sVersion   string          `json:"kubernetes_version"`
	Scope        string          `json:"scope"` // cluster | workload
	Workload     *WorkloadInfo   `json:"workload,omitempty"`
	Since        string          `json:"since"`
	APIReachable bool            `json:"api_reachable"`
	APIErrors    []string        `json:"api_errors,omitempty"`
	Resources    []ResourceEntry `json:"resources,omitempty"`
	PodLogs      PodLogStats     `json:"pod_logs"`
	Nodes        []NodeEntry     `json:"nodes"`
	Findings     int             `json:"findings"`
	Duration     string          `json:"duration"`
	Notes        []string        `json:"notes,omitempty"`
}

// NodeEntry is one node's part of the bundle.
type NodeEntry struct {
	Name      string   `json:"name"`
	Host      string   `json:"host"`
	Probe     string   `json:"probe"` // ok | error text
	EtcdProbe string   `json:"etcd_probe,omitempty"`
	Logs      string   `json:"logs"` // ok | error text
	Files     int      `json:"files"`
	Bytes     int64    `json:"bytes"`
	Skipped   []string `json:"skipped,omitempty"`   // items left out past the node budget
	Truncated []string `json:"truncated,omitempty"` // files cut to file_mb (newest end kept)
	Seconds   float64  `json:"seconds"`
}

// ProbeMeta is nodes/<node>/probe/<kind>.meta.json: what replaying a
// probe's output needs besides the output (the clock-skew check compares
// the node's clock with when the probe was sent).
type ProbeMeta struct {
	Node     string    `json:"node"`
	Host     string    `json:"host"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	HostKey  string    `json:"host_key,omitempty"`
	Status   string    `json:"status"`
}

// Result is where the bundle went.
type Result struct {
	Path     string
	Size     int64
	Manifest Manifest
}

// Run collects the bundle and writes it where cfg.Gather.Out points.
// Label names the cluster a bundle came from: its kubeconfig context, or
// the API server's host when that is rke2/k3s's generic "default".
func (m Manifest) Label() string {
	if m.Context == "" || m.Context == "default" {
		return strutil.FirstNonEmpty(strutil.URLHost(m.Server), m.Context)
	}
	return m.Context
}

func Run(ctx context.Context, cfg config.Config, log io.Writer) (*Result, error) {
	if log == nil {
		log = io.Discard
	}
	start := time.Now()
	g := cfg.Gather
	tmp, err := os.MkdirTemp("", "khealth-bundle-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	st := stage{dir: tmp}
	m := Manifest{Format: FormatVersion, Tool: "khealth " + config.Version, Created: start.UTC(), Scope: "cluster", Since: g.Since.String()}

	var runner *sshrun.Runner
	if cfg.SSH.Enabled {
		runner, err = sshrun.New(cfg.SSH)
		if err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		}
		defer runner.Close()
	} else {
		m.Notes = append(m.Notes, "SSH disabled (--no-ssh): no node logs, probes or etcd state")
	}

	// 1. one khealth cycle (API snapshot, node + etcd probes with the heavy
	// tiers, findings), keeping every probe's raw output
	fmt.Fprintln(log, "collecting the API snapshot and the node probes ...")
	var mu sync.Mutex
	probes := map[string]*NodeEntry{}
	entry := func(t headless.Target) *NodeEntry {
		e := probes[t.Name]
		if e == nil {
			e = &NodeEntry{Name: t.Name, Host: t.Host, Logs: "not collected"}
			probes[t.Name] = e
		}
		return e
	}
	raw := func(kind string, t headless.Target, r sshrun.Result) {
		dir := "nodes/" + safeName(t.Name) + "/probe/"
		_ = st.write(dir+kind+".txt", []byte(r.Stdout))
		if r.Stderr != "" {
			_ = st.write(dir+kind+".stderr", []byte(r.Stderr))
		}
		status := "ok"
		if r.Err != nil && !strings.Contains(r.Stdout, "===END") {
			status = strutil.FirstLine(r.Err.Error())
		}
		_ = st.writeJSON(dir+kind+".meta.json", ProbeMeta{Node: t.Name, Host: t.Host, Started: r.Started, Finished: r.Finished, HostKey: r.HostKey, Status: status})
		mu.Lock()
		defer mu.Unlock()
		e := entry(t)
		if kind == "etcd" {
			e.EtcdProbe = status
		} else {
			e.Probe = status
		}
	}
	hres, err := headless.Run(ctx, cfg, headless.Options{Heavy: true, Log: log, Runner: runner, Raw: raw})
	if err != nil {
		return nil, err
	}
	snap, client := hres.Snap, hres.Client
	// the moment the checks were evaluated at: replay evaluates as of
	// Created, so relative ages ("last restart 26s ago") come out the same
	m.Created = hres.Input.Now.UTC()
	m.Context, m.Server = client.Context, client.Host
	m.Distribution, m.K8sVersion = snap.Distribution, snap.Version
	m.APIReachable = len(snap.Nodes) > 0
	m.APIErrors = snap.Errors
	m.Findings = len(hres.Findings)
	if hres.Offline {
		m.Notes = append(m.Notes, "the API listed no nodes: nodes came from ssh.hosts and every one got the etcd probe")
	}

	// 2. what the bundle is about: the cluster, or one workload
	var pods []corev1.Pod
	targets := hres.Targets
	podGlobs := map[string][]string{} // extra on-disk pod log globs per node
	since := start.Add(-g.Since)
	if g.Workload != "" {
		if !m.APIReachable {
			return nil, fmt.Errorf("--gather-workload needs the API server (%s)", strings.Join(snap.Errors, "; "))
		}
		w, wp, err := resolveWorkload(ctx, client, g.Workload)
		if err != nil {
			return nil, err
		}
		m.Scope, m.Workload, pods = "workload", w, wp
		for _, p := range wp {
			podGlobs[p.Spec.NodeName] = append(podGlobs[p.Spec.NodeName], p.Namespace+"_"+p.Name+"_*")
		}
		if !cfg.Flags["ssh-nodes"] {
			// the workload's nodes and the control plane (scheduler,
			// controllers, webhooks and etcd are where a stuck rollout ends up)
			on := map[string]bool{}
			for _, n := range w.Nodes {
				on[n] = true
			}
			var keep []headless.Target
			for _, t := range targets {
				if on[t.Name] || t.ControlPlane || t.Etcd {
					keep = append(keep, t)
				}
			}
			targets = keep
		}
		fmt.Fprintf(log, "workload %s/%s %s: %d pods on %d nodes\n", w.Namespace, strings.ToLower(w.Kind), w.Name, len(w.Pods), len(w.Nodes))
	} else {
		for i := range snap.Pods {
			if needsLogs(&snap.Pods[i], since) && k8s.IngressController(&snap.Pods[i]) == "" {
				pods = append(pods, snap.Pods[i])
			}
		}
	}
	// the ingress controllers' access logs are the traffic view of the
	// analysis: always collected, with a larger cap (they are busy)
	var controllers []corev1.Pod
	for i := range snap.Pods {
		if k8s.IngressController(&snap.Pods[i]) != "" && snap.Pods[i].Status.Phase == corev1.PodRunning {
			controllers = append(controllers, snap.Pods[i])
		}
	}

	// 3. the API dump and the node logs, side by side
	var wg sync.WaitGroup
	if m.APIReachable {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ns := ""
			if m.Workload != nil {
				ns = m.Workload.Namespace
			}
			what := "API objects"
			if ns != "" {
				what += " (namespace " + ns + ")"
			}
			fmt.Fprintf(log, "dumping %s and the logs of %d pods ...\n", what, len(pods))
			errs := apiHealth(ctx, client, st)
			res := dumpResources(ctx, client, st, ns)
			pl := podLogs(ctx, client, st, pods, g.Since, int64(g.PodLogMB)<<20)
			cl := podLogs(ctx, client, st, controllers, g.Since, int64(g.PodLogMB)<<22)
			pl.Pods, pl.Containers, pl.Previous, pl.Bytes = pl.Pods+cl.Pods, pl.Containers+cl.Containers, pl.Previous+cl.Previous, pl.Bytes+cl.Bytes
			pl.Errors = append(pl.Errors, cl.Errors...)
			mu.Lock()
			m.APIErrors = append(m.APIErrors, errs...)
			m.Resources, m.PodLogs = res, pl
			mu.Unlock()
		}()
	}
	if runner != nil {
		globs := append([]string{}, staticPodGlobs...)
		if !m.APIReachable {
			globs = append(globs, systemPodGlobs...)
			for _, s := range cfg.Namespaces.System {
				globs = append(globs, strings.TrimRight(s, "-*")+"*")
			}
		}
		for _, t := range targets {
			wg.Add(1)
			go func(t headless.Target) {
				defer wg.Done()
				o := nodeOpts{
					BudgetKB: int64(g.NodeMB) << 10, FileBytes: int64(g.FileMB) << 20, PodBytes: int64(g.PodLogMB) << 20,
					Minutes: int(g.Since.Minutes()), PodGlobs: append(append([]string{}, globs...), podGlobs[t.Name]...),
				}
				e := gatherNode(ctx, runner, st, t, o, log)
				mu.Lock()
				p := entry(t)
				p.Logs, p.Files, p.Bytes, p.Skipped, p.Truncated, p.Seconds = e.Logs, e.Files, e.Bytes, e.Skipped, e.Truncated, e.Seconds
				mu.Unlock()
			}(t)
		}
	}
	wg.Wait()
	for _, e := range probes {
		m.Nodes = append(m.Nodes, *e)
	}
	sort.Slice(m.Nodes, func(i, j int) bool { return m.Nodes[i].Name < m.Nodes[j].Name })

	// 4. khealth's own view: the findings report and the snapshot it came from
	rep := export.Build(export.Input{Snap: snap, Nodes: hres.Input.Nodes, Findings: hres.Findings, Context: client.Context, Server: client.Host, Version: config.Version, Now: start})
	if f, err := st.create("report.json"); err == nil {
		if err := export.WriteJSON(f, rep); err != nil {
			m.Notes = append(m.Notes, "report.json: "+err.Error())
		}
		f.Close()
	}
	if tree, err := scrubSnapshot(snap); err != nil {
		m.Notes = append(m.Notes, "snapshot.json: "+err.Error())
	} else if err := st.writeJSON("snapshot.json", tree); err != nil {
		m.Notes = append(m.Notes, "snapshot.json: "+err.Error())
	}
	m.Duration = time.Since(start).Round(time.Second).String()
	if err := st.writeJSON("manifest.json", m); err != nil {
		return nil, err
	}

	out := outPath(g.Out, m.Label(), start)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return nil, err
	}
	root := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(out), ".gz"), ".tar")
	root = strings.TrimSuffix(root, ".tgz")
	size, err := st.pack(out, root)
	if err != nil {
		return nil, err
	}
	return &Result{Path: out, Size: size, Manifest: m}, nil
}

// gatherNode streams gather.sh's archive from one node into
// nodes/<node>/.
func gatherNode(ctx context.Context, runner *sshrun.Runner, st stage, t headless.Target, o nodeOpts, log io.Writer) NodeEntry {
	e := NodeEntry{Name: t.Name, Host: t.Host}
	dir := st.path("nodes/" + safeName(t.Name))
	c, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	fmt.Fprintf(log, "  %s: gathering logs ...\n", t.Name)
	pr, pw := io.Pipe()
	type read struct {
		files int
		n     int64
		err   error
	}
	done := make(chan read, 1)
	go func() {
		// hard stop well above the budget: the node caps itself, this only
		// guards against a script that does not
		files, n, err := readNodeTar(pr, dir, o.BudgetKB<<10*2+o.FileBytes)
		if err == nil {
			// the tar end marker is not the end of the stream (record
			// padding, the gzip trailer): take the rest, or the node's
			// last writes fail and a good run reads as an error
			_, _ = io.Copy(io.Discard, pr)
		}
		pr.CloseWithError(err)
		done <- read{files, n, err}
	}()
	r := runner.Stream(c, t.Host, nodeScript(o), pw)
	pw.CloseWithError(r.Err)
	rd := <-done
	e.Files, e.Bytes = rd.files, rd.n
	e.Seconds = r.Finished.Sub(r.Started).Seconds()
	switch {
	case r.Err != nil:
		msg := strutil.FirstLine(r.Err.Error())
		if s := strings.TrimSpace(r.Stderr); s != "" {
			msg += ": " + strutil.FirstLine(lastLines(s, 1))
		}
		e.Logs = msg
	case rd.err != nil:
		e.Logs = rd.err.Error()
	default:
		e.Logs = "ok"
	}
	if r.Stderr != "" {
		_ = st.write("nodes/"+safeName(t.Name)+"/_gather/stderr.txt", []byte(r.Stderr))
	}
	e.Skipped = readLines(filepath.Join(dir, "_gather", "skipped"))
	e.Truncated = readLines(filepath.Join(dir, "_gather", "truncated"))
	fmt.Fprintf(log, "  %s: %s, %d files, %.1f MiB in %.0fs\n", t.Name, e.Logs, e.Files, float64(e.Bytes)/(1<<20), e.Seconds)
	return e
}

func readLines(p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// scrubSnapshot is the snapshot as the bundle stores it, as a JSON tree:
// the same rules as the API dump, applied to every object wherever it sits
// (typed lists, CR summaries) rather than type by type, so a type added to
// the snapshot later cannot slip through. managedFields and the
// last-applied annotation (a full copy of the object, env values included)
// go, credential-looking env values are masked, Helm values (user input,
// often with passwords) are not kept.
func scrubSnapshot(s *k8s.Snapshot) (any, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(b, &tree); err != nil {
		return nil, err
	}
	scrubTree(tree)
	return tree, nil
}

func scrubTree(v any) {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			scrubTree(e)
		}
	case map[string]any:
		delete(t, "managedFields")
		if a, ok := t["annotations"].(map[string]any); ok {
			delete(a, lastApplied)
		}
		if vy, ok := t["ValuesYAML"].(string); ok && vy != "" {
			t["ValuesYAML"] = "<not collected>"
		}
		if env, ok := t["env"].([]any); ok {
			for _, e := range env {
				if em, ok := e.(map[string]any); ok {
					if name, _ := em["name"].(string); credName.MatchString(name) {
						if _, has := em["value"]; has {
							em["value"] = "<masked>"
						}
					}
				}
			}
		}
		for _, e := range t {
			scrubTree(e)
		}
	}
}
