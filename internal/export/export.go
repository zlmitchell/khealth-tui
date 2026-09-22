// Package export writes what khealth found to files other tools can read:
// a JSON document (alerting, diffing between runs, feeding a ticket) and an
// Excel workbook with one sheet per scan type (the health findings, then
// every STIG / CIS benchmark that was evaluated, then the node hardening
// table) for the people who audit against spreadsheets. Both come from the
// same Report, built once from the data the TUI already holds; nothing is
// re-collected.
package export

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/stig"
)

// Input is everything the report is built from.
type Input struct {
	Snap      *k8s.Snapshot
	Nodes     map[string]*nodeinfo.Info
	Findings  []checks.Finding
	FirstSeen func(checks.Finding) time.Time // when the TUI first saw a finding (zero when unknown)
	Resolved  []ResolvedFinding
	Stig      []stig.Result // nil when the security scan was not run
	StigRun   bool
	Context   string // kubeconfig context / cluster name for the file name
	Server    string // API server URL
	Version   string // khealth version
	Now       time.Time
}

// ResolvedFinding is a finding that went away recently (the TUI keeps them
// for a while).
type ResolvedFinding struct {
	checks.Finding
	First, Resolved time.Time
}

// Report is the exported document.
type Report struct {
	GeneratedAt time.Time  `json:"generated_at"`
	Tool        string     `json:"tool"`
	Version     string     `json:"version"`
	Cluster     Cluster    `json:"cluster"`
	Summary     Summary    `json:"summary"`
	Findings    []Finding  `json:"findings"`
	Resolved    []Finding  `json:"resolved,omitempty"`
	Security    *Security  `json:"security,omitempty"`
	Nodes       []NodeInfo `json:"nodes"`
}

// Cluster identifies what was scanned.
type Cluster struct {
	Context      string `json:"context,omitempty"`
	Server       string `json:"server,omitempty"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Nodes        int    `json:"nodes"`
	Pods         int    `json:"pods"`
	Namespaces   int    `json:"namespaces"`
}

// Summary counts findings per severity and rules per status.
type Summary struct {
	Crit, Warn, Info int            `json:"-"`
	Findings         map[string]int `json:"findings"`           // severity -> count
	Security         map[string]int `json:"security,omitempty"` // status -> count over every benchmark
}

// Finding is one health observation.
type Finding struct {
	Severity  string     `json:"severity"`
	Area      string     `json:"area"`
	Object    string     `json:"object"`
	Message   string     `json:"message"`
	Hint      string     `json:"hint,omitempty"`
	Steps     []string   `json:"steps,omitempty"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	Resolved  *time.Time `json:"resolved,omitempty"`
}

// Security is the STIG / CIS scan: one entry per benchmark.
type Security struct {
	Benchmarks []Benchmark `json:"benchmarks"`
}

// Benchmark is one reference document with its scorecard and rules.
type Benchmark struct {
	Name       string             `json:"name"`
	Sheet      string             `json:"-"`
	Score      *float64           `json:"score,omitempty"` // not a finding / (not a finding + open), nil when nothing was scored
	Counts     map[string]int     `json:"counts"`
	NodeScores map[string]float64 `json:"node_scores,omitempty"` // OS STIGs: per node
	Rules      []Rule             `json:"rules"`
	PerNode    bool               `json:"-"` // rules carry per-node outcomes
	nodes      []string
}

// Rule is one evaluated rule.
type Rule struct {
	ID      string            `json:"id"`
	RuleID  string            `json:"rule_id,omitempty"`
	Cat     string            `json:"cat,omitempty"`
	Group   string            `json:"group,omitempty"`
	Title   string            `json:"title"`
	Status  string            `json:"status"`
	Detail  string            `json:"detail,omitempty"`
	Fix     string            `json:"fix,omitempty"`
	Check   string            `json:"check,omitempty"`
	PerNode map[string]string `json:"per_node,omitempty"`
}

// NodeInfo is the node hardening line: what is in effect now vs what the
// configuration says for the next boot.
type NodeInfo struct {
	Name      string          `json:"name"`
	Roles     []string        `json:"roles,omitempty"`
	Version   string          `json:"kubelet_version"`
	Ready     bool            `json:"ready"`
	OS        string          `json:"os,omitempty"`
	Kernel    string          `json:"kernel,omitempty"`
	SSH       string          `json:"ssh"` // ok, off, or the error
	Hardening []HardeningItem `json:"hardening,omitempty"`
}

// HardeningItem mirrors nodeinfo.HardeningItem.
type HardeningItem struct {
	Name     string `json:"name"`
	Runtime  string `json:"runtime"`
	Boot     string `json:"boot,omitempty"`
	OK       bool   `json:"ok"`
	Mismatch bool   `json:"mismatch,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Build assembles the report.
func Build(in Input) *Report {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := &Report{GeneratedAt: now, Tool: "khealth", Version: in.Version, Cluster: Cluster{Context: in.Context, Server: in.Server}}
	r.Summary.Findings = map[string]int{}
	if s := in.Snap; s != nil {
		r.Cluster.Distribution, r.Cluster.Version = s.Distribution, s.Version
		r.Cluster.Nodes, r.Cluster.Pods, r.Cluster.Namespaces = len(s.Nodes), len(s.Pods), len(s.Namespaces)
	}
	for _, f := range in.Findings {
		x := finding(f)
		if in.FirstSeen != nil {
			if t := in.FirstSeen(f); !t.IsZero() {
				x.FirstSeen = &t
			}
		}
		r.Findings = append(r.Findings, x)
		r.Summary.Findings[f.Severity.String()]++
		switch f.Severity {
		case checks.SevCrit:
			r.Summary.Crit++
		case checks.SevWarn:
			r.Summary.Warn++
		default:
			r.Summary.Info++
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return sevRank(r.Findings[i].Severity) < sevRank(r.Findings[j].Severity) })
	for _, rf := range in.Resolved {
		x := finding(rf.Finding)
		first, res := rf.First, rf.Resolved
		if !first.IsZero() {
			x.FirstSeen = &first
		}
		x.Resolved = &res
		r.Resolved = append(r.Resolved, x)
	}
	if in.StigRun {
		r.Security = security(in.Stig)
		r.Summary.Security = map[string]int{}
		for _, b := range r.Security.Benchmarks {
			for st, n := range b.Counts {
				r.Summary.Security[st] += n
			}
		}
	}
	if in.Snap != nil {
		for i := range in.Snap.Nodes {
			r.Nodes = append(r.Nodes, nodeInfo(&in.Snap.Nodes[i], in.Nodes[in.Snap.Nodes[i].Name]))
		}
	}
	return r
}

func finding(f checks.Finding) Finding {
	return Finding{Severity: f.Severity.String(), Area: f.Area, Object: f.Object, Message: f.Message, Hint: f.Hint, Steps: f.Steps}
}

func sevRank(s string) int {
	switch s {
	case "CRIT":
		return 0
	case "WARN":
		return 1
	}
	return 2
}

// security groups the results by benchmark, in the order the Security tab
// scores them, the OS STIGs last.
func security(rs []stig.Result) *Security {
	sec := &Security{}
	byName := map[string]*Benchmark{}
	var order []string
	for _, r := range rs {
		name := stig.BenchmarkName(r)
		b := byName[name]
		if b == nil {
			b = &Benchmark{Name: name, Counts: map[string]int{}}
			byName[name] = b
			order = append(order, name)
		}
		rule := Rule{ID: r.ID, RuleID: r.RuleID, Cat: r.Cat, Group: r.Group, Title: r.Title, Status: r.Status.String(), Detail: r.Detail, Fix: r.Fix, Check: r.Check}
		if len(r.PerNode) > 0 {
			rule.PerNode = map[string]string{}
			for n, st := range r.PerNode {
				rule.PerNode[n] = st.String()
			}
			b.PerNode = true
		}
		b.Rules = append(b.Rules, rule)
		b.Counts[r.Status.String()]++
	}
	// cluster benchmarks first (as listed in stig.Benchmarks), then the OS ones
	rank := func(name string) int {
		for i, b := range stig.Benchmarks {
			if strings.HasPrefix(name, b.Name) {
				return i
			}
		}
		return len(stig.Benchmarks) + 1
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(order[i]) < rank(order[j]) })
	nodeSet := map[string]map[string]bool{}
	for _, name := range order {
		b := byName[name]
		for _, sc := range stig.Scores(resultsOf(rs, name), true) {
			if sc.Node == "" {
				if p := sc.Percent(); !math.IsNaN(p) {
					p = math.Round(p*10) / 10
					b.Score = &p
				}
				continue
			}
			if p := sc.Percent(); !math.IsNaN(p) {
				if b.NodeScores == nil {
					b.NodeScores = map[string]float64{}
				}
				b.NodeScores[sc.Node] = math.Round(p*10) / 10
			}
		}
		if b.PerNode {
			for _, rule := range b.Rules {
				for n := range rule.PerNode {
					if nodeSet[name] == nil {
						nodeSet[name] = map[string]bool{}
					}
					nodeSet[name][n] = true
				}
			}
			for n := range nodeSet[name] {
				b.nodes = append(b.nodes, n)
			}
			sort.Strings(b.nodes)
		}
		b.Sheet = sheetName(name)
		sec.Benchmarks = append(sec.Benchmarks, *b)
	}
	return sec
}

func resultsOf(rs []stig.Result, name string) []stig.Result {
	var out []stig.Result
	for _, r := range rs {
		if stig.BenchmarkName(r) == name {
			out = append(out, r)
		}
	}
	return out
}

func nodeInfo(n *corev1.Node, ni *nodeinfo.Info) NodeInfo {
	x := NodeInfo{Name: n.Name, Version: n.Status.NodeInfo.KubeletVersion, OS: n.Status.NodeInfo.OSImage, Kernel: n.Status.NodeInfo.KernelVersion, SSH: "off"}
	if st, _ := k8s.NodeCondition(n, corev1.NodeReady); st == corev1.ConditionTrue {
		x.Ready = true
	}
	for k := range n.Labels {
		if strings.HasPrefix(k, "node-role.kubernetes.io/") {
			x.Roles = append(x.Roles, strings.TrimPrefix(k, "node-role.kubernetes.io/"))
		}
	}
	sort.Strings(x.Roles)
	if ni == nil {
		return x
	}
	if ni.Err != nil {
		x.SSH = ni.Err.Error()
		return x
	}
	x.SSH = "ok"
	if ni.OS.Pretty != "" {
		x.OS = ni.OS.Pretty
	}
	for _, it := range ni.HardeningItems() {
		x.Hardening = append(x.Hardening, HardeningItem{Name: it.Name, Runtime: it.Runtime, Boot: it.Boot, OK: it.OK, Mismatch: it.Mismatch, Detail: it.Detail})
	}
	return x
}

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var unsafeFile = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// FileBase is the file name (without extension) for a report:
// khealth-<context>-<timestamp>.
func FileBase(r *Report) string {
	name := r.Cluster.Context
	if name == "" {
		name = r.Cluster.Server
		name = strings.TrimPrefix(strings.TrimPrefix(name, "https://"), "http://")
	}
	name = strings.Trim(unsafeFile.ReplaceAllString(name, "-"), "-")
	if name == "" {
		name = "cluster"
	}
	return "khealth-" + name + "-" + r.GeneratedAt.Format("20060102-150405")
}

// WriteFiles writes <dir>/<base>.json and <dir>/<base>.xlsx and returns
// their paths.
func WriteFiles(dir string, r *Report) (jsonPath, xlsxPath string, err error) {
	paths, err := WriteFormats(dir, r, true, true)
	if err != nil {
		return "", "", err
	}
	return paths[0], paths[1], nil
}

// WriteFormats writes the report as JSON and/or XLSX under dir and returns
// the paths written, JSON first.
func WriteFormats(dir string, r *Report, json, xlsx bool) ([]string, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	base := filepath.Join(dir, FileBase(r))
	var out []string
	if json {
		p := base + ".json"
		f, err := os.Create(p)
		if err != nil {
			return nil, err
		}
		if err := WriteJSON(f, r); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if xlsx {
		p := base + ".xlsx"
		if err := WriteXLSX(p, r); err != nil {
			return nil, fmt.Errorf("xlsx: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}
