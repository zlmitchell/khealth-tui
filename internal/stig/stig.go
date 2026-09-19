// Package stig evaluates automatable DISA STIG / CIS style hardening checks
// for Kubernetes (upstream/kubeadm) and RKE2 from API data (control-plane
// component flags, kubelet configz, namespaces, RBAC) and node facts
// (sysctls, file permissions, rke2 profile, OS hardening).
//
// One file per reference document, all sourced from dl.dod.cyber.mil
// (wp-content/uploads/stigs/zip) or cisecurity.org:
//
//	kubernetes.go  DISA Kubernetes STIG V2R6            (V-2423xx.., V-2455xx, V-2548xx, V-2748xx)
//	rke2.go        DISA Rancher Government RKE2 STIG V2R7 (V-2545xx; RKE2-* prerequisites)
//	cis.go         CIS Kubernetes Benchmark v2.0 numbering (CIS-x.y.z)
//	os.go          per-node OS checks shared by the OS STIGs
//	rhel.go        DISA RHEL 8 / 9 / 10 STIG rule tables
//	ubuntu.go      DISA Ubuntu 20.04 / 22.04 / 24.04 LTS STIG rule tables
//
// Verify the mapping against the release you are audited against.
package stig

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

// Benchmark names a reference document the rule IDs were written against.
type Benchmark struct {
	Name     string
	Version  string
	Prefixes []string // rule ID prefixes owned by this reference
	Note     string
}

// Matches reports whether a rule ID belongs to this benchmark.
func (b Benchmark) Matches(id string) bool {
	for _, p := range b.Prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// Benchmarks lists the references behind the rule table, newest releases as
// published on dl.dod.cyber.mil / cisecurity.org at the time of writing. The
// IDs are a best-effort mapping: confirm against the release you are audited on.
var Benchmarks = []Benchmark{
	{Name: "DISA Kubernetes STIG", Version: "V2R6 (01 Apr 2026)", Prefixes: []string{"V-242", "V-245", "V-2548", "V-2748"}, Note: "vulnerability IDs V-2423xx..V-2424xx, V-2455xx, V-2548xx, V-2748xx (secrets at rest, new in V2R6)"},
	{Name: "DISA Rancher Government RKE2 STIG", Version: "V2R7 (01 Jul 2026)", Prefixes: []string{"V-2545", "V-268", "RKE2-"}, Note: "V-2545xx/V-268321; RKE2-* are rke2 hardening-guide prerequisites (etcd user, SELinux) not carried as STIG IDs"},
	{Name: "CIS Kubernetes Benchmark", Version: "v2.0.1 (Jun 2026) / rke2 CIS self-assessment v1.12", Prefixes: []string{"CIS-"}, Note: "section numbers follow v2.0 (renumbered from v1.9)"},
	{Name: "DISA OS STIGs", Version: "RHEL 8 V2R8 / 9 V2R9 / 10 V1R2, Ubuntu 20.04 V2R4 / 22.04 V2R9 / 24.04 V1R6", Prefixes: []string{"OS-"}, Note: "matched per node from /etc/os-release (see OSBenchmarks); OS-* IDs are the generic fallback for other distributions"},
}

// Status of one rule.
type Status int

const (
	Pass Status = iota
	Fail
	Manual
	NA
	Unknown
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Fail:
		return "FAIL"
	case Manual:
		return "MANUAL"
	case NA:
		return "N/A"
	}
	return "UNKNOWN"
}

// Result is one evaluated rule.
type Result struct {
	ID      string
	Title   string
	Cat     string // I, II, III
	Group   string // apiserver, controller-manager, scheduler, etcd, kubelet, node, os, cluster
	Status  Status
	Detail  string
	Fix     string
	Ref     string            // reference document when not derivable from the ID prefix (OS STIGs)
	PerNode map[string]Status // per-node outcome for perNode rules
}

// Input is everything the rules look at.
type Input struct {
	Snap  *k8s.Snapshot
	Nodes map[string]*nodeinfo.Info
	Etcd  map[string]*etcd.Probe
}

// Evaluate runs all rules.
func Evaluate(in Input) []Result {
	if in.Snap == nil {
		return nil
	}
	e := &evaluator{in: in, dist: in.Snap.Distribution}
	e.apiserver = k8s.ComponentArgs(in.Snap.Pods, "kube-apiserver")
	e.cm = k8s.ComponentArgs(in.Snap.Pods, "kube-controller-manager")
	e.sched = k8s.ComponentArgs(in.Snap.Pods, "kube-scheduler")
	e.etcdArgs = k8s.ComponentArgs(in.Snap.Pods, "etcd")

	e.apiserverRules()
	e.cmRules()
	e.schedulerRules()
	e.etcdRules()
	e.kubeletRules()
	e.cisRules()
	if len(e.sshNodes()) == 0 {
		e.add(Result{ID: "node", Title: "Node-level checks (sysctls, file permissions, rke2 profile, OS hardening)", Cat: "-", Group: "node", Status: Unknown, Detail: "no SSH data", Fix: "enable SSH collection"})
	} else {
		e.nodeRules()
		e.cisNodeRules()
		e.rke2Rules()
		e.osRules()
	}
	e.clusterRules()

	sort.SliceStable(e.out, func(i, j int) bool {
		if e.out[i].Status != e.out[j].Status {
			return statusRank(e.out[i].Status) < statusRank(e.out[j].Status)
		}
		if e.out[i].Cat != e.out[j].Cat {
			return e.out[i].Cat < e.out[j].Cat
		}
		return e.out[i].ID < e.out[j].ID
	})
	return e.out
}

func statusRank(s Status) int {
	switch s {
	case Fail:
		return 0
	case Manual:
		return 1
	case Unknown:
		return 2
	case Pass:
		return 3
	}
	return 4
}

type evaluator struct {
	in        Input
	dist      string
	apiserver map[string]map[string]string
	cm        map[string]map[string]string
	sched     map[string]map[string]string
	etcdArgs  map[string]map[string]string
	out       []Result
}

func (e *evaluator) add(r Result) { e.out = append(e.out, r) }

// perNode aggregates a check across the nodes present in flags maps.
func (e *evaluator) perNode(id, title, cat, group, fix string, nodes []string, check func(node string) (Status, string)) {
	if len(nodes) == 0 {
		e.add(Result{ID: id, Title: title, Cat: cat, Group: group, Status: Unknown, Detail: "no " + group + " data (mirror pods / configz not readable)", Fix: fix})
		return
	}
	sort.Strings(nodes)
	var fails, manual, nas []string
	passes := 0
	per := make(map[string]Status, len(nodes))
	for _, n := range nodes {
		st, detail := check(n)
		per[n] = st
		switch st {
		case Pass:
			passes++
		case Fail:
			fails = append(fails, n+": "+detail)
		case Manual:
			manual = append(manual, n+": "+detail)
		case NA:
			nas = append(nas, n)
		}
	}
	r := Result{ID: id, Title: title, Cat: cat, Group: group, Fix: fix, PerNode: per}
	switch {
	case len(fails) > 0:
		r.Status = Fail
		r.Detail = strings.Join(fails, "; ")
	case len(manual) > 0:
		r.Status = Manual
		r.Detail = strings.Join(manual, "; ")
	case passes > 0:
		r.Status = Pass
		r.Detail = fmt.Sprintf("%d/%d nodes", passes, len(nodes))
	default:
		r.Status = NA
		r.Detail = "not applicable"
	}
	e.add(r)
}

// sshNodes lists nodes with usable SSH facts, sorted.
func (e *evaluator) sshNodes() []string {
	var nodes []string
	for n, ni := range e.in.Nodes {
		if ni != nil && ni.Err == nil {
			nodes = append(nodes, n)
		}
	}
	sort.Strings(nodes)
	return nodes
}

func keys(m map[string]map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func flagEq(flags map[string]string, name, want string) (Status, string) {
	v, ok := flags[name]
	if !ok {
		return Fail, "--" + name + " not set"
	}
	if v == want {
		return Pass, ""
	}
	return Fail, fmt.Sprintf("--%s=%s", name, v)
}

func flagSet(flags map[string]string, name string) (Status, string) {
	if v, ok := flags[name]; ok && v != "" {
		return Pass, ""
	}
	return Fail, "--" + name + " not set"
}

func flagAbsent(flags map[string]string, name string) (Status, string) {
	if v, ok := flags[name]; ok {
		return Fail, fmt.Sprintf("--%s=%s is set", name, v)
	}
	return Pass, ""
}

func flagMinInt(flags map[string]string, name string, min int) (Status, string) {
	v, ok := flags[name]
	if !ok {
		return Fail, "--" + name + " not set"
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min {
		return Fail, fmt.Sprintf("--%s=%s (want >= %d)", name, v, min)
	}
	return Pass, ""
}

func tlsMin(flags map[string]string) (Status, string) {
	v, ok := flags["tls-min-version"]
	if !ok {
		return Fail, "--tls-min-version not set (defaults to TLS 1.2 on recent releases; set explicitly)"
	}
	if v == "VersionTLS12" || v == "VersionTLS13" {
		return Pass, ""
	}
	return Fail, "--tls-min-version=" + v
}

func nested(m map[string]any, path ...string) (any, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func modeAtMost(mode string, max int) bool {
	n, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		return false
	}
	return n&^int64(max) == 0
}

func truncList(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" (+%d more)", len(l)-n)
}

func uniq(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Counts returns pass/fail/manual/na/unknown totals.

func Counts(rs []Result) map[Status]int {
	m := map[Status]int{}
	for _, r := range rs {
		m[r.Status]++
	}
	return m
}
