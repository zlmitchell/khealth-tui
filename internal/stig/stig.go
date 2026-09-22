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
//	rancher.go     DISA Rancher Government MCM STIG V2R2  (V-2528xx, V-257292; management cluster only)
//	cis.go         CIS Kubernetes Benchmark v2.0 numbering (CIS-x.y.z)
//	os.go          per-node OS checks shared by the OS STIGs
//	rhel.go        DISA RHEL 8 / 9 / 10 STIG rule tables
//	ubuntu.go      DISA Ubuntu 22.04 / 24.04 LTS STIG rule tables
//
// Verify the mapping against the release you are audited against.
package stig

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
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
	{Name: "DISA Rancher Government RKE2 STIG", Version: "V2R7 (01 Jul 2026)", Prefixes: []string{"V-2545", "V-268", "RKE2-"}, Note: "all 21 rules (V-2545xx, V-268321; rule ids CNTR-R2-*): those that restate a Kubernetes STIG check alias it and name the source; RKE2-* are the rke2 hardening-guide prerequisites (etcd user, SELinux, per-component ciphers, audit-log-mode)"},
	{Name: "DISA Rancher Government MCM STIG", Version: "V2R2 (05 Jan 2026)", Prefixes: []string{"V-2528", "V-257292"}, Note: "Rancher Multi-Cluster Manager; evaluated only on the cluster that runs Rancher"},
	{Name: "CIS Kubernetes Benchmark", Version: "v2.0.1 (Jun 2026) / rke2 CIS self-assessment v1.12", Prefixes: []string{"CIS-"}, Note: "section numbers follow v2.0 (renumbered from v1.9)"},
	{Name: "Generic OS checks", Version: "(no STIG ID)", Prefixes: []string{"OS-"}, Note: "the fallback checks for distributions without a DISA table (SLES, Flatcar, ...); the OS STIGs themselves are listed in OSBenchmarks. Pending reboot is an Overview finding, not a rule"},
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
	Group   string // apiserver, controller-manager, scheduler, etcd, kubelet, node, os, cluster, rancher
	Status  Status
	Detail  string
	Fix     string
	Ref     string            // reference document when not derivable from the ID prefix (OS STIGs)
	RuleID  string            // STIG rule ID (RHEL-09-211010) when the reference has one
	Check   string            // the reference's own check text (OS STIGs), shown in the detail view
	PerNode map[string]Status // per-node outcome for perNode rules
}

// Input is everything the rules look at.
type Input struct {
	Snap     *k8s.Snapshot
	Nodes    map[string]*nodeinfo.Info
	Etcd     map[string]*etcd.Probe
	EtcdExec *etcd.Probe // cluster-wide etcd view via kubectl exec (optional)
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

	if psa := e.psaConfig(); psa != nil {
		// headless runs have no UI handler to install these (see ui/app.go)
		k8s.SetExemptNamespaces(psa.ExemptNamespaces)
	}
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
	e.rke2STIGRules() // every RKE2 STIG rule with its own row (rke2stig.go)
	e.clusterRules()
	e.rancherRules()

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

// psaConfig is the PodSecurity admission config the apiserver runs with,
// read from a server node's disk by the SSH config tier (nil without it).
func (e *evaluator) psaConfig() *nodeinfo.PSAConfig {
	paths := map[string]string{}
	for n, f := range e.apiserver {
		paths[n] = f["admission-control-config-file"]
	}
	return nodeinfo.EffectivePSA(e.in.Nodes, paths)
}

// perNode aggregates a check across the nodes present in flags maps.
func (e *evaluator) perNode(id, title, cat, group, fix string, nodes []string, check func(node string) (Status, string)) {
	if len(nodes) == 0 {
		e.add(Result{ID: id, Title: title, Cat: cat, Group: group, Status: Unknown, Detail: "no " + group + " data (mirror pods / configz not readable)", Fix: fix})
		return
	}
	sort.Strings(nodes)
	var fails, manual []string
	passes := 0
	passDetail := "" // kept when every passing node reports the same evidence
	per := make(map[string]Status, len(nodes))
	for _, n := range nodes {
		st, detail := check(n)
		per[n] = st
		switch st {
		case Pass:
			if passes == 0 {
				passDetail = detail
			} else if detail != passDetail {
				passDetail = ""
			}
			passes++
		case Fail:
			fails = append(fails, n+": "+detail)
		case Manual:
			manual = append(manual, n+": "+detail)
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
		if passDetail != "" {
			r.Detail += ": " + passDetail
		}
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

// Counts returns pass/fail/manual/na/unknown totals.

func Counts(rs []Result) map[Status]int {
	m := map[Status]int{}
	for _, r := range rs {
		m[r.Status]++
	}
	return m
}
