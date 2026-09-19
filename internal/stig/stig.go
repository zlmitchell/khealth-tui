// Package stig evaluates automatable DISA STIG / CIS style hardening checks
// for Kubernetes (upstream/kubeadm) and RKE2 from API data (control-plane
// component flags, kubelet configz, namespaces, RBAC) and node facts
// (sysctls, file permissions, rke2 profile).
//
// Rule identifiers reference the DISA Kubernetes STIG V2R6, the DISA Rancher
// Government Solutions RKE2 STIG V2R7 (both from dl.dod.cyber.mil) or the CIS
// Kubernetes Benchmark v2.0 numbering; verify the mapping against the release
// you are audited against.
package stig

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

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
	{Name: "OS hardening (RHEL/Ubuntu STIG themes)", Version: "FIPS, MAC, fapolicyd, auditd, firewall, secure boot", Prefixes: []string{"OS-"}, Note: "per-node facts over SSH"},
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
	ID     string
	Title  string
	Cat    string // I, II, III
	Group  string // apiserver, controller-manager, scheduler, etcd, kubelet, node, cluster
	Status Status
	Detail string
	Fix    string
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
	e.nodeRules()
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
	for _, n := range nodes {
		st, detail := check(n)
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
	r := Result{ID: id, Title: title, Cat: cat, Group: group, Fix: fix}
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

func (e *evaluator) apiserverRules() {
	nodes := keys(e.apiserver)
	g := "apiserver"
	rk := func(node string) map[string]string { return e.apiserver[node] }
	e.perNode("V-242390", "API server anonymous authentication disabled", "I", g, "kube-apiserver-arg: anonymous-auth=false", nodes, func(n string) (Status, string) { return flagEq(rk(n), "anonymous-auth", "false") })
	e.perNode("V-242382", "API server authorization mode is Node,RBAC (not AlwaysAllow)", "II", g, "kube-apiserver-arg: authorization-mode=Node,RBAC", nodes, func(n string) (Status, string) {
		v := rk(n)["authorization-mode"]
		if strings.Contains(v, "AlwaysAllow") {
			return Fail, "--authorization-mode=" + v
		}
		if strings.Contains(v, "Node") && strings.Contains(v, "RBAC") {
			return Pass, ""
		}
		return Fail, "--authorization-mode=" + v
	})
	e.perNode("V-242378", "API server minimum TLS version 1.2", "II", g, "kube-apiserver-arg: tls-min-version=VersionTLS12", nodes, func(n string) (Status, string) { return tlsMin(rk(n)) })
	e.perNode("V-242418", "API server approved TLS cipher suites configured", "II", g, "kube-apiserver-arg: tls-cipher-suites=<FIPS/approved list>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "tls-cipher-suites") })
	e.perNode("V-242402", "API server audit log path configured", "II", g, "kube-apiserver-arg: audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log (rke2 profile: cis sets this)", nodes, func(n string) (Status, string) { return flagSet(rk(n), "audit-log-path") })
	e.perNode("V-242461", "API server audit policy file configured", "II", g, "kube-apiserver-arg: audit-policy-file=/etc/rancher/rke2/audit-policy.yaml", nodes, func(n string) (Status, string) { return flagSet(rk(n), "audit-policy-file") })
	e.perNode("V-242464", "API server audit-log-maxage >= 30", "II", g, "kube-apiserver-arg: audit-log-maxage=30", nodes, func(n string) (Status, string) { return flagMinInt(rk(n), "audit-log-maxage", 30) })
	e.perNode("V-242463", "API server audit-log-maxbackup >= 10", "II", g, "kube-apiserver-arg: audit-log-maxbackup=10", nodes, func(n string) (Status, string) { return flagMinInt(rk(n), "audit-log-maxbackup", 10) })
	e.perNode("V-242462", "API server audit-log-maxsize >= 100", "II", g, "kube-apiserver-arg: audit-log-maxsize=100", nodes, func(n string) (Status, string) { return flagMinInt(rk(n), "audit-log-maxsize", 100) })
	e.perNode("V-242436", "ValidatingAdmissionWebhook admission plugin enabled", "I", g, "do not list ValidatingAdmissionWebhook in --disable-admission-plugins", nodes, func(n string) (Status, string) {
		if strings.Contains(rk(n)["disable-admission-plugins"], "ValidatingAdmissionWebhook") {
			return Fail, "disabled via --disable-admission-plugins"
		}
		return Pass, ""
	})
	e.perNode("CIS-1.2.14", "NodeRestriction admission plugin enabled", "II", g, "kube-apiserver-arg: enable-admission-plugins=NodeRestriction,...", nodes, func(n string) (Status, string) {
		if strings.Contains(rk(n)["enable-admission-plugins"], "NodeRestriction") {
			return Pass, ""
		}
		return Fail, "--enable-admission-plugins=" + rk(n)["enable-admission-plugins"]
	})
	e.perNode("V-254800", "Pod Security Admission configured (admission-control-config-file)", "I", g, "rke2: profile: cis (uses /etc/rancher/rke2/rke2-pss.yaml) or set pod-security-admission-config-file; kubeadm: --admission-control-config-file", nodes, func(n string) (Status, string) {
		f := rk(n)
		if f["admission-control-config-file"] != "" || f["pod-security-admission-config-file"] != "" {
			return Pass, ""
		}
		return Fail, "no admission config file (namespaces must carry pod-security.kubernetes.io/enforce labels instead)"
	})
	e.perNode("V-242438", "API server request-timeout set", "II", g, "kube-apiserver-arg: request-timeout=300s", nodes, func(n string) (Status, string) { return flagSet(rk(n), "request-timeout") })
	e.perNode("CIS-1.2.15", "API server profiling disabled", "II", g, "kube-apiserver-arg: profiling=false", nodes, func(n string) (Status, string) { return flagEq(rk(n), "profiling", "false") })
	e.perNode("V-274882", "Secrets encrypted at rest (encryption-provider-config)", "I", g, "rke2: secrets-encryption: true; kubeadm: --encryption-provider-config", nodes, func(n string) (Status, string) { return flagSet(rk(n), "encryption-provider-config") })
	e.perNode("CIS-1.2.5", "API server verifies kubelet certificates (kubelet-certificate-authority)", "II", g, "kube-apiserver-arg: kubelet-certificate-authority=<ca>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "kubelet-certificate-authority") })
	e.perNode("CIS-1.2.21", "API server service-account-lookup enabled", "II", g, "kube-apiserver-arg: service-account-lookup=true", nodes, func(n string) (Status, string) {
		if v, ok := rk(n)["service-account-lookup"]; !ok || v == "true" {
			return Pass, ""
		}
		return Fail, "--service-account-lookup=false"
	})
	e.perNode("V-245543", "API server static token file not used", "I", g, "remove --token-auth-file", nodes, func(n string) (Status, string) { return flagAbsent(rk(n), "token-auth-file") })
	e.perNode("V-242389", "API server secure port enabled", "II", g, "--secure-port must not be 0", nodes, func(n string) (Status, string) {
		if rk(n)["secure-port"] == "0" {
			return Fail, "--secure-port=0"
		}
		return Pass, ""
	})
	e.perNode("V-242400", "API server alpha APIs disabled", "II", g, "do not set AllAlpha=true in --feature-gates / --runtime-config", nodes, func(n string) (Status, string) {
		if strings.Contains(rk(n)["feature-gates"], "AllAlpha=true") || strings.Contains(rk(n)["runtime-config"], "api/alpha=true") || strings.Contains(rk(n)["runtime-config"], "api/all=true") {
			return Fail, "alpha APIs enabled"
		}
		return Pass, ""
	})
}

func (e *evaluator) cmRules() {
	nodes := keys(e.cm)
	g := "controller-manager"
	rk := func(node string) map[string]string { return e.cm[node] }
	e.perNode("V-242381", "Controller manager uses individual service account credentials", "I", g, "kube-controller-manager-arg: use-service-account-credentials=true", nodes, func(n string) (Status, string) { return flagEq(rk(n), "use-service-account-credentials", "true") })
	e.perNode("V-242385", "Controller manager bound to localhost", "II", g, "kube-controller-manager-arg: bind-address=127.0.0.1", nodes, func(n string) (Status, string) {
		v, ok := rk(n)["bind-address"]
		if !ok || v == "127.0.0.1" || v == "::1" {
			return Pass, ""
		}
		return Fail, "--bind-address=" + v
	})
	e.perNode("V-242376", "Controller manager minimum TLS version 1.2", "II", g, "kube-controller-manager-arg: tls-min-version=VersionTLS12", nodes, func(n string) (Status, string) { return tlsMin(rk(n)) })
	e.perNode("V-242409", "Controller manager profiling disabled", "II", g, "kube-controller-manager-arg: profiling=false", nodes, func(n string) (Status, string) { return flagEq(rk(n), "profiling", "false") })
	e.perNode("CIS-1.3.5", "Controller manager root-ca-file set", "II", g, "kube-controller-manager-arg: root-ca-file=<ca>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "root-ca-file") })
	e.perNode("CIS-1.3.4", "Controller manager service-account-private-key-file set", "II", g, "kube-controller-manager-arg: service-account-private-key-file=<key>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "service-account-private-key-file") })
}

func (e *evaluator) schedulerRules() {
	nodes := keys(e.sched)
	g := "scheduler"
	rk := func(node string) map[string]string { return e.sched[node] }
	e.perNode("V-242384", "Scheduler bound to localhost", "II", g, "kube-scheduler-arg: bind-address=127.0.0.1", nodes, func(n string) (Status, string) {
		v, ok := rk(n)["bind-address"]
		if !ok || v == "127.0.0.1" || v == "::1" {
			return Pass, ""
		}
		return Fail, "--bind-address=" + v
	})
	e.perNode("V-242377", "Scheduler minimum TLS version 1.2", "II", g, "kube-scheduler-arg: tls-min-version=VersionTLS12", nodes, func(n string) (Status, string) { return tlsMin(rk(n)) })
	e.perNode("CIS-1.4.1", "Scheduler profiling disabled", "II", g, "kube-scheduler-arg: profiling=false", nodes, func(n string) (Status, string) { return flagEq(rk(n), "profiling", "false") })
}

func (e *evaluator) etcdRules() {
	g := "etcd"
	// Source of truth: kubeadm mirror pod args, or the rke2 generated etcd config file (via SSH probe).
	nodes := keys(e.etcdArgs)
	cfgNodes := map[string]string{}
	for n, p := range e.in.Etcd {
		for _, cf := range p.ConfigDump {
			if strings.Contains(cf.Path, "/db/etcd/config") {
				cfgNodes[n] = cf.Content
			}
		}
	}
	all := map[string]bool{}
	for _, n := range nodes {
		if len(e.etcdArgs[n]) > 1 { // rke2's static pod only has --config-file
			all[n] = true
		}
	}
	for n := range cfgNodes {
		all[n] = true
	}
	var list []string
	for n := range all {
		list = append(list, n)
	}
	check := func(n, flag, yamlKey, want string) (Status, string) {
		if c, ok := cfgNodes[n]; ok {
			cnt := strings.Count(c, yamlKey+": "+want)
			if cnt > 0 {
				return Pass, ""
			}
			if strings.Contains(c, yamlKey+":") {
				return Fail, yamlKey + " not " + want + " in etcd config"
			}
			if want == "false" { // absent boolean defaults to false
				return Pass, ""
			}
			return Fail, yamlKey + " missing in etcd config"
		}
		f := e.etcdArgs[n]
		v, ok := f[flag]
		if !ok {
			if want == "false" {
				return Pass, ""
			}
			return Fail, "--" + flag + " not set"
		}
		if v == want {
			return Pass, ""
		}
		return Fail, "--" + flag + "=" + v
	}
	e.perNode("V-242423", "etcd requires client certificate authentication", "II", g, "etcd --client-cert-auth=true (rke2 default)", list, func(n string) (Status, string) { return check(n, "client-cert-auth", "client-cert-auth", "true") })
	e.perNode("V-242426", "etcd requires peer certificate authentication", "II", g, "etcd --peer-client-cert-auth=true (rke2 default)", list, func(n string) (Status, string) { return check(n, "peer-client-cert-auth", "client-cert-auth", "true") })
	e.perNode("V-242379", "etcd auto-tls disabled", "II", g, "etcd --auto-tls=false", list, func(n string) (Status, string) { return check(n, "auto-tls", "auto-tls", "false") })
	e.perNode("V-242380", "etcd peer-auto-tls disabled", "II", g, "etcd --peer-auto-tls=false", list, func(n string) (Status, string) { return check(n, "peer-auto-tls", "auto-tls", "false") })
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

func (e *evaluator) kubeletRules() {
	g := "kubelet"
	var nodes []string
	for n := range e.in.Snap.KubeletConfigs {
		nodes = append(nodes, n)
	}
	cfg := func(n string) map[string]any { return e.in.Snap.KubeletConfigs[n] }
	fix := "rke2: kubelet-arg in config.yaml (profile: cis sets most); kubeadm: /var/lib/kubelet/config.yaml"
	if len(nodes) == 0 && e.in.Snap.KubeletCfgErr != "" {
		e.add(Result{ID: "kubelet", Title: "kubelet configuration readable via nodes/proxy configz", Cat: "-", Group: g, Status: Unknown, Detail: e.in.Snap.KubeletCfgErr, Fix: "grant get on nodes/proxy to read the running kubelet config"})
	}
	e.perNode("V-242391", "kubelet anonymous authentication disabled", "I", g, fix, nodes, func(n string) (Status, string) {
		v, _ := nested(cfg(n), "authentication", "anonymous", "enabled")
		if b, ok := v.(bool); ok && !b {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("authentication.anonymous.enabled=%v", v)
	})
	e.perNode("V-242392", "kubelet authorization mode is Webhook (not AlwaysAllow)", "I", g, fix, nodes, func(n string) (Status, string) {
		v, _ := nested(cfg(n), "authorization", "mode")
		if v == "Webhook" {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("authorization.mode=%v", v)
	})
	e.perNode("V-242387", "kubelet read-only port disabled", "I", g, fix, nodes, func(n string) (Status, string) {
		v, ok := cfg(n)["readOnlyPort"]
		if !ok {
			return Pass, ""
		}
		if f, isNum := v.(float64); isNum && f == 0 {
			return Pass, ""
		}
		return Fail, fmt.Sprintf("readOnlyPort=%v", v)
	})
	e.perNode("V-245541", "kubelet streaming connection idle timeout not disabled", "II", g, fix, nodes, func(n string) (Status, string) {
		v, ok := cfg(n)["streamingConnectionIdleTimeout"]
		if !ok {
			return Pass, "" // default 4h
		}
		if s, _ := v.(string); s == "0s" || s == "0" {
			return Fail, "streamingConnectionIdleTimeout=0"
		}
		return Pass, ""
	})
	e.perNode("V-242434", "kubelet protects kernel defaults", "I", g, "kubelet-arg: protect-kernel-defaults=true (requires the CIS sysctls, see node rules)", nodes, func(n string) (Status, string) {
		if b, _ := cfg(n)["protectKernelDefaults"].(bool); b {
			return Pass, ""
		}
		return Fail, "protectKernelDefaults=false"
	})
	e.perNode("CIS-4.2.6", "kubelet makes iptables util chains", "II", g, fix, nodes, func(n string) (Status, string) {
		v, ok := cfg(n)["makeIPTablesUtilChains"]
		if !ok {
			return Pass, ""
		}
		if b, _ := v.(bool); b {
			return Pass, ""
		}
		return Fail, "makeIPTablesUtilChains=false"
	})
	e.perNode("CIS-4.2.8", "kubelet event record QPS limited", "III", g, fix, nodes, func(n string) (Status, string) {
		v, ok := cfg(n)["eventRecordQPS"]
		if !ok {
			return Pass, ""
		}
		if f, _ := v.(float64); f == 0 {
			return Fail, "eventRecordQPS=0 (unlimited)"
		}
		return Pass, ""
	})
	e.perNode("CIS-4.2.12", "kubelet TLS cipher suites restricted", "II", g, "kubelet-arg: tls-cipher-suites=<approved list>", nodes, func(n string) (Status, string) {
		v, ok := cfg(n)["tlsCipherSuites"]
		if l, isList := v.([]any); ok && isList && len(l) > 0 {
			return Pass, ""
		}
		return Fail, "tlsCipherSuites not set"
	})
	e.perNode("CIS-4.2.10", "kubelet client certificate rotation enabled", "II", g, fix, nodes, func(n string) (Status, string) {
		if b, _ := cfg(n)["rotateCertificates"].(bool); b {
			return Pass, ""
		}
		return Fail, "rotateCertificates=false"
	})
	e.perNode("V-242420", "kubelet client CA file set (authentication.x509.clientCAFile)", "II", g, "kubelet-arg: client-ca-file=<ca> (rke2 sets this)", nodes, func(n string) (Status, string) {
		if v, _ := nested(cfg(n), "authentication", "x509", "clientCAFile"); v != nil && v != "" {
			return Pass, ""
		}
		return Fail, "authentication.x509.clientCAFile not set"
	})
	e.perNode("V-242425", "kubelet uses explicit TLS cert/key (or serving cert rotation)", "II", g, "kubelet-arg: tls-cert-file/tls-private-key-file (V-242424/V-242425), or serverTLSBootstrap", nodes, func(n string) (Status, string) {
		c := cfg(n)
		if s, _ := c["tlsCertFile"].(string); s != "" {
			return Pass, ""
		}
		if b, _ := c["serverTLSBootstrap"].(bool); b {
			return Pass, ""
		}
		if fg, ok := c["featureGates"].(map[string]any); ok {
			if b, _ := fg["RotateKubeletServerCertificate"].(bool); b {
				return Pass, ""
			}
		}
		return Manual, "self-signed serving cert in use; set tlsCertFile/tlsPrivateKeyFile or enable serverTLSBootstrap"
	})
	// hostname-override needs the process cmdline (SSH)
	var sshNodes []string
	for n, ni := range e.in.Nodes {
		if ni != nil && ni.Err == nil && len(ni.KubeletFlags) > 0 {
			sshNodes = append(sshNodes, n)
		}
	}
	if len(sshNodes) > 0 {
		e.perNode("V-242404", "kubelet hostname override not used", "II", g, "remove --hostname-override (rke2/k3s set it deliberately: N/A)", sshNodes, func(n string) (Status, string) {
			ni := e.in.Nodes[n]
			if ni.Dist == "rke2" || ni.Dist == "k3s" {
				return NA, ""
			}
			if v, ok := ni.KubeletFlags["hostname-override"]; ok {
				return Fail, "--hostname-override=" + v
			}
			return Pass, ""
		})
	}
}

func modeAtMost(mode string, max int) bool {
	n, err := strconv.ParseInt(mode, 8, 32)
	if err != nil {
		return false
	}
	return n&^int64(max) == 0
}

func (e *evaluator) nodeRules() {
	g := "node"
	var nodes []string
	for n, ni := range e.in.Nodes {
		if ni != nil && ni.Err == nil {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		e.add(Result{ID: "node", Title: "Node-level checks (sysctls, file permissions, rke2 profile)", Cat: "-", Group: g, Status: Unknown, Detail: "no SSH data", Fix: "enable SSH collection"})
		return
	}
	ni := func(n string) *nodeinfo.Info { return e.in.Nodes[n] }
	isRKE := func(n string) bool { d := ni(n).Dist; return d == "rke2" || d == "k3s" }

	e.perNode("V-254555", "rke2 CIS/STIG profile enabled (profile: cis)", "II", g, "config.yaml: profile: cis (requires etcd user + sysctls before restart); STIG also expects audit-policy-file and audit-log-mode=blocking-strict", nodes, func(n string) (Status, string) {
		if !isRKE(n) {
			return NA, ""
		}
		if v := ni(n).Settings["profile"]; strings.Contains(v, "cis") || strings.Contains(v, "etcd") {
			return Pass, ""
		}
		return Fail, "profile not set"
	})
	want := map[string]string{"vm.overcommit_memory": "1", "vm.panic_on_oom": "0", "kernel.panic": "10", "kernel.panic_on_oops": "1", "kernel.keys.root_maxbytes": "25000000", "kernel.keys.root_maxkeys": "1000000"}
	e.perNode("CIS-sysctl", "Kernel sysctls match kubelet protect-kernel-defaults expectations", "II", g, "cp /usr/local/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf && sysctl -p (or set the six values manually)", nodes, func(n string) (Status, string) {
		var bad []string
		for k, w := range want {
			if v := ni(n).Sysctl[k]; v != "" && v != w {
				bad = append(bad, k+"="+v)
			}
		}
		sort.Strings(bad)
		if len(bad) > 0 {
			return Fail, strings.Join(bad, ",")
		}
		return Pass, ""
	})
	e.perNode("V-242445", "etcd data directory owned by etcd user with mode 700", "II", g, "rke2: useradd -r -c 'etcd user' -s /sbin/nologin -M etcd -U; chown -R etcd:etcd <datadir>; chmod 700", nodes, func(n string) (Status, string) {
		info := ni(n)
		if !info.ControlPlane {
			return NA, ""
		}
		var p *nodeinfo.Perm
		for _, path := range []string{"/var/lib/rancher/rke2/server/db/etcd", "/var/lib/etcd"} {
			if p = info.Perm(path); p != nil {
				break
			}
		}
		if p == nil {
			return NA, ""
		}
		var probs []string
		if !modeAtMost(p.Mode, 0o700) {
			probs = append(probs, "mode "+p.Mode)
		}
		if isRKE(n) && p.User != "etcd" {
			probs = append(probs, "owner "+p.User)
		} else if !isRKE(n) && p.User != "etcd" && p.User != "root" {
			probs = append(probs, "owner "+p.User)
		}
		if len(probs) > 0 {
			return Fail, p.Path + ": " + strings.Join(probs, ", ")
		}
		return Pass, ""
	})
	e.perNode("RKE2-etcd-user", "etcd system user exists (rke2 CIS profile requirement)", "II", g, "useradd -r -c 'etcd user' -s /sbin/nologin -M etcd -U", nodes, func(n string) (Status, string) {
		info := ni(n)
		if !isRKE(n) || !info.ControlPlane {
			return NA, ""
		}
		if info.EtcdUser {
			return Pass, ""
		}
		return Fail, "no etcd user"
	})
	e.perNode("V-254564", "rke2/k3s config.yaml is root-owned with mode 600", "II", g, "chmod 600 /etc/rancher/rke2/config.yaml; chown root:root", nodes, func(n string) (Status, string) {
		info := ni(n)
		if !isRKE(n) {
			return NA, ""
		}
		var probs []string
		for _, p := range info.Perms {
			if strings.HasPrefix(p.Path, "/etc/rancher/rke2/config.yaml") || strings.HasPrefix(p.Path, "/etc/rancher/k3s/config.yaml") {
				if p.Type != "regular file" {
					continue
				}
				if !modeAtMost(p.Mode, 0o600) || p.User != "root" {
					probs = append(probs, fmt.Sprintf("%s %s %s", p.Path, p.Mode, p.User))
				}
			}
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("V-242460", "admin kubeconfig (rke2.yaml / admin.conf) not world-readable", "II", g, "rke2: write-kubeconfig-mode: \"0600\"; kubeadm: chmod 600 /etc/kubernetes/admin.conf", nodes, func(n string) (Status, string) {
		info := ni(n)
		var probs []string
		for _, path := range []string{"/etc/rancher/rke2/rke2.yaml", "/etc/rancher/k3s/k3s.yaml", "/etc/kubernetes/admin.conf"} {
			if p := info.Perm(path); p != nil && !modeAtMost(p.Mode, 0o640) {
				probs = append(probs, path+" "+p.Mode)
			}
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("V-242408", "Static pod manifests are root-owned with mode 644 or stricter", "II", g, "chmod 644 and chown root:root the manifest files", nodes, func(n string) (Status, string) {
		info := ni(n)
		var probs []string
		found := false
		for _, p := range info.Perms {
			if (strings.HasPrefix(p.Path, "/var/lib/rancher/rke2/agent/pod-manifests/") || strings.HasPrefix(p.Path, "/etc/kubernetes/manifests/")) && p.Type == "regular file" {
				found = true
				if !modeAtMost(p.Mode, 0o644) || p.User != "root" || p.Group != "root" {
					probs = append(probs, fmt.Sprintf("%s %s %s:%s", p.Path, p.Mode, p.User, p.Group))
				}
			}
		}
		if !found {
			return NA, ""
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("V-242466", "PKI certificate files have mode 644 or stricter", "II", g, "chmod 644 *.crt", nodes, func(n string) (Status, string) {
		info := ni(n)
		var probs []string
		found := false
		for _, p := range info.Perms {
			if strings.HasSuffix(p.Path, ".crt") && p.Type == "regular file" {
				found = true
				if !modeAtMost(p.Mode, 0o644) {
					probs = append(probs, p.Path+" "+p.Mode)
				}
			}
		}
		if !found {
			return NA, ""
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("V-242467", "PKI private keys have mode 600", "II", g, "chmod 600 *.key", nodes, func(n string) (Status, string) {
		info := ni(n)
		var probs []string
		found := false
		for _, p := range info.Perms {
			if strings.HasSuffix(p.Path, ".key") && p.Type == "regular file" {
				found = true
				if !modeAtMost(p.Mode, 0o600) {
					probs = append(probs, p.Path+" "+p.Mode)
				}
			}
		}
		if !found {
			return NA, ""
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("V-242456", "kubelet config / kubeconfig files root-owned, mode 644 or stricter", "II", g, "chmod 644, chown root:root", nodes, func(n string) (Status, string) {
		info := ni(n)
		var probs []string
		found := false
		for _, path := range []string{"/var/lib/kubelet/config.yaml", "/var/lib/kubelet/kubeconfig", "/etc/kubernetes/kubelet.conf", "/var/lib/rancher/rke2/agent/kubelet.kubeconfig", "/var/lib/rancher/rke2/agent/kubeproxy.kubeconfig"} {
			if p := info.Perm(path); p != nil {
				found = true
				if !modeAtMost(p.Mode, 0o644) || p.User != "root" {
					probs = append(probs, fmt.Sprintf("%s %s %s", path, p.Mode, p.User))
				}
			}
		}
		if !found {
			return NA, ""
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("CIS-1.1.9", "CNI configuration files root-owned, mode 600 or stricter", "III", g, "chmod 600 /etc/cni/net.d/*", nodes, func(n string) (Status, string) {
		info := ni(n)
		var probs []string
		found := false
		for _, p := range info.Perms {
			if strings.Contains(p.Path, "/cni/net.d/") && p.Type == "regular file" {
				found = true
				if !modeAtMost(p.Mode, 0o600) || p.User != "root" {
					probs = append(probs, fmt.Sprintf("%s %s %s", p.Path, p.Mode, p.User))
				}
			}
		}
		if !found {
			return NA, ""
		}
		if len(probs) > 0 {
			return Fail, strings.Join(probs, "; ")
		}
		return Pass, ""
	})
	e.perNode("RKE2-selinux", "SELinux enforcing (rke2 hardening guide)", "III", g, "config.yaml: selinux: true and install rke2-selinux", nodes, func(n string) (Status, string) {
		info := ni(n)
		switch strings.ToLower(info.SELinux) {
		case "enforcing":
			return Pass, ""
		case "":
			return Manual, "getenforce unavailable (SELinux not installed?)"
		default:
			return Fail, "SELinux " + info.SELinux
		}
	})
	e.perNode("CIS-swap", "Swap disabled on nodes", "III", g, "swapoff -a and remove from fstab", nodes, func(n string) (Status, string) {
		if ni(n).SwapTotal > 0 {
			return Fail, "swap enabled"
		}
		return Pass, ""
	})
	// OS hardening (per node)
	e.perNode("OS-fips", "Kernel running in FIPS mode", "II", g, "RHEL: fips-mode-setup --enable && reboot; Ubuntu: pro enable fips-updates; rke2: also set profile/cipher suites", nodes, func(n string) (Status, string) {
		h := ni(n).Hardening
		switch h["fips"] {
		case "1":
			if h["fips_boot"] == "no" && !strings.Contains(strings.ToLower(h["ubuntu_pro"]), "fips") {
				return Fail, "FIPS on now but fips=1 missing from grub/kernel cmdline config: lost on reboot"
			}
			return Pass, ""
		case "0":
			if h["fips_boot"] == "yes" {
				return Fail, "fips_enabled=0 now, but fips=1 configured for next boot (reboot pending?)"
			}
			return Fail, "fips_enabled=0"
		}
		return Manual, "/proc/sys/crypto/fips_enabled not readable"
	})
	e.perNode("OS-mac", "Mandatory access control enforcing (SELinux or AppArmor)", "II", g, "RHEL: SELINUX=enforcing (+ rke2-selinux); Ubuntu: AppArmor enabled with profiles enforced", nodes, func(n string) (Status, string) {
		info := ni(n)
		h := info.Hardening
		if strings.EqualFold(h["selinux"], "Enforcing") {
			if cfg := h["selinux_config"]; cfg != "" && !strings.EqualFold(cfg, "enforcing") {
				return Fail, "enforcing now but /etc/selinux/config SELINUX=" + cfg + " (reverts on reboot)"
			}
			return Pass, ""
		}
		if h["apparmor"] == "Y" {
			if h["apparmor_enforced"] == "0" {
				return Fail, "AppArmor enabled but no profiles enforced"
			}
			return Pass, ""
		}
		if h["selinux"] != "" {
			return Fail, "SELinux " + h["selinux"] + " (config " + h["selinux_config"] + ")"
		}
		return Fail, "neither SELinux enforcing nor AppArmor enabled"
	})
	e.perNode("OS-fapolicyd", "Application allow-listing (fapolicyd) active on RHEL-family nodes", "II", g, "dnf install fapolicyd && systemctl enable --now fapolicyd (add container runtime paths to rules.d)", nodes, func(n string) (Status, string) {
		info := ni(n)
		if info.OS.Family() != "rhel" {
			return NA, ""
		}
		switch info.ServiceState("fapolicyd") {
		case "active":
			if en := info.ServiceEnabled("fapolicyd"); en == "disabled" || en == "masked" {
				return Fail, "fapolicyd active now but " + en + " at boot"
			}
			return Pass, ""
		case "":
			return Fail, "fapolicyd not installed"
		default:
			if info.ServiceEnabled("fapolicyd") == "enabled" {
				return Fail, "fapolicyd " + info.ServiceState("fapolicyd") + " now (enabled at boot: stopped manually?)"
			}
			return Fail, "fapolicyd " + info.ServiceState("fapolicyd") + "/" + info.ServiceEnabled("fapolicyd")
		}
	})
	e.perNode("OS-auditd", "Audit daemon active", "II", g, "systemctl enable --now auditd; load STIG audit rules", nodes, func(n string) (Status, string) {
		info := ni(n)
		switch info.ServiceState("auditd") {
		case "active":
			if r := info.Hardening["audit_rules"]; r == "0" {
				return Fail, "auditd active but no rules loaded"
			}
			if en := info.ServiceEnabled("auditd"); en == "disabled" || en == "masked" {
				return Fail, "auditd active now but " + en + " at boot"
			}
			return Pass, ""
		case "":
			return Fail, "auditd not installed"
		default:
			return Fail, "auditd " + info.ServiceState("auditd")
		}
	})
	e.perNode("OS-firewall", "Host firewall active (firewalld / ufw)", "II", g, "firewalld or ufw with the Kubernetes/rke2 ports opened", nodes, func(n string) (Status, string) {
		info := ni(n)
		if info.ServiceState("firewalld") == "active" || info.ServiceState("ufw") == "active" || strings.HasPrefix(info.Hardening["ufw"], "active") {
			if en := info.ServiceEnabled("firewalld"); en == "disabled" || en == "masked" {
				return Fail, "firewalld active now but " + en + " at boot"
			}
			if info.Hardening["ufw_config"] == "no" && strings.HasPrefix(info.Hardening["ufw"], "active") {
				return Fail, "ufw active now but ENABLED=no in /etc/ufw/ufw.conf"
			}
			return Pass, ""
		}
		if info.ServiceEnabled("firewalld") == "enabled" {
			return Fail, "firewalld enabled at boot but not active now"
		}
		if info.ServiceState("firewalld") == "" && info.ServiceState("ufw") == "" && info.Hardening["ufw"] == "" {
			return Manual, "no firewalld/ufw found (nftables/iptables managed elsewhere?)"
		}
		return Fail, "firewall inactive"
	})
	e.perNode("OS-reboot", "No pending reboot (kernel/security updates applied)", "III", g, "reboot the node in a maintenance window", nodes, func(n string) (Status, string) {
		if ni(n).Hardening["reboot_required"] == "yes" {
			return Fail, "reboot required"
		}
		return Pass, ""
	})
	e.perNode("OS-secureboot", "UEFI Secure Boot enabled", "III", g, "enable Secure Boot in firmware (signed kernel/modules required)", nodes, func(n string) (Status, string) {
		sb := ni(n).Hardening["secureboot"]
		switch {
		case strings.Contains(sb, "enabled"):
			return Pass, ""
		case sb == "":
			return Manual, "mokutil not available / BIOS boot"
		}
		return Fail, sb
	})
}

func (e *evaluator) clusterRules() {
	g := "cluster"
	s := e.in.Snap

	// V-242383 default namespace
	var def []string
	for i := range s.Pods {
		if s.Pods[i].Namespace == "default" {
			def = append(def, s.Pods[i].Name)
		}
	}
	r := Result{ID: "V-242383", Title: "User workloads not deployed in the default namespace", Cat: "I", Group: g, Status: Pass, Detail: "no pods in default", Fix: "move workloads to dedicated namespaces"}
	if len(def) > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d pod(s) in default: %s", len(def), truncList(def, 5))
	}
	e.add(r)

	// PSA labels
	psaCluster := false
	for _, f := range e.apiserver {
		if f["admission-control-config-file"] != "" || f["pod-security-admission-config-file"] != "" {
			psaCluster = true
		}
	}
	var noPSA []string
	for _, ns := range s.Namespaces {
		if k8s.IsSystemNamespace(ns.Name) {
			continue
		}
		if ns.Labels["pod-security.kubernetes.io/enforce"] == "" {
			noPSA = append(noPSA, ns.Name)
		}
	}
	r = Result{ID: "V-254800-ns", Title: "Namespaces enforce a Pod Security Standard", Cat: "I", Group: g, Status: Pass, Fix: "label namespaces: pod-security.kubernetes.io/enforce=restricted (or baseline), or use a cluster-wide admission config"}
	switch {
	case len(noPSA) == 0:
		r.Detail = "all user namespaces labelled"
	case psaCluster:
		r.Status = Manual
		r.Detail = fmt.Sprintf("cluster-wide PSA config present; %d namespace(s) rely on the default: %s", len(noPSA), truncList(noPSA, 6))
	default:
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d namespace(s) without enforce label: %s", len(noPSA), truncList(noPSA, 6))
	}
	e.add(r)

	// dashboard
	r = Result{ID: "V-242395", Title: "Kubernetes Dashboard not installed", Cat: "II", Group: g, Status: Pass, Detail: "not found", Fix: "uninstall kubernetes-dashboard"}
	for i := range s.Deployments {
		if strings.Contains(s.Deployments[i].Name, "kubernetes-dashboard") {
			r.Status = Fail
			r.Detail = s.Deployments[i].Namespace + "/" + s.Deployments[i].Name
		}
	}
	e.add(r)

	// cluster-admin bindings
	var subjects []string
	for i := range s.CRBs {
		b := &s.CRBs[i]
		if b.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, sub := range b.Subjects {
			if sub.Kind == "Group" && sub.Name == "system:masters" {
				continue
			}
			subjects = append(subjects, fmt.Sprintf("%s/%s (via %s)", sub.Kind, sub.Name, b.Name))
		}
	}
	r = Result{ID: "CIS-5.1.1", Title: "cluster-admin role bindings minimised", Cat: "II", Group: g, Status: Pass, Detail: "only system:masters", Fix: "review and remove unnecessary cluster-admin bindings"}
	if len(subjects) > 0 {
		r.Status = Manual
		r.Detail = fmt.Sprintf("%d subject(s): %s", len(subjects), truncList(subjects, 6))
	}
	e.add(r)

	// privileged / host namespaces outside system namespaces
	var priv, hostNS, secretEnv []string
	for i := range s.Pods {
		p := &s.Pods[i]
		sys := k8s.IsSystemNamespace(p.Namespace)
		ref := p.Namespace + "/" + p.Name
		for _, c := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged && !sys {
				priv = append(priv, ref)
				break
			}
		}
		if (p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC) && !sys {
			hostNS = append(hostNS, ref)
		}
		for _, c := range p.Spec.Containers {
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					secretEnv = append(secretEnv, ref)
					break
				}
			}
		}
	}
	r = Result{ID: "CIS-5.2.2", Title: "No privileged containers outside system namespaces", Cat: "II", Group: g, Status: Pass, Detail: "none", Fix: "remove privileged: true or move to a system namespace with PSA privileged"}
	if len(priv) > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d pod(s): %s", len(priv), truncList(uniq(priv), 5))
	}
	e.add(r)
	r = Result{ID: "CIS-5.2.3", Title: "No host PID/IPC/network pods outside system namespaces (CIS 5.2.3-5.2.5)", Cat: "II", Group: g, Status: Pass, Detail: "none", Fix: "remove hostNetwork/hostPID/hostIPC"}
	if len(hostNS) > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d pod(s): %s", len(hostNS), truncList(uniq(hostNS), 5))
	}
	e.add(r)
	r = Result{ID: "V-242415", Title: "Secrets are not exposed as environment variables", Cat: "I", Group: g, Status: Pass, Detail: "none", Fix: "mount secrets as files instead of env vars"}
	if len(secretEnv) > 0 {
		r.Status = Manual
		r.Detail = fmt.Sprintf("%d pod(s) use secretKeyRef env: %s", len(secretEnv), truncList(uniq(secretEnv), 5))
	}
	e.add(r)

	// network policies
	hasNP := map[string]bool{}
	for i := range s.NetPols {
		hasNP[s.NetPols[i].Namespace] = true
	}
	var noNP []string
	for _, ns := range s.Namespaces {
		if !k8s.IsSystemNamespace(ns.Name) && !hasNP[ns.Name] {
			noNP = append(noNP, ns.Name)
		}
	}
	r = Result{ID: "CIS-5.3.2", Title: "All user namespaces have NetworkPolicies", Cat: "III", Group: g, Status: Pass, Detail: "all covered", Fix: "add a default-deny NetworkPolicy per namespace"}
	if len(noNP) > 0 {
		r.Status = Manual
		r.Detail = fmt.Sprintf("%d namespace(s) without: %s", len(noNP), truncList(noNP, 6))
	}
	e.add(r)

	// version currency
	e.add(Result{ID: "V-242443", Title: "Kubernetes is a supported, patched version", Cat: "II", Group: g, Status: Manual, Detail: "cluster " + s.Version + " - verify against the current upstream support window (three most recent minors) and rke2 release notes", Fix: "upgrade"})

	// default service account automount
	var autoSA []string
	for i := range s.Pods {
		p := &s.Pods[i]
		if k8s.IsSystemNamespace(p.Namespace) {
			continue
		}
		if (p.Spec.ServiceAccountName == "" || p.Spec.ServiceAccountName == "default") && (p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken) {
			autoSA = append(autoSA, p.Namespace+"/"+p.Name)
		}
	}
	r = Result{ID: "CIS-5.1.6", Title: "Pods do not use the default ServiceAccount with automounted tokens", Cat: "III", Group: g, Status: Pass, Detail: "none", Fix: "use dedicated service accounts; automountServiceAccountToken: false"}
	if len(autoSA) > 0 {
		r.Status = Manual
		r.Detail = fmt.Sprintf("%d pod(s): %s", len(autoSA), truncList(autoSA, 5))
	}
	e.add(r)
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
