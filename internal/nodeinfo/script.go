// Package nodeinfo collects host-level facts from cluster nodes over SSH:
// resources, disks, services, certificates, security settings, registries,
// images and (in heavy mode) journal logs.
package nodeinfo

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/perf"
	"github.com/zlmitchell/khealth-tui/internal/stigdata"
)

// Options controls what the node script collects.
type Options struct {
	// The demand tiers (docs/ARCHITECTURE.md §7): each is a guarded block
	// of heavy.sh / preflight.sh that a tab asks for, R forces, or the
	// background floor runs; Info.Merge* carries the previous result
	// forward when a probe leaves one out.
	Journal       bool     // journal + rke2 log files (Logs tab, log findings) and the fapolicyd denials
	Images        bool     // crictl images/ps, tarball manifests, registry pull dry run (Images tab)
	PVs           bool     // du of hostPath/local PV directories (Storage tab)
	KubeletPID    int      // kubelet pid seen by the previous probe (skips the /proc scan while it is still the kubelet)
	CPUSample     bool     // sample /proc/stat twice with a 1 s sleep (first contact only; later probes diff against the previous one)
	Config        bool     // include the config tier of the base script: certs, sysctls, file modes, slow hardening commands, rke2/k3s config, manifests, registries (first contact / R / RKE2 and Security tabs; carried forward otherwise by Info.MergeConfig)
	OSStig        bool     // include the OS STIG facts (sysctl -a, packages, units, mounts, sshd -T, audit rules, stat/find scans, config dumps)
	LogLines      int      // journalctl -n
	LogSince      string   // journalctl --since
	KnownTarballs []string // "path|size|mtime" entries whose manifests are already known
	PVPaths       []string // hostPath/local PV directories to measure with du (PVs tier)
	VCenters      []string // vCenter host[:port]s from the vSphere CPI config, probed from the node (config tier)
	// network probe targets (config tier): one "node=podIP" per node for the
	// overlay ping, the CoreDNS pod IPs, the DNS and kubernetes service IPs
	NetTargets []string
	DNSPods    []string
	DNSIP      string
	APISvcIP   string
}

// Heavy reports whether any demand tier is on (the heavy.sh part runs).
func (o Options) Heavy() bool { return o.Journal || o.Images || o.PVs }

// Tiers names the tiers on, for the perf log ("journal+images").
func (o Options) Tiers() string {
	var t []string
	if o.Journal {
		t = append(t, "journal")
	}
	if o.Images {
		t = append(t, "images")
	}
	if o.PVs {
		t = append(t, "pv")
	}
	if o.Config {
		t = append(t, "config")
	}
	if o.OSStig {
		t = append(t, "stig")
	}
	return strings.Join(t, "+")
}

var safeHost = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}(:[0-9]{1,5})?$`)

var safeSince = regexp.MustCompile(`^[-+0-9a-zA-Z: ]{1,40}$`)
var safePath = regexp.MustCompile(`^/[A-Za-z0-9_./@:+-]{1,400}$`)

// Script returns the POSIX sh script executed on each node.
func Script(o Options) string {
	since := o.LogSince
	if !safeSince.MatchString(since) {
		since = "-24h"
	}
	lines := o.LogLines
	if lines <= 0 || lines > 5000 {
		lines = 400
	}
	known := strings.Join(o.KnownTarballs, "|")
	known = strings.ReplaceAll(known, "'", "")
	var paths []string
	for _, pp := range o.PVPaths {
		if safePath.MatchString(pp) {
			paths = append(paths, pp)
		}
	}

	var b strings.Builder
	b.WriteString(AsYAMLShell)
	base := strings.ReplaceAll(baseScript, "__CONFIG__", map[bool]string{true: "1", false: "0"}[o.Config])
	base = strings.ReplaceAll(base, "__CPUSAMPLE__", map[bool]string{true: "1", false: "0"}[o.CPUSample])
	base = strings.ReplaceAll(base, "__KPID__", fmt.Sprint(max(o.KubeletPID, 0)))
	base = strings.ReplaceAll(base, "__NETTARGETS__", strings.Join(netTargets(o.NetTargets), " "))
	base = strings.ReplaceAll(base, "__DNSPODS__", strings.Join(ips(o.DNSPods), " "))
	base = strings.ReplaceAll(base, "__DNSIP__", ipOrEmpty(o.DNSIP))
	base = strings.ReplaceAll(base, "__APISVC__", ipOrEmpty(o.APISvcIP))
	b.WriteString(base)
	pf := strings.ReplaceAll(preflightScript, "__CONFIG__", map[bool]string{true: "1", false: "0"}[o.Config])
	pf = strings.ReplaceAll(pf, "__IMAGES__", map[bool]string{true: "1", false: "0"}[o.Images])
	pf = strings.ReplaceAll(pf, "__JOURNAL__", map[bool]string{true: "1", false: "0"}[o.Journal])
	var vcs []string
	for _, h := range o.VCenters {
		if safeHost.MatchString(h) {
			vcs = append(vcs, h)
		}
	}
	b.WriteString(strings.ReplaceAll(pf, "__VCENTERS__", strings.Join(vcs, " ")))
	if o.OSStig {
		for _, st := range stigStages {
			b.WriteString(st.script())
		}
	}
	if o.Heavy() {
		h := strings.ReplaceAll(heavyScript, "__LINES__", fmt.Sprint(lines))
		h = strings.ReplaceAll(h, "__SINCE__", since)
		h = strings.ReplaceAll(h, "__KNOWN__", known)
		h = strings.ReplaceAll(h, "__PVPATHS__", strings.Join(paths, " "))
		h = strings.ReplaceAll(h, "__IMAGES__", map[bool]string{true: "1", false: "0"}[o.Images])
		h = strings.ReplaceAll(h, "__PVS__", map[bool]string{true: "1", false: "0"}[o.PVs])
		h = strings.ReplaceAll(h, "__JOURNAL__", map[bool]string{true: "1", false: "0"}[o.Journal])
		b.WriteString(h)
	}
	b.WriteString(perf.Footer)
	b.WriteString("echo '===END'\n")
	return b.String()
}

//go:embed scripts/base.sh
var baseScript string

// AsYAMLShell defines j2y / asyaml / isjson / jsonnote: the JSON-to-YAML
// step for the files Rancher delivers as JSON (config.yaml.d/50-rancher.yaml,
// registries.yaml). Every probe script that reads those files starts with
// it (the node probe here, the etcd probe in package etcd).
//
//go:embed scripts/asyaml.sh
var AsYAMLShell string

// osStigScript collects the generic facts the OS STIG templates evaluate
// (see internal/stigdata); the data-derived stat/find/dump sections are
// appended by stigdata.ProbeScript.
//
//go:embed scripts/os_stig.sh
var osStigScript string

//go:embed scripts/os_stig_facts.sh
var osStigFactsScript string

//go:embed scripts/os_stig_sweep.sh
var osStigSweepScript string

// STIGStage is one slice of the OS STIG collection. The Security scan
// (Shift+S) runs the stages one after the other per node, each as its own
// script over SSH, so the checklist can show how far every node is and the
// filesystem sweep (the slow part on a big node) gets a timeout of its own
// instead of holding the sysctl/package/audit facts hostage. Options.OSStig
// still concatenates all of them into one script (perfbench, headless tools).
type STIGStage struct {
	Name   string // system | files | accounts | sweep
	Label  string // what the stage collects, for the checklist
	Slow   bool   // may run for minutes on a large filesystem: gets the long probe timeout
	script func() string
}

var stigStages = []STIGStage{
	{Name: "system", Label: "sysctl -a, packages, units, mounts, sshd -T, audit rules, modules, boot args", script: func() string { return osStigScript }},
	{Name: "files", Label: "file modes and owners, directory scans, config dumps", script: stigdata.ProbeScript},
	{Name: "accounts", Label: "crypto policy, firewall, AIDE, GRUB, accounts and password ages", script: func() string { return osStigFactsScript }},
	{Name: "sweep", Label: "filesystem sweep: world-writable, unowned, home directories, audit logs", Slow: true, script: func() string { return osStigSweepScript }},
}

// STIGStages lists the stages in run order.
func STIGStages() []STIGStage {
	out := make([]STIGStage, len(stigStages))
	copy(out, stigStages)
	return out
}

// STIGStageScript returns the script for one stage: the base prelude
// (sec/mask helpers, data-dir detection), the stage's sections and the
// perf footer. "" for an unknown stage.
func STIGStageScript(name string) string {
	for _, st := range stigStages {
		if st.Name != name {
			continue
		}
		var b strings.Builder
		b.WriteString(scriptPrelude())
		b.WriteString(st.script())
		b.WriteString(perf.Footer)
		b.WriteString("echo '===END'\n")
		return b.String()
	}
	return ""
}

// scriptPrelude is the head of base.sh up to its first section: the sec
// and mask helpers every script needs, defined once in base.sh.
func scriptPrelude() string {
	if i := strings.Index(baseScript, "sec DATADIR"); i > 0 {
		return baseScript[:i]
	}
	return baseScript
}

//go:embed scripts/heavy.sh
var heavyScript string

// preflightScript collects the facts behind the "will rke2 keep running /
// can this node be re-provisioned" findings (swap, fapolicyd, auditd disk
// actions, account expiry, proxies, vSphere cloud-init ISO, registry
// credentials); see preflight.go.
//
//go:embed scripts/preflight.sh
var preflightScript string

var safeIP = regexp.MustCompile(`^[0-9a-fA-F.:]{2,45}$`)
var safeNode = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)

// netTargets keeps the "node=ip" entries that are safe to paste into the
// script.
func netTargets(in []string) []string {
	var out []string
	for _, t := range in {
		n, ip, ok := strings.Cut(t, "=")
		if ok && safeNode.MatchString(n) && safeIP.MatchString(ip) {
			out = append(out, n+"="+ip)
		}
	}
	return out
}

func ips(in []string) []string {
	var out []string
	for _, ip := range in {
		if safeIP.MatchString(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func ipOrEmpty(ip string) string {
	if safeIP.MatchString(ip) {
		return ip
	}
	return ""
}
