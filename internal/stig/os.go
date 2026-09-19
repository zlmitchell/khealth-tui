package stig

// DISA operating-system STIGs (RHEL 8/9/10, Ubuntu 20.04/22.04/24.04) applied
// per node from /etc/os-release. Every rule of the matched STIG is emitted:
//
//   - hand-written checks (this file, keyed by rhel.go / ubuntu.go) win when
//     they exist, because they carry runtime-vs-boot detail;
//   - otherwise the ComplianceAsCode template checks embedded in
//     internal/stigdata are evaluated (ostemplates.go);
//   - rules with no automatable check are reported MANUAL with the STIG's
//     own check text.
//
// Nodes whose OS has no table fall back to generic OS-* rule IDs.

import (
	"fmt"
	"sort"
	"strings"

	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stigdata"
)

// OSBenchmark is one DISA OS STIG release: the embedded table plus the
// hand-written overrides for facts the node probe collects directly.
type OSBenchmark struct {
	Name    string
	Version string
	product string // stigdata product: rhel9, ubuntu2204 ...
	family  string // "rhel" or "ubuntu"
	release string // VERSION_ID prefix: "8", "9", "10", "20.04", ...
	rules   map[string]osRef
}

// Table returns the embedded rule table (nil when none is embedded).
func (b *OSBenchmark) Table() *stigdata.Table {
	t, err := stigdata.Load(b.product)
	if err != nil {
		return nil
	}
	return t
}

// Coverage summarises how the table's rules are evaluated.
func (b *OSBenchmark) Coverage() (total, automated int) {
	t := b.Table()
	if t == nil {
		return len(b.rules), len(b.rules)
	}
	override := b.overrides()
	for _, r := range t.Rules {
		total++
		if _, ok := override[r.VID]; ok || templated(r) {
			automated++
		}
	}
	return total, automated
}

// overrides maps vulnerability IDs to hand-written checks.
func (b *OSBenchmark) overrides() map[string]osCheck {
	byKey := map[string]osCheck{}
	for _, c := range osChecks {
		byKey[c.key] = c
	}
	out := map[string]osCheck{}
	for key, ref := range b.rules {
		if c, ok := byKey[key]; ok {
			out[ref.ID] = c
		}
	}
	return out
}

func templated(r stigdata.Rule) bool {
	for _, c := range r.Checks {
		if _, ok := templateEvals[c.Template]; ok {
			return true
		}
	}
	return false
}

type osRef struct {
	ID  string
	Cat string
}

// OSBenchmarks lists the OS STIG tables in match order.
var OSBenchmarks = append(append([]OSBenchmark{}, rhelBenchmarks...), ubuntuBenchmarks...)

// OSBenchmarkFor picks the OS STIG for a node, or nil when none applies
// (SLES, Flatcar, unknown, no SSH data). RHEL derivatives (Rocky, Alma,
// CentOS Stream, Oracle) are audited against the RHEL STIG of the same major.
func OSBenchmarkFor(os nodeinfo.OSRelease) *OSBenchmark {
	family := ""
	switch {
	case os.ID == "ubuntu":
		family = "ubuntu"
	case rhelLike(os):
		family = "rhel"
	default:
		return nil
	}
	major := os.VersionID
	if family == "rhel" {
		major, _, _ = strings.Cut(major, ".")
	}
	for i := range OSBenchmarks {
		b := &OSBenchmarks[i]
		if b.family == family && b.release == major {
			return b
		}
	}
	return nil
}

func (b *OSBenchmark) String() string { return b.Name + " " + b.Version }

// evalTemplated runs every template check behind a rule on one node. Any
// failure fails the rule; a rule that also carries an untemplated (custom
// OVAL) check is reported Manual when its automated part passes, because
// only part of it was verified.
func evalTemplated(info *nodeinfo.Info, rule stigdata.Rule) (Status, string) {
	var fails, manuals, custom []string
	passes, nas := 0, 0
	for i, c := range rule.Checks {
		ev, ok := templateEvals[c.Template]
		if !ok {
			if c.Template == "" {
				custom = append(custom, c.Rule)
			} else {
				manuals = append(manuals, c.Rule+": template "+c.Template+" not supported")
			}
			continue
		}
		st, detail := ev(info, c, stigdata.CheckID(rule.VID, i))
		switch st {
		case Pass:
			passes++
		case NA:
			nas++
		case Fail:
			fails = append(fails, detail)
		default:
			manuals = append(manuals, detail)
		}
	}
	switch {
	case len(fails) > 0:
		return Fail, strings.Join(fails, "; ")
	case len(manuals) > 0:
		return Manual, strings.Join(manuals, "; ")
	case len(custom) > 0 && passes > 0:
		return Manual, "automated part passes; verify " + truncList(custom, 3) + " manually"
	case passes > 0:
		return Pass, ""
	case nas > 0:
		return NA, ""
	}
	return Manual, "nothing evaluated"
}

// rhelLike is true for RHEL and its rebuilds, but not SUSE (which
// nodeinfo folds into the "rhel" family for package-manager purposes).
func rhelLike(os nodeinfo.OSRelease) bool {
	return os.Family() == "rhel" && !strings.Contains(strings.ToLower(os.ID+" "+os.IDLike), "suse")
}

// osCheck is one automatable OS fact.
type osCheck struct {
	key   string // rule table key
	id    string // generic fallback ID
	cat   string // generic fallback category
	title string
	fix   string
	eval  func(info *nodeinfo.Info) (Status, string)
}

// sysctlEq builds a check for a single kernel parameter value.
func sysctlEq(key, param, want, id, title, cat string) osCheck {
	return osCheck{key: key, id: id, cat: cat, title: title, fix: "sysctl -w " + param + "=" + want + " and persist in /etc/sysctl.d/", eval: func(info *nodeinfo.Info) (Status, string) {
		v, ok := info.Sysctl[param]
		if !ok || v == "" {
			return Manual, param + " not collected (older probe or unsupported kernel)"
		}
		if v == want {
			return Pass, ""
		}
		return Fail, param + "=" + v
	}}
}

// osChecks are evaluated for every SSH-reachable node. Order is the display
// order within the group.
var osChecks = []osCheck{
	{key: "fips", id: "OS-fips", cat: "I", title: "Kernel running in FIPS mode", fix: "RHEL: fips-mode-setup --enable && reboot; Ubuntu: pro enable fips-updates; rke2: also set profile/cipher suites", eval: func(info *nodeinfo.Info) (Status, string) {
		h := info.Hardening
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
	}},
	{key: "mac", id: "OS-mac", cat: "II", title: "Mandatory access control enforcing (SELinux / AppArmor)", fix: "RHEL: SELINUX=enforcing (+ rke2-selinux); Ubuntu: apparmor.service enabled with profiles enforced", eval: func(info *nodeinfo.Info) (Status, string) {
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
			if en := info.ServiceEnabled("apparmor"); en == "disabled" || en == "masked" {
				return Fail, "AppArmor enabled now but apparmor.service " + en + " at boot"
			}
			return Pass, ""
		}
		if h["selinux"] != "" {
			return Fail, "SELinux " + h["selinux"] + " (config " + h["selinux_config"] + ")"
		}
		return Fail, "neither SELinux enforcing nor AppArmor enabled"
	}},
	{key: "fapolicyd", id: "OS-fapolicyd", cat: "II", title: "Application allow-listing (fapolicyd) active", fix: "dnf install fapolicyd && systemctl enable --now fapolicyd (add container runtime paths to rules.d)", eval: func(info *nodeinfo.Info) (Status, string) {
		if !rhelLike(info.OS) {
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
	}},
	{key: "auditd", id: "OS-auditd", cat: "II", title: "Audit daemon enabled and active", fix: "systemctl enable --now auditd; load STIG audit rules", eval: func(info *nodeinfo.Info) (Status, string) {
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
	}},
	{key: "firewall", id: "OS-firewall", cat: "II", title: "Host firewall active (firewalld / ufw)", fix: "firewalld or ufw with the Kubernetes/rke2 ports opened", eval: func(info *nodeinfo.Info) (Status, string) {
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
	}},
	{key: "usbguard", id: "OS-usbguard", cat: "II", title: "USBGuard enabled and active", fix: "dnf install usbguard && systemctl enable --now usbguard (generate a policy first: usbguard generate-policy)", eval: func(info *nodeinfo.Info) (Status, string) {
		if !rhelLike(info.OS) {
			return NA, ""
		}
		switch info.ServiceState("usbguard") {
		case "active":
			if en := info.ServiceEnabled("usbguard"); en == "disabled" || en == "masked" {
				return Fail, "usbguard active now but " + en + " at boot"
			}
			return Pass, ""
		case "":
			return Fail, "usbguard not installed"
		default:
			return Fail, "usbguard " + info.ServiceState("usbguard")
		}
	}},
	{key: "timesync", id: "OS-timesync", cat: "II", title: "Clock synchronised with an authoritative time source (chrony)", fix: "install chrony, point it at the approved NTP servers (maxpoll 16) and enable chronyd", eval: func(info *nodeinfo.Info) (Status, string) {
		chrony := info.ServiceState("chronyd")
		if chrony == "" {
			chrony = info.ServiceState("chrony")
		}
		if info.NTPSynced != nil {
			if *info.NTPSynced {
				if chrony == "" && info.ServiceState("systemd-timesyncd") != "" {
					return Manual, "synchronised via systemd-timesyncd (STIG expects chrony)"
				}
				return Pass, ""
			}
			return Fail, "clock not synchronised"
		}
		if chrony == "active" {
			return Pass, ""
		}
		return Manual, "timedatectl not available and chronyd not active"
	}},
	sysctlEq("aslr", "kernel.randomize_va_space", "2", "OS-aslr", "Address space layout randomisation enabled", "II"),
	sysctlEq("dmesg", "kernel.dmesg_restrict", "1", "OS-dmesg", "Kernel message buffer restricted to root", "III"),
	sysctlEq("kptr", "kernel.kptr_restrict", "1", "OS-kptr", "Kernel pointer addresses hidden", "II"),
	sysctlEq("ptrace", "kernel.yama.ptrace_scope", "1", "OS-ptrace", "ptrace restricted to descendant processes", "II"),
	sysctlEq("core_pattern", "kernel.core_pattern", "|/bin/false", "OS-core", "Core dumps disabled (kernel.core_pattern)", "II"),
	sysctlEq("protected_symlinks", "fs.protected_symlinks", "1", "OS-symlinks", "DAC enforced on symlinks", "II"),
	sysctlEq("protected_hardlinks", "fs.protected_hardlinks", "1", "OS-hardlinks", "DAC enforced on hardlinks", "II"),
	sysctlEq("accept_redirects_all", "net.ipv4.conf.all.accept_redirects", "0", "OS-redirects", "IPv4 ICMP redirects ignored (all interfaces)", "II"),
	sysctlEq("accept_redirects_default", "net.ipv4.conf.default.accept_redirects", "0", "OS-redirects-default", "IPv4 ICMP redirects ignored (default)", "II"),
	sysctlEq("source_route_all", "net.ipv4.conf.all.accept_source_route", "0", "OS-srcroute", "IPv4 source-routed packets not forwarded (all interfaces)", "II"),
	sysctlEq("source_route_default", "net.ipv4.conf.default.accept_source_route", "0", "OS-srcroute-default", "IPv4 source-routed packets not forwarded (default)", "II"),
	sysctlEq("echo_broadcast", "net.ipv4.icmp_echo_ignore_broadcasts", "1", "OS-broadcast", "ICMP echo to broadcast addresses ignored", "II"),
}

// osRules evaluates every rule of each node's OS STIG, grouping nodes by
// benchmark so each group reports under that STIG's vulnerability IDs.
// Nodes without a benchmark get the generic osChecks under OS-* IDs.
func (e *evaluator) osRules() {
	g := "os"
	nodes := e.sshNodes()
	if len(nodes) == 0 {
		return
	}
	ni := func(n string) *nodeinfo.Info { return e.in.Nodes[n] }

	groups := map[*OSBenchmark][]string{}
	for _, n := range nodes {
		groups[OSBenchmarkFor(ni(n).OS)] = append(groups[OSBenchmarkFor(ni(n).OS)], n)
	}
	var order []*OSBenchmark
	for b := range groups {
		order = append(order, b)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i] == nil || order[j] == nil {
			return order[j] == nil
		}
		return order[i].Name < order[j].Name
	})
	for _, b := range order {
		members := groups[b]
		if b == nil {
			for _, c := range osChecks {
				e.perNode(c.id, c.title, c.cat, g, c.fix, members, func(n string) (Status, string) { return c.eval(ni(n)) })
			}
			continue
		}
		t := b.Table()
		if t == nil {
			// no embedded table: the hand-written subset only
			for _, c := range osChecks {
				r, ok := b.rules[c.key]
				if !ok {
					continue
				}
				start := len(e.out)
				e.perNode(r.ID, c.title, r.Cat, g, c.fix, members, func(n string) (Status, string) { return c.eval(ni(n)) })
				for i := start; i < len(e.out); i++ {
					e.out[i].Ref = b.String()
				}
			}
			continue
		}
		override := b.overrides()
		for _, rule := range t.Rules {
			rule := rule
			start := len(e.out)
			fix := rule.Fix
			if oc, ok := override[rule.VID]; ok {
				fix = oc.fix + "\n\nSTIG: " + rule.Fix
				e.perNode(rule.VID, rule.Title, rule.Cat, g, fix, members, func(n string) (Status, string) { return oc.eval(ni(n)) })
			} else if templated(rule) {
				e.perNode(rule.VID, rule.Title, rule.Cat, g, fix, members, func(n string) (Status, string) { return evalTemplated(ni(n), rule) })
			} else {
				reason := "not automated by ComplianceAsCode"
				if rule.Status != "unmapped" && len(rule.Checks) > 0 {
					var names []string
					for _, c := range rule.Checks {
						names = append(names, c.Rule)
					}
					reason = "custom OVAL only (" + truncList(names, 3) + ")"
				}
				e.add(Result{ID: rule.VID, Title: rule.Title, Cat: rule.Cat, Group: g, Status: Manual, Detail: reason, Fix: fix})
			}
			for i := start; i < len(e.out); i++ {
				e.out[i].Ref = b.String()
				e.out[i].RuleID = rule.STIGID
				e.out[i].Check = rule.Check
			}
		}
	}

	// Not STIG rules, but the same per-node facts.
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

// OSSummary counts a node's OS-group results by status.
func OSSummary(rs []Result, node string) (counts map[Status]int, ref string) {
	counts = map[Status]int{}
	for _, r := range rs {
		if r.Group != "os" {
			continue
		}
		if st, ok := r.PerNode[node]; ok {
			counts[st]++
			if r.Ref != "" {
				ref = r.Ref
			}
		}
	}
	return counts, ref
}

// OSSummaryText renders OSSummary as "12 pass, 3 fail, 1 manual".
func OSSummaryText(counts map[Status]int) string {
	var parts []string
	for _, st := range []Status{Pass, Fail, Manual, NA} {
		if c := counts[st]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, strings.ToLower(st.String())))
		}
	}
	return strings.Join(parts, ", ")
}
