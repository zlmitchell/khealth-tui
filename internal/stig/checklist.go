package stig

// Remediation checklist: the FAIL and MANUAL results regrouped by what the
// fix changes - a file on the nodes, a Kubernetes object, a package or
// unit - so whoever does the work opens each file once and sees every line
// it needs. Rules that restate each other (STIG aliases, CIS/STIG overlap)
// collapse into one item carrying all their IDs.

import (
	"regexp"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/stigdata"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// TargetKind orders the checklist: files first, then cluster objects, then
// host state that has no single file.
type TargetKind int

const (
	TargetFile     TargetKind = iota // config file or directory on the nodes
	TargetResource                   // Kubernetes object
	TargetBoot                       // kernel command line
	TargetPackage                    // packages to install / remove
	TargetUnit                       // systemd units
	TargetReview                     // no single target: read the fix
)

func (k TargetKind) String() string {
	switch k {
	case TargetFile:
		return "file"
	case TargetResource:
		return "resource"
	case TargetBoot:
		return "boot"
	case TargetPackage:
		return "package"
	case TargetUnit:
		return "unit"
	}
	return "review"
}

// Target is what a fix changes.
type Target struct {
	Kind   TargetKind
	Name   string // /etc/ssh/sshd_config, Namespace team-a, packages: install ...
	Change string // the line or command for this target ("" = the rule's fix)
}

const reviewName = "no single target (read the fix)"

// ChecklistItem is one change: every rule it satisfies, the nodes it is
// still open on (nil for cluster objects and cluster-wide rules).
type ChecklistItem struct {
	IDs    []string
	Cat    string
	Title  string
	Status Status // Fail when any merged rule fails, else Manual
	Change string
	Detail string
	Nodes  []string
	Result int // index of the first merged result in the input (detail view)
}

// ChecklistGroup is one target and the changes it needs.
type ChecklistGroup struct {
	Kind  TargetKind
	Name  string
	Hint  string   // what to run after editing (reload, rebuild, reboot)
	Nodes []string // union of the items' nodes
	Items []ChecklistItem
}

// Checklist regroups the open (FAIL / MANUAL) results by target.
func Checklist(rs []Result) []ChecklistGroup {
	var groups []*ChecklistGroup
	byKey := map[string]*ChecklistGroup{}
	for i, r := range rs {
		if r.Status != Fail && r.Status != Manual {
			continue
		}
		nodes := openNodes(r)
		for _, t := range targetsOf(r) {
			key := t.Kind.String() + "\x00" + t.Name
			g := byKey[key]
			if g == nil {
				g = &ChecklistGroup{Kind: t.Kind, Name: t.Name, Hint: targetHint(t)}
				byKey[key] = g
				groups = append(groups, g)
			}
			change := strutil.FirstNonEmpty(t.Change, r.Fix)
			merged := false
			for j := range g.Items {
				it := &g.Items[j]
				// the review bucket holds free-text fixes: equal text there
				// (or none at all) is not the same change
				if it.Change != change || t.Kind == TargetReview {
					continue
				}
				if !slices.Contains(it.IDs, r.ID) {
					it.IDs = append(it.IDs, r.ID)
				}
				if r.Status == Fail && it.Status != Fail {
					it.Status, it.Title, it.Detail, it.Result = Fail, r.Title, r.Detail, i
				}
				if catRank(r.Cat) < catRank(it.Cat) {
					it.Cat = r.Cat
				}
				it.Nodes = unionSorted(it.Nodes, nodes)
				merged = true
				break
			}
			if !merged {
				g.Items = append(g.Items, ChecklistItem{IDs: []string{r.ID}, Cat: r.Cat, Title: r.Title, Status: r.Status, Change: change, Detail: r.Detail, Nodes: nodes, Result: i})
			}
		}
	}
	out := make([]ChecklistGroup, 0, len(groups))
	for _, g := range groups {
		sort.SliceStable(g.Items, func(i, j int) bool {
			a, b := g.Items[i], g.Items[j]
			if a.Status != b.Status {
				return statusRank(a.Status) < statusRank(b.Status)
			}
			if a.Cat != b.Cat {
				return catRank(a.Cat) < catRank(b.Cat)
			}
			return a.IDs[0] < b.IDs[0]
		})
		for _, it := range g.Items {
			g.Nodes = unionSorted(g.Nodes, it.Nodes)
		}
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Open counts the items and how many of them fail.
func (g ChecklistGroup) Open() (items, fails int) {
	for _, it := range g.Items {
		if it.Status == Fail {
			fails++
		}
	}
	return len(g.Items), fails
}

func catRank(c string) int {
	switch c {
	case "I":
		return 0
	case "II":
		return 1
	case "III":
		return 2
	}
	return 3
}

func unionSorted(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string{}, a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// openNodes lists the nodes a per-node rule is still open on.
func openNodes(r Result) []string {
	var out []string
	for n, st := range r.PerNode {
		if st == Fail || st == Manual {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

var detailPath = regexp.MustCompile(`(/(?:etc|var|boot|usr|opt|root)/[^\s,;:()'"]+)`)

// targetsOf is the result's own targets, narrowed to the files its detail
// names when it lists several; otherwise the first host path the detail
// mentions for node-side rules; otherwise the review bucket.
func targetsOf(r Result) []Target {
	if len(r.Targets) > 0 {
		targets := sshdTargets(r)
		var named, files, other []Target
		for _, t := range targets {
			if t.Kind == TargetFile && !strings.HasSuffix(t.Name, "/") && !strings.Contains(t.Name, "*") {
				files = append(files, t)
				if strings.Contains(r.Detail, t.Name) {
					named = append(named, t)
				}
				continue
			}
			other = append(other, t)
		}
		if len(named) > 0 && len(named) < len(files) {
			return append(named, other...)
		}
		return targets
	}
	switch r.Group {
	case "os", "node", "rke2", "root":
		m := detailPath.FindString(r.Detail)
		if m == "" && r.Group == "os" {
			// the OS STIG fix text opens with the file it edits ("Edit the
			// /etc/audit/auditd.conf file ...")
			m = detailPath.FindString(r.Fix)
		}
		if m != "" {
			return []Target{{Kind: TargetFile, Name: pathName(m)}}
		}
	}
	return []Target{{Kind: TargetReview, Name: reviewName}}
}

var sshdDropin = regexp.MustCompile(`/etc/ssh/sshd_config\.d/[^\s;,()]+`)

// sshdTargets moves an sshd fix to the drop-in that sets the wrong value
// on each node (evalSSHD names it: "... in /etc/ssh/sshd_config.d/50-redhat.conf"):
// the drop-in is read first, so a line added to sshd_config changes nothing.
func sshdTargets(r Result) []Target {
	var out []Target
	for _, t := range r.Targets {
		if t.Name != "/etc/ssh/sshd_config" {
			out = append(out, t)
			continue
		}
		seen := map[string]bool{}
		for _, seg := range strings.Split(r.Detail, "; ") {
			name := t.Name
			if m := sshdDropin.FindString(seg); m != "" {
				name = m
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, Target{Kind: TargetFile, Name: name, Change: t.Change})
			}
		}
	}
	return out
}

// pathName tidies a path lifted from prose: no trailing punctuation, and a
// glob becomes its directory so it groups with the template targets.
func pathName(p string) string {
	p = strings.TrimRight(p, ".")
	if i := strings.IndexAny(p, "*?["); i >= 0 {
		p = p[:strings.LastIndex(p[:i], "/")+1]
	}
	return p
}

// targetHint says what applies an edit to the target.
func targetHint(t Target) string {
	n := t.Name
	switch t.Kind {
	case TargetBoot:
		return "RHEL: grubby --update-kernel=ALL --args='<arg>'; Ubuntu: GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub; reboot"
	case TargetPackage:
		return "dnf / apt-get"
	case TargetResource:
		return "kubectl edit, or change the chart / manifest that owns it so the fix survives the next deploy"
	}
	switch {
	case strings.HasPrefix(n, "/etc/sysctl.d/"):
		return "then sysctl --system"
	case strings.HasPrefix(n, "/etc/audit/rules.d/"):
		return "then augenrules --load (a reboot when the rules end with -e 2)"
	case n == "/etc/audit/auditd.conf":
		return "then service auditd reload"
	case n == "/etc/ssh/sshd_config":
		return "or a drop-in under /etc/ssh/sshd_config.d/ (the first value read wins); sshd -t, then systemctl reload sshd"
	case strings.HasPrefix(n, "/etc/ssh/sshd_config.d/"):
		return "change the existing line here: drop-ins are read before sshd_config and the first value wins; sshd -t, then systemctl reload sshd"
	case strings.HasPrefix(n, "/etc/rancher/rke2/"):
		return "or a file under config.yaml.d/; then systemctl restart rke2-server (rke2-agent on agents), one node at a time"
	case strings.HasPrefix(n, "/etc/rancher/k3s/"):
		return "then systemctl restart k3s (k3s-agent on agents), one node at a time"
	case strings.HasPrefix(n, "/etc/kubernetes/manifests/"):
		return "the kubelet recreates the static pod when the manifest changes"
	case n == "/var/lib/kubelet/config.yaml":
		return "then systemctl restart kubelet"
	case strings.HasPrefix(n, "/etc/modprobe.d/"):
		return "applies at the next load: rmmod the module or reboot"
	case strings.HasPrefix(n, "/etc/dconf/"):
		return "then dconf update"
	case n == "/etc/fstab":
		return "then mount -o remount <mount point>"
	case strings.HasPrefix(n, "/etc/systemd/"):
		return "then systemctl daemon-reload and restart the unit"
	}
	return ""
}

// ---------- OS STIG template targets ----------

// ruleTargets derives the targets of an OS STIG rule from the
// ComplianceAsCode checks behind it.
func ruleTargets(rule stigdata.Rule) []Target {
	var out []Target
	for _, c := range rule.Checks {
		out = append(out, checkTargets(c)...)
	}
	return out
}

func checkTargets(c stigdata.Check) []Target {
	file := func(name, change string) []Target { return []Target{{Kind: TargetFile, Name: name, Change: change}} }
	switch c.Template {
	case "sysctl":
		return file("/etc/sysctl.d/", c.Str("SYSCTLVAR")+" = "+strutil.FirstNonEmpty(c.Str("SYSCTLVAL"), "<value>"))
	case "package_installed", "package_installed_guard_var":
		return []Target{{Kind: TargetPackage, Name: "packages: install", Change: c.Str("PKGNAME")}}
	case "package_removed", "package_removed_guard_var":
		pkgs := c.List("PACKAGES")
		if len(pkgs) == 0 {
			pkgs = []string{c.Str("PKGNAME")}
		}
		return []Target{{Kind: TargetPackage, Name: "packages: remove", Change: strings.Join(pkgs, " ")}}
	case "service_enabled", "service_enabled_guard_var":
		return []Target{{Kind: TargetUnit, Name: "systemd units", Change: "systemctl enable --now " + c.Str("SERVICENAME") + ".service"}}
	case "service_disabled", "service_disabled_guard_var":
		return []Target{{Kind: TargetUnit, Name: "systemd units", Change: "systemctl mask --now " + c.Str("SERVICENAME") + ".service"}}
	case "socket_enabled":
		return []Target{{Kind: TargetUnit, Name: "systemd units", Change: "systemctl enable --now " + c.Str("SOCKETNAME") + ".socket"}}
	case "socket_disabled":
		return []Target{{Kind: TargetUnit, Name: "systemd units", Change: "systemctl mask --now " + c.Str("SOCKETNAME") + ".socket"}}
	case "timer_enabled":
		return []Target{{Kind: TargetUnit, Name: "systemd units", Change: "systemctl enable --now " + c.Str("TIMERNAME") + ".timer"}}
	case "mount":
		return file("/etc/fstab", c.Str("MOUNTPOINT")+" on its own partition")
	case "mount_option", "mount_option_home":
		return file("/etc/fstab", c.Str("MOUNTPOINT")+": add "+c.Str("MOUNTOPTION"))
	case "mount_option_remote_filesystems":
		return file("/etc/fstab", "nfs/cifs mounts: add "+c.Str("MOUNTOPTION"))
	case "mount_option_removable_partitions":
		return file("/etc/fstab", "removable media: add "+c.Str("MOUNTOPTION"))
	case "sshd_lineinfile":
		return file("/etc/ssh/sshd_config", c.Str("PARAMETER")+" "+strutil.FirstNonEmpty(c.Value("VALUE", "XCCDF_VARIABLE"), "<value>"))
	case "file_permissions", "file_owner", "file_groupowner":
		var cmd string
		switch c.Template {
		case "file_permissions":
			cmd = "chmod " + c.Str("FILEMODE")
		case "file_owner":
			cmd = "chown " + c.Str("UID_OR_NAME")
		default:
			cmd = "chgrp " + c.Str("GID_OR_NAME")
		}
		scoped := ""
		if c.Bool("RECURSIVE") {
			cmd += " -R"
		}
		if re := c.Str("FILE_REGEX"); re != "" {
			scoped = " (files matching " + re + ")"
		}
		var out []Target
		for _, fp := range c.List("FILEPATH") {
			out = append(out, Target{Kind: TargetFile, Name: fp, Change: cmd + scoped})
		}
		return out
	case "file_existence":
		if c.Bool("EXISTS") {
			return file(c.Str("FILEPATH"), "create")
		}
		return file(c.Str("FILEPATH"), "remove")
	case "audit_rules_watch":
		return file("/etc/audit/rules.d/", "-w "+strings.TrimRight(c.Str("PATH"), "/")+" -p wa")
	case "audit_rules_privileged_commands":
		return file("/etc/audit/rules.d/", "-a always,exit -F path="+strings.ReplaceAll(c.Str("PATH"), `\/`, "/")+" -F perm=x -F auid>=1000 -F auid!=unset")
	case "audit_rules_dac_modification", "audit_rules_file_deletion_events", "audit_rules_kernel_module_loading":
		return file("/etc/audit/rules.d/", "-a always,exit -F arch=b64 -S "+strutil.FirstNonEmpty(c.Str("ATTR"), c.Str("NAME"))+" -F auid>=1000 -F auid!=unset (and arch=b32)")
	case "audit_rules_unsuccessful_file_modification":
		return file("/etc/audit/rules.d/", "-a always,exit -F arch=b64 -S "+c.Str("NAME")+" -F exit=-EACCES / -F exit=-EPERM -F auid>=1000 -F auid!=unset (and arch=b32)")
	case "kernel_module_disabled":
		m := c.Str("KERNMODULE")
		return file("/etc/modprobe.d/", "install "+m+" /bin/false; blacklist "+m)
	case "grub2_bootloader_argument":
		arg := c.Str("ARG_NAME")
		if v := c.Value("ARG_VALUE", "ARG_VARIABLE"); v != "" {
			arg += "=" + v
		}
		return []Target{{Kind: TargetBoot, Name: "kernel command line", Change: arg}}
	case "auditd_lineinfile":
		return file("/etc/audit/auditd.conf", c.Str("PARAMETER")+" = "+strutil.FirstNonEmpty(c.Value("VALUE", "XCCDF_VARIABLE"), "<value>"))
	case "key_value_pair_in_file":
		sep := c.Str("SEP")
		if sep == "" {
			sep = "="
		}
		return file(c.Str("PATH"), c.Str("KEY")+sep+strutil.FirstNonEmpty(c.Value("VALUE", "XCCDF_VARIABLE"), "<value>"))
	case "shell_lineinfile":
		return file(c.Str("PATH"), c.Str("PARAMETER")+"="+strutil.FirstNonEmpty(c.Value("VALUE", "XCCDF_VARIABLE"), "<value>"))
	case "lineinfile":
		return file(c.Str("PATH"), strings.TrimSpace(c.Str("TEXT")))
	case "systemd_dropin_configuration":
		return file(strutil.FirstNonEmpty(c.Str("DROPIN_DIR"), c.Str("MASTER_CFG_FILE")), "["+c.Str("SECTION")+"] "+c.Str("PARAM")+"="+c.Str("VALUE"))
	case "dconf_ini_file":
		return file(c.Str("PATH"), "["+c.Str("SECTION")+"] "+c.Str("PARAMETER")+"="+c.Str("VALUE")+" and lock it under "+c.Str("LOCK_PATH"))
	case "accounts_password":
		key := c.Str("VARIABLE")
		return file("/etc/security/pwquality.conf", key+" = "+strutil.FirstNonEmpty(c.Resolved["var_password_pam_"+key], "<value>"))
	case "pam_account_password_faillock":
		return file("/etc/security/faillock.conf", c.Str("PRM_NAME")+" = "+strutil.FirstNonEmpty(c.Resolved[c.Str("EXT_VARIABLE")], "<value>"))
	case "pam_options":
		return file(c.Str("PATH"), strings.Join(strings.Fields(c.Str("TYPE")+" "+c.Str("CONTROL_FLAG")+" "+c.Str("MODULE")), " ")+": add the STIG arguments")
	}
	return nil
}

// ---------- Kubernetes component targets ----------

var argPrefix = regexp.MustCompile(`^(kube-apiserver|kube-controller-manager|kube-scheduler|kubelet|etcd)-arg: `)

var groupComponent = map[string]string{
	"apiserver":          "kube-apiserver",
	"controller-manager": "kube-controller-manager",
	"scheduler":          "kube-scheduler",
	"etcd":               "etcd",
	"kubelet":            "kubelet",
}

// componentTarget places a control-plane or kubelet rule in the file that
// sets it on this distribution: config.yaml on rke2/k3s, the static pod
// manifest or the kubelet config on kubeadm.
func componentTarget(dist string, r Result) (Target, bool) {
	fix := distPart(r.Fix, dist)
	comp := groupComponent[r.Group]
	if m := argPrefix.FindStringSubmatch(fix); m != nil {
		comp = m[1]
	}
	change := fix
	if r.Fix == kubeletFix {
		change = r.Title
	}
	switch dist {
	case "rke2", "k3s":
		if comp == "" && !strings.HasPrefix(fix, "config.yaml:") {
			return Target{}, false
		}
		return Target{Kind: TargetFile, Name: "/etc/rancher/" + dist + "/config.yaml", Change: strings.TrimPrefix(change, "config.yaml: ")}, true
	case "kubeadm":
		if comp == "" {
			return Target{}, false
		}
		if m := argPrefix.FindStringSubmatch(change); m != nil {
			change = "--" + strings.TrimPrefix(change, m[0])
		}
		if comp == "kubelet" {
			return Target{Kind: TargetFile, Name: "/var/lib/kubelet/config.yaml", Change: change}, true
		}
		return Target{Kind: TargetFile, Name: "/etc/kubernetes/manifests/" + comp + ".yaml", Change: change}, true
	}
	return Target{}, false
}

// distPart picks this distribution's half of a "rke2: ...; kubeadm: ..." fix.
func distPart(fix, dist string) string {
	if !strings.Contains(fix, "kubeadm:") || !strings.Contains(fix, "rke2:") {
		return fix
	}
	want := dist
	if dist == "k3s" {
		want = "rke2"
	}
	for _, part := range strings.Split(fix, ";") {
		part = strings.TrimSpace(part)
		if rest, ok := strings.CutPrefix(part, want+":"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return fix
}

// ---------- Kubernetes object targets ----------

// workloadOf names the object that owns a pod, so a fix lands on the
// Deployment rather than a pod the next rollout replaces.
func workloadOf(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if h := p.Labels["pod-template-hash"]; o.Kind == "ReplicaSet" && h != "" && strings.HasSuffix(o.Name, "-"+h) {
			return "Deployment " + p.Namespace + "/" + strings.TrimSuffix(o.Name, "-"+h)
		}
		return o.Kind + " " + p.Namespace + "/" + o.Name
	}
	return "Pod " + p.Namespace + "/" + p.Name
}

// objectTargets makes one resource target per distinct object name.
func objectTargets(names []string, change string) []Target {
	var out []Target
	for _, n := range strutil.Uniq(names) {
		out = append(out, Target{Kind: TargetResource, Name: n, Change: change})
	}
	return out
}

// finishTargets fills in the targets the rules did not set: component
// flags by distribution, then RKE2 aliases from their source rules.
func (e *evaluator) finishTargets() {
	for i := range e.out {
		r := &e.out[i]
		if len(r.Targets) == 0 {
			if t, ok := componentTarget(e.dist, *r); ok {
				r.Targets = []Target{t}
			}
		}
	}
	for i := range e.out {
		r := &e.out[i]
		if len(r.Targets) > 0 || len(r.aliasOf) == 0 {
			continue
		}
		for _, src := range r.aliasOf {
			if s := e.byID(src); s != nil && (s.Status == Fail || s.Status == Manual) {
				for _, t := range s.Targets {
					t.Change = strutil.FirstNonEmpty(t.Change, s.Fix)
					r.Targets = append(r.Targets, t)
				}
			}
		}
	}
}
