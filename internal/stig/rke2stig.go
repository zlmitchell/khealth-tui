package stig

// The 21 rules of the DISA RKE2 STIG V2R7 (U_RGS_RKE2_V2R7_STIG.zip, rule
// IDs CNTR-R2-*), each with its own row so a checklist from that STIG maps
// one to one. Most restate a Kubernetes STIG or CIS check: those rows
// alias the check already evaluated (same evidence, RKE2 ID and title, the
// source rule named in the detail). The others are evaluated here.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// rke2Alias adds an RKE2 STIG row whose outcome follows its source rules:
// any Fail is a Fail, else any Unknown, else any Manual, else Pass (N/A
// only when every source is N/A). A source that was never evaluated
// leaves the row Unknown.
func (e *evaluator) rke2Alias(id, stigID, title, cat, fix string, sources ...string) {
	r := Result{ID: id, RuleID: stigID, Title: title, Cat: cat, Group: "rke2", Fix: fix, PerNode: map[string]Status{}}
	var details []string
	count := map[Status]int{}
	for _, src := range sources {
		s := e.byID(src)
		if s == nil {
			r.Status, r.Detail = Unknown, "source rule "+src+" not evaluated"
			r.PerNode = nil
			e.add(r)
			return
		}
		count[s.Status]++
		d := src
		if s.Detail != "" {
			d += ": " + s.Detail
		}
		details = append(details, d)
		for n, st := range s.PerNode {
			if cur, ok := r.PerNode[n]; !ok || worse(st, cur) {
				r.PerNode[n] = st
			}
		}
	}
	switch {
	case count[Fail] > 0:
		r.Status = Fail
	case count[Unknown] > 0:
		r.Status = Unknown
	case count[Manual] > 0:
		r.Status = Manual
	case count[NA] == len(sources):
		r.Status = NA
	default:
		r.Status = Pass
	}
	if len(r.PerNode) == 0 {
		r.PerNode = nil
	}
	r.Detail = "as " + strings.Join(details, "; ")
	e.add(r)
}

// worse orders statuses for the per-node merge: Fail > Unknown > Manual > NA > Pass.
func worse(a, b Status) bool {
	rank := map[Status]int{Fail: 4, Unknown: 3, Manual: 2, NA: 1, Pass: 0}
	return rank[a] > rank[b]
}

// byID finds an evaluated rule.
func (e *evaluator) byID(id string) *Result {
	for i := range e.out {
		if e.out[i].ID == id {
			return &e.out[i]
		}
	}
	return nil
}

var envSecretName = regexp.MustCompile(`(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL)`)

func (e *evaluator) rke2STIGRules() {
	s := e.in.Snap
	if s.Distribution != "rke2" && s.Distribution != "k3s" {
		return // the RKE2 STIG applies to rke2 (and its k3s twin) only
	}
	g := "rke2"

	// ---- restated Kubernetes STIG / CIS checks ----
	e.rke2Alias("V-254554", "CNTR-R2-000030", "RKE2 controller manager uses individual service account credentials", "II", "kube-controller-manager-arg: use-service-account-credentials=true", "V-242381")
	e.rke2Alias("V-254556", "CNTR-R2-000100", "RKE2 controller manager bound to localhost", "II", "kube-controller-manager-arg: bind-address=127.0.0.1", "V-242385")
	e.rke2Alias("V-254557", "CNTR-R2-000110", "RKE2 kubelet anonymous authentication disabled", "II", kubeletFix, "V-242391")
	e.rke2Alias("V-254559", "CNTR-R2-000130", "RKE2 kubelet read-only port disabled", "I", kubeletFix, "V-242387")
	e.rke2Alias("V-254561", "CNTR-R2-000150", "RKE2 kubelet authorization mode is Webhook", "I", kubeletFix, "V-242392")
	e.rke2Alias("V-254562", "CNTR-R2-000160", "RKE2 API server anonymous authentication disabled", "I", "kube-apiserver-arg: anonymous-auth=false", "V-242390")
	e.rke2Alias("V-254563", "CNTR-R2-000320", "RKE2 audit records retained (audit-log-maxage >= 30)", "II", "kube-apiserver-arg: audit-log-maxage=30 (rke2 default)", "V-242464")
	e.rke2Alias("V-254569", "CNTR-R2-000940", "RKE2 kubelet protects kernel defaults", "II", "kubelet-arg: protect-kernel-defaults=true (profile: cis sets it; needs the CIS sysctls)", "V-242434")
	e.rke2Alias("V-254572", "CNTR-R2-001270", "RKE2 API server authorization mode is Node,RBAC", "II", "kube-apiserver-arg: authorization-mode=Node,RBAC (rke2 default)", "V-242382")

	// ---- V-254553: TLS on apiserver, controller manager and scheduler ----
	// tls-min-version >= 1.2 and an explicit cipher list on each; the
	// Kubernetes STIG only demands the ciphers on the apiserver
	cipherOn := func(id, comp string, flags map[string]map[string]string) {
		nodes := strutil.SortedKeys(flags)
		e.perNode(id, comp+" TLS cipher suites explicitly configured", "I", g, comp+"-arg: tls-cipher-suites=<FIPS/approved list> (with tls-min-version=VersionTLS12)", nodes, func(n string) (Status, string) {
			return flagSet(flags[n], "tls-cipher-suites")
		})
	}
	cipherOn("RKE2-cm-ciphers", "kube-controller-manager", e.cm)
	cipherOn("RKE2-sched-ciphers", "kube-scheduler", e.sched)
	e.rke2Alias("V-254553", "CNTR-R2-000010", "RKE2 protects sessions with FIPS-validated TLS (tls-min-version, tls-cipher-suites on apiserver, controller manager, scheduler)", "I",
		"config.yaml kube-apiserver-arg / kube-controller-manager-arg / kube-scheduler-arg: tls-min-version=VersionTLS12 and tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,...",
		"V-242378", "V-242418", "V-242376", "RKE2-cm-ciphers", "V-242377", "RKE2-sched-ciphers")

	// ---- V-254555: profile cis + audit policy + audit-log-mode ----
	apiNodes := strutil.SortedKeys(e.apiserver)
	e.perNode("RKE2-audit-log-mode", "API server audit-log-mode is blocking-strict", "II", g, "kube-apiserver-arg: audit-log-mode=blocking-strict (rke2 profile: cis sets it)", apiNodes, func(n string) (Status, string) {
		if v := e.apiserver[n]["audit-log-mode"]; v == "blocking-strict" {
			return Pass, ""
		} else if v == "" {
			return Fail, "audit-log-mode not set (default batch)"
		} else {
			return Fail, "audit-log-mode=" + v
		}
	})
	profileSrc := []string{"V-242461", "RKE2-audit-log-mode"}
	if e.byID("V-254555") != nil {
		// the node rule (profile: cis in config.yaml) exists only with SSH;
		// the STIG row takes it over under its own title
		p := e.byID("V-254555")
		p.ID, p.Group = "RKE2-profile", g
		profileSrc = append(profileSrc, "RKE2-profile")
	}
	e.rke2Alias("V-254555", "CNTR-R2-000060", "RKE2 components configured per the security configuration guide (profile: cis, audit-policy-file, audit-log-mode)", "II",
		"config.yaml: profile: cis; kube-apiserver-arg: audit-policy-file=/etc/rancher/rke2/audit-policy.yaml, audit-log-mode=blocking-strict; review the audit policy contents", profileSrc...)

	// ---- V-254564: files under /etc/rancher/rke2 and the agent dir ----
	if e.byID("V-254564") != nil {
		p := e.byID("V-254564")
		p.RuleID = "CNTR-R2-000520"
		p.Group = g
	}

	// ---- V-254565: only needed default components enabled ----
	// automated reading of `disable:`; whether each remaining component is
	// needed is the operator's call
	disabled := map[string]bool{}
	rke := false
	for _, n := range e.sshNodes() {
		ni := e.in.Nodes[n]
		if ni.Dist != "rke2" && ni.Dist != "k3s" {
			continue
		}
		rke = true
		for _, cf := range ni.ConfigFiles {
			for _, d := range nodeinfo.YAMLList(cf.Content, "disable") {
				disabled[d] = true
			}
		}
	}
	r := Result{ID: "V-254565", RuleID: "CNTR-R2-000550", Title: "RKE2 configured with only essential components (disable: unneeded bundled charts)", Cat: "II", Group: g, Status: Manual, Fix: "config.yaml: disable: [rke2-ingress-nginx, rke2-metrics-server, ...] for bundled components the cluster does not need"}
	if !rke {
		r.Status, r.Detail = Unknown, "no SSH data from an rke2 server (config.yaml not read)"
	} else {
		var on []string
		for _, c := range []string{"rke2-canal", "rke2-coredns", "rke2-ingress-nginx", "rke2-metrics-server", "rke2-snapshot-controller", "rke2-snapshot-validation-webhook"} {
			if !disabled[c] {
				on = append(on, c)
			}
		}
		r.Detail = fmt.Sprintf("disabled: %s; still enabled: %s - confirm each enabled component is required", strutil.FirstNonEmpty(strings.Join(strutil.SortedKeys(disabled), ", "), "none"), strings.Join(on, ", "))
	}
	e.add(r)

	// ---- V-254566: PPSM - the ports the control plane binds ----
	r = Result{ID: "V-254566", RuleID: "CNTR-R2-000580", Title: "RKE2 ports, protocols and services per the PPSM CAL", Cat: "II", Group: g, Status: Manual, Fix: "review against the PPSM CAL and https://docs.rke2.io/install/requirements#networking; document any deviation with the ISSO"}
	var ports []string
	for _, n := range apiNodes {
		f := e.apiserver[n]
		ports = append(ports, fmt.Sprintf("%s: secure-port=%s etcd-servers=%s", n, strutil.FirstNonEmpty(f["secure-port"], "6443"), strutil.FirstNonEmpty(f["etcd-servers"], "https://127.0.0.1:2379")))
		if f["insecure-port"] != "" && f["insecure-port"] != "0" {
			r.Status = Fail
			r.Detail = n + ": insecure-port=" + f["insecure-port"]
		}
	}
	if r.Status == Manual {
		r.Detail = "apiserver 6443, supervisor 9345, etcd 2379-2380, kubelet 10250, metrics 10257/10259, CNI overlay; " + strutil.TruncList(ports, 3)
	}
	e.add(r)

	// ---- V-254567: no secrets as literal environment variables ----
	r = Result{ID: "V-254567", RuleID: "CNTR-R2-000800", Title: "RKE2 stores only cryptographic representations of passwords (no secrets as literal env values)", Cat: "II", Group: g, Status: Pass, Fix: "move the value to a Secret and reference it with valueFrom.secretKeyRef"}
	var literal []string
	seen := map[string]bool{}
	checkContainers := func(ns, kind, name string, cs []corev1.Container) {
		for _, c := range cs {
			for _, env := range c.Env {
				if env.ValueFrom == nil && env.Value != "" && envSecretName.MatchString(env.Name) {
					key := ns + "/" + kind + "/" + name
					if !seen[key] {
						seen[key] = true
						literal = append(literal, key+" ("+env.Name+")")
					}
				}
			}
		}
	}
	for i := range s.Pods {
		p := &s.Pods[i]
		checkContainers(p.Namespace, "pod", p.Name, append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...))
	}
	for i := range s.CronJobs {
		cj := &s.CronJobs[i]
		checkContainers(cj.Namespace, "cronjob", cj.Name, cj.Spec.JobTemplate.Spec.Template.Spec.Containers)
	}
	sort.Strings(literal)
	if len(literal) > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d workload(s) carry a password/token/key-named variable as a literal value: %s", len(literal), strutil.TruncList(literal, 5))
	} else {
		r.Detail = "no PASSWORD/SECRET/TOKEN/KEY-named env var with a literal value in pods or cronjobs"
	}
	e.add(r)

	// ---- V-254568: kubelet streaming-connection-idle-timeout >= 5m ----
	kNodes := e.kubeletNodes()
	e.perNode("V-254568", "RKE2 kubelet terminates idle streaming connections (streaming-connection-idle-timeout >= 5m)", "II", g, "kubelet-arg: streaming-connection-idle-timeout=5m", kNodes, func(n string) (Status, string) {
		v, ok := e.kubeletCfg(n)["streamingConnectionIdleTimeout"]
		if !ok {
			return Pass, "default 4h"
		}
		str, _ := v.(string)
		d, err := time.ParseDuration(str)
		if err != nil {
			return Manual, "streamingConnectionIdleTimeout=" + str
		}
		if d == 0 {
			return Fail, "streamingConnectionIdleTimeout=0 (never)"
		}
		if d < 5*time.Minute {
			return Fail, "streamingConnectionIdleTimeout=" + str + " (< 5m)"
		}
		return Pass, ""
	})
	if b := e.byID("V-254568"); b != nil {
		b.RuleID = "CNTR-R2-000890"
	}

	// ---- V-254570: system namespaces reserved ----
	r = Result{ID: "V-254570", RuleID: "CNTR-R2-000970", Title: "RKE2 system namespaces hold only system workloads (default, kube-public, kube-node-lease empty)", Cat: "II", Group: g, Status: Pass, Fix: "move user workloads out of default / kube-public / kube-node-lease"}
	var stray []string
	for i := range s.Pods {
		p := &s.Pods[i]
		switch p.Namespace {
		case "default", "kube-public", "kube-node-lease":
			stray = append(stray, p.Namespace+"/"+p.Name)
		}
	}
	for i := range s.Deployments {
		d := &s.Deployments[i]
		switch d.Namespace {
		case "default", "kube-public", "kube-node-lease":
			stray = append(stray, d.Namespace+"/deploy/"+d.Name)
		}
	}
	if len(stray) > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d workload(s): %s", len(stray), strutil.TruncList(strutil.Uniq(stray), 5))
	} else {
		r.Detail = "only service/kubernetes in default; kube-public and kube-node-lease empty"
	}
	e.add(r)

	// ---- V-254571: PSA config file with restricted defaults ----
	r = Result{ID: "V-254571", RuleID: "CNTR-R2-001130", Title: "RKE2 Pod Security Admission config enforces restricted by default (pod-security-admission-config-file)", Cat: "II", Group: g, Fix: "config.yaml: pod-security-admission-config-file: <file> with defaults enforce/audit/warn: restricted (profile: cis ships /etc/rancher/rke2/rke2-pss.yaml), or add a custom file and re-point the key"}
	switch psa := e.psaConfig(); {
	case psa == nil && len(e.sshNodes()) == 0:
		r.Status, r.Detail = Unknown, "the admission config file needs the SSH config tier on a server node"
	case psa == nil:
		flagged := false
		for _, f := range e.apiserver {
			if f["admission-control-config-file"] != "" {
				flagged = true
			}
		}
		if flagged {
			r.Status, r.Detail = Manual, "admission-control-config-file is set but the file was not read (not among the dumped files)"
		} else {
			r.Status, r.Detail = Fail, "no admission config file on the apiserver"
		}
	case psa.External != "":
		r.Status, r.Detail = Manual, psa.Path+" keeps the PodSecurity settings in "+psa.External+" (not read)"
	default:
		var wrong []string
		for k, v := range map[string]string{"enforce": psa.Enforce, "audit": psa.Audit, "warn": psa.Warn} {
			if strings.ToLower(v) != "restricted" {
				wrong = append(wrong, k+"="+strutil.FirstNonEmpty(v, "privileged"))
			}
		}
		sort.Strings(wrong)
		if len(wrong) > 0 {
			r.Status, r.Detail = Fail, psa.Path+": defaults "+strings.Join(wrong, ", ")+" (STIG: restricted)"
		} else {
			r.Status, r.Detail = Pass, psa.Path+": defaults enforce/audit/warn restricted"
		}
	}
	e.add(r)

	// ---- V-254574: no multiple versions of the same image ----
	r = Result{ID: "V-254574", RuleID: "CNTR-R2-001580", Title: "RKE2 old components removed (no image runs in more than one version)", Cat: "II", Group: g, Status: Pass, Fix: "update the workloads still on the old tag, then prune the image (crictl rmi)"}
	tags := map[string]map[string]bool{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, c := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			repo, tag := splitImage(c.Image)
			if tag == "" {
				continue
			}
			if tags[repo] == nil {
				tags[repo] = map[string]bool{}
			}
			tags[repo][tag] = true
		}
	}
	var multi []string
	for _, repo := range strutil.SortedKeys(tags) {
		if len(tags[repo]) > 1 {
			multi = append(multi, repo+" ("+strings.Join(strutil.SortedKeys(tags[repo]), ", ")+")")
		}
	}
	if len(multi) > 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("%d image(s) run in several versions: %s", len(multi), strutil.TruncList(multi, 4))
	} else {
		r.Detail = fmt.Sprintf("%d images, one version each", len(tags))
	}
	e.add(r)

	// ---- V-254575: supported release, latest images ----
	r = Result{ID: "V-254575", RuleID: "CNTR-R2-001620", Title: "RKE2 on a supported Kubernetes release with images patched to current versions", Cat: "II", Group: g, Status: Manual, Fix: "keep rke2 within the three supported minor releases (https://kubernetes.io/releases/) and rebuild images from patched bases; the Upgrade tab and the Helm tab show what is behind"}
	r.Detail = "cluster " + strutil.FirstNonEmpty(s.Version, "version unknown") + fmt.Sprintf(", %d distinct images running", len(tags)) + " - image currency is a registry/scanner question"
	e.add(r)

	// ---- V-268321: images signed by Rancher Government ----
	r = Result{ID: "V-268321", RuleID: "CNTR-R2-000460", Title: "RKE2 built from verified packages (Carbide-signed images)", Cat: "II", Group: g, Status: Manual, Fix: "verify the image signatures against the RGS Carbide key (cosign / hauler, https://rancherfederal.github.io/carbide-docs); the Images tab lists every image and registry"}
	var registries []string
	regs := map[string]bool{}
	for repo := range tags {
		reg := "docker.io"
		if i := strings.Index(repo, "/"); i > 0 && strings.ContainsAny(repo[:i], ".:") {
			reg = repo[:i]
		}
		regs[reg] = true
	}
	registries = strutil.SortedKeys(regs)
	r.Detail = "images pulled from " + strings.Join(registries, ", ") + "; signature verification is not something the cluster reports"
	e.add(r)
}

// splitImage returns repository and tag of an image reference (digest
// references have no tag).
func splitImage(img string) (string, string) {
	if i := strings.Index(img, "@"); i >= 0 {
		return img[:i], ""
	}
	slash := strings.LastIndex(img, "/")
	if colon := strings.LastIndex(img, ":"); colon > slash {
		return img[:colon], img[colon+1:]
	}
	return img, ""
}
