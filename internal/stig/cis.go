package stig

// CIS Kubernetes Benchmark v2.0.1 (June 2026) section numbers, which also
// back the rke2 CIS self-assessment guides (docs.rke2.io, v1.12). Rules the
// DISA Kubernetes STIG already carries live in kubernetes.go under their
// V- IDs; this file holds the CIS-only recommendations.

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

func (e *evaluator) cisRules() {
	e.cisControlPlaneRules()
	e.cisKubeletRules()
	e.cisClusterRules()
}

func (e *evaluator) cisControlPlaneRules() {
	{
		nodes := slices.Collect(maps.Keys(e.apiserver))
		g := "apiserver"
		rk := func(node string) map[string]string { return e.apiserver[node] }
		e.perNode("CIS-1.2.14", "NodeRestriction admission plugin enabled", "II", g, "kube-apiserver-arg: enable-admission-plugins=NodeRestriction,...", nodes, func(n string) (Status, string) {
			if strings.Contains(rk(n)["enable-admission-plugins"], "NodeRestriction") {
				return Pass, ""
			}
			return Fail, "--enable-admission-plugins=" + rk(n)["enable-admission-plugins"]
		})
		e.perNode("CIS-1.2.15", "API server profiling disabled", "II", g, "kube-apiserver-arg: profiling=false", nodes, func(n string) (Status, string) { return flagEq(rk(n), "profiling", "false") })
		e.perNode("CIS-1.2.5", "API server verifies kubelet certificates (kubelet-certificate-authority)", "II", g, "kube-apiserver-arg: kubelet-certificate-authority=<ca>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "kubelet-certificate-authority") })
		e.perNode("CIS-1.2.21", "API server service-account-lookup enabled", "II", g, "kube-apiserver-arg: service-account-lookup=true", nodes, func(n string) (Status, string) {
			if v, ok := rk(n)["service-account-lookup"]; !ok || v == "true" {
				return Pass, ""
			}
			return Fail, "--service-account-lookup=false"
		})
	}
	{
		nodes := slices.Collect(maps.Keys(e.cm))
		g := "controller-manager"
		rk := func(node string) map[string]string { return e.cm[node] }
		e.perNode("CIS-1.3.5", "Controller manager root-ca-file set", "II", g, "kube-controller-manager-arg: root-ca-file=<ca>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "root-ca-file") })
		e.perNode("CIS-1.3.4", "Controller manager service-account-private-key-file set", "II", g, "kube-controller-manager-arg: service-account-private-key-file=<key>", nodes, func(n string) (Status, string) { return flagSet(rk(n), "service-account-private-key-file") })
	}
	{
		nodes := slices.Collect(maps.Keys(e.sched))
		g := "scheduler"
		rk := func(node string) map[string]string { return e.sched[node] }
		e.perNode("CIS-1.4.1", "Scheduler profiling disabled", "II", g, "kube-scheduler-arg: profiling=false", nodes, func(n string) (Status, string) { return flagEq(rk(n), "profiling", "false") })
	}
}

func (e *evaluator) cisKubeletRules() {
	g := "kubelet"
	nodes := e.kubeletNodes()
	cfg := e.kubeletCfg
	fix := kubeletFix
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
}

func (e *evaluator) cisNodeRules() {
	g := "node"
	nodes := e.sshNodes()
	ni := func(n string) *nodeinfo.Info { return e.in.Nodes[n] }

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
	e.perNode("CIS-swap", "Swap disabled on nodes", "III", g, "swapoff -a and remove from fstab", nodes, func(n string) (Status, string) {
		if ni(n).SwapTotal > 0 {
			return Fail, "swap enabled"
		}
		return Pass, ""
	})
}

func (e *evaluator) cisClusterRules() {
	g := "cluster"
	s := e.in.Snap

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
	r := Result{ID: "CIS-5.1.1", Title: "cluster-admin role bindings minimized", Cat: "II", Group: g, Status: Pass, Detail: "only system:masters", Fix: "review and remove unnecessary cluster-admin bindings"}
	if len(subjects) > 0 {
		r.Status = Manual
		r.Detail = fmt.Sprintf("%d subject(s): %s", len(subjects), truncList(subjects, 6))
	}
	e.add(r)

	// privileged / host namespaces outside system namespaces
	var priv, hostNS []string
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
