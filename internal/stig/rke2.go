package stig

// DISA Rancher Government Solutions RKE2 STIG V2R7 (Release 7, benchmark
// date 01 Jul 2026), from dl.dod.cyber.mil/wp-content/uploads/stigs/zip/
// U_RGS_RKE2_V2R7_STIG.zip. Most RKE2 STIG rules restate Kubernetes STIG
// checks (kubelet auth, controller-manager binding, PSA, TLS) that are
// already evaluated under their V-242xxx IDs; this file holds the rke2
// specific items. RKE2-* IDs are rke2 hardening-guide prerequisites the
// STIG references but does not number.

import (
	"fmt"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func (e *evaluator) rke2Rules() {
	g := "node"
	ni := func(n string) *nodeinfo.Info { return e.in.Nodes[n] }
	isRKE := func(n string) bool { d := ni(n).Dist; return d == "rke2" || d == "k3s" }
	// The RKE2 STIG only applies where rke2/k3s runs: on a kubeadm cluster
	// it is left out entirely rather than listed as N/A on every node.
	var nodes []string
	for _, n := range e.sshNodes() {
		if isRKE(n) {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return
	}

	e.perNode("V-254555", "rke2 CIS/STIG profile enabled (profile: cis)", "II", g, "config.yaml: profile: cis (requires etcd user + sysctls before restart); STIG also expects audit-policy-file and audit-log-mode=blocking-strict", nodes, func(n string) (Status, string) {
		if !isRKE(n) {
			return NA, ""
		}
		if v := ni(n).Settings["profile"]; strings.Contains(v, "cis") || strings.Contains(v, "etcd") {
			return Pass, ""
		}
		return Fail, "profile not set"
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
}
