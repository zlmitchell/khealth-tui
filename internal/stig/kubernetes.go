package stig

// DISA Kubernetes STIG V2R6 (Release 6, benchmark date 01 Apr 2026), from
// dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V2R6_STIG.zip.
// Vulnerability IDs and categories follow that XCCDF; the check logic is
// adapted to rke2/k3s layouts as well as kubeadm.

import (
	"fmt"
	"sort"
	"strings"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

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
	e.perNode("V-254800", "Pod Security Admission configured (admission-control-config-file)", "I", g, "rke2: profile: cis (uses /etc/rancher/rke2/rke2-pss.yaml) or set pod-security-admission-config-file; kubeadm: --admission-control-config-file", nodes, func(n string) (Status, string) {
		f := rk(n)
		if f["admission-control-config-file"] != "" || f["pod-security-admission-config-file"] != "" {
			return Pass, ""
		}
		return Fail, "no admission config file (namespaces must carry pod-security.kubernetes.io/enforce labels instead)"
	})
	e.perNode("V-242438", "API server request-timeout set", "II", g, "kube-apiserver-arg: request-timeout=300s", nodes, func(n string) (Status, string) { return flagSet(rk(n), "request-timeout") })
	e.perNode("V-274882", "Secrets encrypted at rest (encryption-provider-config, verified in etcd)", "I", g, "rke2: secrets-encryption: true; kubeadm: --encryption-provider-config with aescbc/kms first and identity last, then rewrite existing secrets: kubectl get secrets -A -o json | kubectl replace -f -", nodes, func(n string) (Status, string) {
		if st, d := flagSet(rk(n), "encryption-provider-config"); st != Pass {
			return st, d
		}
		return e.encryptionAtRest()
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

// encryptionAtRest judges V-274882 from the etcd probes: the provider order
// of the running apiserver's config (identity first means new writes are
// plaintext) and a Secret sampled from etcd (stored values start with
// "k8s:enc:<provider>:" only when actually encrypted). The flag alone proves
// nothing: secrets written before it was enabled stay plaintext until they
// are rewritten.
func (e *evaluator) encryptionAtRest() (Status, string) {
	var probes []*etcd.Probe
	if e.in.EtcdExec != nil {
		probes = append(probes, e.in.EtcdExec)
	}
	for _, n := range sortedProbeNodes(e.in.Etcd) {
		probes = append(probes, e.in.Etcd[n])
	}
	var cfg, sample *etcd.Encryption
	for _, p := range probes {
		if p == nil || p.Encryption == nil {
			continue
		}
		if cfg == nil && len(p.Encryption.Tokens) > 0 {
			cfg = p.Encryption
		}
		if sample == nil && p.Encryption.SamplePrefix != "" {
			sample = p.Encryption
		}
	}
	var probs []string
	if cfg != nil {
		if prov := cfg.Providers(); len(prov) > 0 && prov[0] == "identity" {
			probs = append(probs, "identity is the first provider in "+cfg.ConfigFile+" (new writes are plaintext)")
		}
		hasSecrets := false
		for _, t := range cfg.Tokens {
			if t == "secrets" {
				hasSecrets = true
			}
		}
		if !hasSecrets {
			probs = append(probs, "secrets are not listed as an encrypted resource in "+cfg.ConfigFile)
		}
	}
	sampled, encrypted, provider := sample.Sampled()
	switch {
	case sampled && !encrypted:
		probs = append(probs, "etcd sample "+sample.SampleKey+" is stored in plaintext (rewrite existing secrets)")
	}
	if len(probs) > 0 {
		return Fail, strings.Join(probs, "; ")
	}
	switch {
	case sampled:
		d := "etcd sample encrypted with " + provider
		if cfg != nil {
			d += "; providers " + strings.Join(cfg.Providers(), ",")
		}
		return Pass, d
	case cfg != nil:
		return Manual, "config providers " + strings.Join(cfg.Providers(), ",") + "; no etcd sample (etcdctl unavailable) - confirm existing secrets were rewritten"
	}
	return Manual, "encryption-provider-config set; etcd content not sampled (needs the etcd probe) - confirm existing secrets were rewritten"
}

func sortedProbeNodes(m map[string]*etcd.Probe) []string {
	var out []string
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// kubeletNodes lists nodes whose kubelet config was read via configz.
func (e *evaluator) kubeletNodes() []string {
	var nodes []string
	for n := range e.in.Snap.KubeletConfigs {
		nodes = append(nodes, n)
	}
	return nodes
}

func (e *evaluator) kubeletCfg(n string) map[string]any { return e.in.Snap.KubeletConfigs[n] }

const kubeletFix = "rke2: kubelet-arg in config.yaml (profile: cis sets most); kubeadm: /var/lib/kubelet/config.yaml"

func (e *evaluator) kubeletRules() {
	g := "kubelet"
	nodes := e.kubeletNodes()
	cfg := e.kubeletCfg
	fix := kubeletFix
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

// nodeRules covers the Kubernetes STIG file-permission rules evaluated from
// node facts collected over SSH.
func (e *evaluator) nodeRules() {
	g := "node"
	nodes := e.sshNodes()
	ni := func(n string) *nodeinfo.Info { return e.in.Nodes[n] }
	isRKE := func(n string) bool { d := ni(n).Dist; return d == "rke2" || d == "k3s" }

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

	// V-242415 secrets as environment variables
	var secretEnv []string
	for i := range s.Pods {
		p := &s.Pods[i]
		ref := p.Namespace + "/" + p.Name
		for _, c := range p.Spec.Containers {
			for _, env := range c.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					secretEnv = append(secretEnv, ref)
					break
				}
			}
		}
	}
	r = Result{ID: "V-242415", Title: "Secrets are not exposed as environment variables", Cat: "I", Group: g, Status: Pass, Detail: "none", Fix: "mount secrets as files instead of env vars"}
	if len(secretEnv) > 0 {
		r.Status = Manual
		r.Detail = fmt.Sprintf("%d pod(s) use secretKeyRef env: %s", len(secretEnv), truncList(uniq(secretEnv), 5))
	}
	e.add(r)

	// version currency
	e.add(Result{ID: "V-242443", Title: "Kubernetes is a supported, patched version", Cat: "II", Group: g, Status: Manual, Detail: "cluster " + s.Version + " - verify against the current upstream support window (three most recent minors) and rke2 release notes", Fix: "upgrade"})

}
