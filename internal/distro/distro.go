// Package distro is the vocabulary of each Kubernetes distribution: unit
// names, config files, data directories and the commands that restart,
// reissue certificates or change kubelet settings. Findings, hints and tab
// text ask for the words here instead of assuming rke2, so a kubeadm
// cluster reads "kubelet / /var/lib/kubelet/config.yaml / kubeadm certs
// renew" where an rke2 one reads "rke2-server / config.yaml / restart".
package distro

import "strings"

// Vocab is the wording for one distribution.
type Vocab struct {
	Name  string // rke2, k3s, kubeadm, kubernetes (generic upstream)
	Label string // how the UI names it

	Server, Agent string   // systemd units that run a control-plane / worker node
	Units         []string // every unit that carries the kubelet (rke2/k3s run it as a child)

	ConfigFile string // the node's main config file
	ConfigName string // short name for prose ("config.yaml", "KubeletConfiguration")
	ConfigDir  string // where per-node config lives
	DataDir    string
	Manifests  string // static pod manifests
	Certs      string // control-plane certificates
	Binaries   string // "rke2 binaries and container runtimes" / "kubelet and containerd binaries"

	RestartServer string // command that restarts the control plane on one node
	RestartAgent  string
	RestartNote   string // e.g. "one server at a time"

	Registries      string // private registry / mirror configuration
	RegistryReload  string // how to apply a registries change
	CertRenew       string // client/serving certificate rotation
	SANKey          string // where extra apiserver SANs are configured
	Reissue         string // how the apiserver serving certificate is regenerated
	NodeTaint       string // how control-plane nodes get their taint
	CloudProviderOn string // how the external cloud provider is enabled on the node
	KubeletArgHow   string // how a kubelet flag/setting is changed, "%s" = the setting
	CISProfile      string // how the hardening profile is enabled
	EtcdBackups     string // how etcd backups are taken by default
	EtcdDataDir     string
	FapolicydFile   string   // rules.d file that allows the distribution's paths
	FapolicydDirs   []string // directories that file must allow (binaries outside the package trust db)
	Supervisor      string   // the process that (re)starts the components: "rke2-server", "kubelet (static pods)"
}

var vocab = map[string]Vocab{
	"rke2": {
		Name: "rke2", Label: "RKE2",
		Server: "rke2-server", Agent: "rke2-agent", Units: []string{"rke2-server", "rke2-agent"},
		ConfigFile: "/etc/rancher/rke2/config.yaml", ConfigName: "config.yaml", ConfigDir: "/etc/rancher/rke2",
		DataDir: "/var/lib/rancher/rke2", Manifests: "/var/lib/rancher/rke2/agent/pod-manifests", Certs: "/var/lib/rancher/rke2/server/tls",
		Binaries:      "rke2 binaries and container runtimes",
		RestartServer: "systemctl restart rke2-server", RestartAgent: "systemctl restart rke2-agent", RestartNote: "one server at a time",
		Registries: "/etc/rancher/rke2/registries.yaml", RegistryReload: "restart rke2 to regenerate the containerd config",
		CertRenew:       "restart rke2: client certificates within 90 days of expiry are rotated on start; rke2 certificate rotate for the rest",
		SANKey:          "tls-san (config.yaml)",
		Reissue:         "systemctl restart rke2-server (one server at a time); rke2 regenerates serving-kube-apiserver.crt with the new SANs",
		NodeTaint:       "config.yaml on servers: node-taint: [\"CriticalAddonsOnly=true:NoExecute\"]",
		CloudProviderOn: "config.yaml: cloud-provider-name: %s (kubelet-arg cloud-provider=external) and disable-cloud-controller: true, then restart rke2",
		KubeletArgHow:   "config.yaml: kubelet-arg: [\"%s\"], then restart rke2",
		CISProfile:      "config.yaml: profile: cis (requires the etcd user and rke2-cis-sysctl.conf before the restart)",
		EtcdBackups:     "rke2 takes etcd snapshots by default (etcd-snapshot-schedule-cron, etcd-snapshot-retention; etcd-s3-* for off-box copies)",
		EtcdDataDir:     "/var/lib/rancher/rke2/server/db/etcd",
		FapolicydFile:   "/etc/fapolicyd/rules.d/80-rke2.rules",
		FapolicydDirs:   []string{"/var/lib/rancher/", "/opt/cni/", "/run/k3s/", "/var/lib/kubelet/"},
		Supervisor:      "rke2-server",
	},
	"k3s": {
		Name: "k3s", Label: "k3s",
		Server: "k3s", Agent: "k3s-agent", Units: []string{"k3s", "k3s-agent"},
		ConfigFile: "/etc/rancher/k3s/config.yaml", ConfigName: "config.yaml", ConfigDir: "/etc/rancher/k3s",
		DataDir: "/var/lib/rancher/k3s", Manifests: "/var/lib/rancher/k3s/agent/pod-manifests", Certs: "/var/lib/rancher/k3s/server/tls",
		Binaries:      "the k3s binary and container runtimes",
		RestartServer: "systemctl restart k3s", RestartAgent: "systemctl restart k3s-agent", RestartNote: "one server at a time",
		Registries: "/etc/rancher/k3s/registries.yaml", RegistryReload: "restart k3s to regenerate the containerd config",
		CertRenew:       "restart k3s: client certificates within 90 days of expiry are rotated on start; k3s certificate rotate for the rest",
		SANKey:          "tls-san (config.yaml)",
		Reissue:         "systemctl restart k3s (one server at a time); k3s regenerates serving-kube-apiserver.crt with the new SANs",
		NodeTaint:       "config.yaml on servers: node-taint: [\"CriticalAddonsOnly=true:NoExecute\"]",
		CloudProviderOn: "config.yaml: disable-cloud-controller: true and kubelet-arg cloud-provider=external, then restart k3s",
		KubeletArgHow:   "config.yaml: kubelet-arg: [\"%s\"], then restart k3s",
		CISProfile:      "config.yaml: protect-kernel-defaults: true and the k3s CIS hardening guide",
		EtcdBackups:     "k3s takes etcd snapshots by default (etcd-snapshot-schedule-cron, etcd-snapshot-retention; etcd-s3-* for off-box copies)",
		EtcdDataDir:     "/var/lib/rancher/k3s/server/db/etcd",
		FapolicydFile:   "/etc/fapolicyd/rules.d/80-k3s.rules",
		FapolicydDirs:   []string{"/var/lib/rancher/", "/opt/cni/", "/run/k3s/", "/var/lib/kubelet/"},
		Supervisor:      "k3s",
	},
	"kubeadm": {
		Name: "kubeadm", Label: "kubeadm",
		Server: "kubelet", Agent: "kubelet", Units: []string{"kubelet"},
		ConfigFile: "/var/lib/kubelet/config.yaml", ConfigName: "KubeletConfiguration (/var/lib/kubelet/config.yaml)", ConfigDir: "/etc/kubernetes",
		DataDir: "/var/lib/kubelet", Manifests: "/etc/kubernetes/manifests", Certs: "/etc/kubernetes/pki",
		Binaries:      "the kubelet, containerd and CNI binaries",
		RestartServer: "systemctl restart kubelet", RestartAgent: "systemctl restart kubelet", RestartNote: "the static pods restart with it",
		Registries: "/etc/containerd/config.toml (config_path) and /etc/containerd/certs.d/<registry>/hosts.toml", RegistryReload: "systemctl restart containerd",
		CertRenew:       "kubeadm certs renew all on each control-plane node, then restart the static pods (move the manifests out of /etc/kubernetes/manifests and back); kubelet client certs rotate on their own with rotateCertificates",
		SANKey:          "kubeadm-config apiServer.certSANs",
		Reissue:         "on each control-plane node: kubeadm certs renew apiserver (reads certSANs from kube-system/kubeadm-config), then restart kube-apiserver (crictl stopp the pod, or move its manifest out of /etc/kubernetes/manifests and back)",
		NodeTaint:       "kubectl taint nodes <node> node-role.kubernetes.io/control-plane:NoSchedule (kubeadm sets it at init unless skipped)",
		CloudProviderOn: "KubeletConfiguration / kubeadm nodeRegistration.kubeletExtraArgs: cloud-provider: external, deploy the %s cloud-controller-manager manifests, then systemctl restart kubelet",
		KubeletArgHow:   "%s in /var/lib/kubelet/config.yaml (KubeletConfiguration, also kubeadm-config kubelet ConfigMap), then systemctl restart kubelet",
		CISProfile:      "kube-bench / the CIS Kubernetes benchmark: apiserver, controller-manager and scheduler flags in /etc/kubernetes/manifests, kubelet settings in /var/lib/kubelet/config.yaml",
		EtcdBackups:     "kubeadm takes no etcd backups: schedule etcdctl snapshot save (ETCDCTL_API=3, certs under /etc/kubernetes/pki/etcd) or use a backup operator",
		EtcdDataDir:     "/var/lib/etcd",
		FapolicydFile:   "/etc/fapolicyd/rules.d/80-kubernetes.rules",
		FapolicydDirs:   []string{"/opt/cni/", "/var/lib/kubelet/", "/var/lib/containerd/", "/run/containerd/"},
		Supervisor:      "kubelet (static pods)",
	},
}

// For returns the vocabulary for a distribution name (rke2, k3s, kubeadm);
// anything else gets the generic upstream wording, which is the kubeadm
// layout without the kubeadm commands.
func For(dist string) Vocab {
	if v, ok := vocab[strings.ToLower(dist)]; ok {
		return v
	}
	v := vocab["kubeadm"]
	v.Name, v.Label = "kubernetes", "Kubernetes"
	if d := strings.ToLower(dist); d != "" && d != "unknown" {
		v.Label = dist // eks, gke, aks, openshift, talos, ... as detected
	}
	v.CertRenew = "renew the control-plane certificates with the tooling that installed the cluster; kubelet client certs rotate on their own with rotateCertificates"
	v.SANKey = "the apiserver's --tls-san / certSANs setting"
	v.Reissue = "reissue the apiserver serving certificate with the tooling that installed the cluster"
	v.NodeTaint = "kubectl taint nodes <node> node-role.kubernetes.io/control-plane:NoSchedule"
	v.CloudProviderOn = "kubelet --cloud-provider=external and the %s cloud-controller-manager manifests"
	v.CISProfile = "kube-bench / the CIS Kubernetes benchmark for the installed components"
	v.EtcdBackups = "no built-in etcd backups: schedule etcdctl snapshot save or use a backup operator"
	return v
}

// IsRancher reports whether the distribution is rke2 or k3s (config.yaml,
// registries.yaml, supervisor units).
func IsRancher(dist string) bool {
	d := strings.ToLower(dist)
	return d == "rke2" || d == "k3s"
}

// KubeletArg formats the hint that changes one kubelet setting: flag form
// ("fail-swap-on=false") for rke2/k3s, KubeletConfiguration field for the
// rest.
func (v Vocab) KubeletArg(flag, field string) string {
	if IsRancher(v.Name) {
		return strings.Replace(v.KubeletArgHow, "%s", flag, 1)
	}
	return strings.Replace(v.KubeletArgHow, "%s", field, 1)
}

// CloudProvider formats the hint that enables the external cloud provider.
func (v Vocab) CloudProvider(provider string) string {
	name := provider
	if v.Name == "rke2" {
		switch provider {
		case "vsphere":
			name = "rancher-vsphere"
		case "aws":
			name = "aws"
		default:
			name = "external"
		}
	}
	return strings.Replace(v.CloudProviderOn, "%s", name, 1)
}

// Restart is the restart command for a node by role.
func (v Vocab) Restart(controlPlane bool) string {
	if controlPlane {
		return v.RestartServer
	}
	return v.RestartAgent
}
