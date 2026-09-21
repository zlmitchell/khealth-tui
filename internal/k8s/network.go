package k8s

import (
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// Cluster networking facts derived from the snapshot: the addresses the
// node-side network probes target and the CNI's own pods.

// ClusterDNSIP is the ClusterIP of the cluster DNS service (kube-dns /
// CoreDNS), "" when it cannot be found.
func (s *Snapshot) ClusterDNSIP() string {
	for i := range s.Services {
		svc := &s.Services[i]
		if svc.Namespace != "kube-system" || svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
			continue
		}
		if svc.Name == "kube-dns" || svc.Name == "rke2-coredns-rke2-coredns" || svc.Name == "coredns" || svc.Labels["k8s-app"] == "kube-dns" {
			return svc.Spec.ClusterIP
		}
	}
	return ""
}

// APIServiceIP is the ClusterIP of default/kubernetes: reaching it from a
// node proves kube-proxy's service routing (iptables / nftables / ipvs).
func (s *Snapshot) APIServiceIP() string {
	for i := range s.Services {
		svc := &s.Services[i]
		if svc.Namespace == "default" && svc.Name == "kubernetes" {
			return svc.Spec.ClusterIP
		}
	}
	return ""
}

// IsServiceIP reports whether ip is the ClusterIP of a Service (an NFS
// export at a service IP is a Longhorn / NFS-server-in-cluster share).
func (s *Snapshot) IsServiceIP(ip string) bool {
	for i := range s.Services {
		if s.Services[i].Spec.ClusterIP == ip && ip != "" {
			return true
		}
	}
	return false
}

// cniPodPrefixes name the CNI daemonset pods of the distributions khealth
// knows; k8s-app labels cover the upstream manifests.
var cniPodPrefixes = []string{"rke2-canal-", "rke2-calico-node-", "rke2-cilium-", "rke2-flannel-", "rke2-multus-", "canal-", "calico-node-", "cilium-", "kube-flannel-", "flannel-", "kube-ovn-", "weave-net-", "antrea-agent-", "aws-node-", "azure-cni-"}
var cniPodLabels = []string{"canal", "calico-node", "cilium", "flannel", "kube-flannel", "weave-net", "antrea-agent", "aws-node"}

// cniExtra are the operator's own CNI pod names/prefixes (config
// namespaces.cni), for a CNI khealth does not know or a renamed one.
var cniExtra struct {
	sync.RWMutex
	names []string
}

// SetCNINames installs extra CNI agent pod names (a prefix when the entry
// ends in "-" or "*", else an exact name or app label).
func SetCNINames(entries []string) {
	cniExtra.Lock()
	defer cniExtra.Unlock()
	cniExtra.names = nil
	for _, e := range entries {
		if e = strings.TrimSpace(e); e != "" {
			cniExtra.names = append(cniExtra.names, e)
		}
	}
}

// CNIPods are the CNI agent pods (one per node for a daemonset CNI), in
// whatever namespace the CNI was installed (cilium, calico and kube-ovn
// charts default to their own): a system namespace or a DaemonSet owner,
// plus the name/label match, is selective enough.
func (s *Snapshot) CNIPods() []*corev1.Pod {
	var out []*corev1.Pod
	for i := range s.Pods {
		p := &s.Pods[i]
		ds := IsSystemNamespace(p.Namespace)
		for _, o := range p.OwnerReferences {
			if o.Kind == "DaemonSet" {
				ds = true
			}
		}
		if ds && isCNIPod(p) {
			out = append(out, p)
		}
	}
	return out
}

func isCNIPod(p *corev1.Pod) bool {
	for _, l := range cniPodLabels {
		if p.Labels["k8s-app"] == l || p.Labels["app"] == l || p.Labels["app.kubernetes.io/name"] == l {
			return true
		}
	}
	for _, pre := range cniPodPrefixes {
		if strings.HasPrefix(p.Name, pre) {
			return true
		}
	}
	cniExtra.RLock()
	defer cniExtra.RUnlock()
	for _, e := range cniExtra.names {
		if strings.HasSuffix(e, "-") || strings.HasSuffix(e, "*") {
			if strings.HasPrefix(p.Name, strings.TrimSuffix(e, "*")) {
				return true
			}
		} else if p.Name == e || p.Labels["k8s-app"] == e || p.Labels["app"] == e || p.Labels["app.kubernetes.io/name"] == e {
			return true
		}
	}
	return false
}

// PodTargets picks one running pod-network pod per node as the target of
// the pod-to-pod probe (node -> overlay -> pod on another node), keyed by
// node name. CoreDNS and metrics-server are preferred: they answer and
// live on the pod network everywhere; the CNI pods (host network) never
// qualify.
func (s *Snapshot) PodTargets() map[string]string {
	best := map[string]int{}
	out := map[string]string{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.HostNetwork || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || p.Spec.NodeName == "" {
			continue
		}
		rank := 1
		switch {
		case strings.Contains(p.Name, "coredns"):
			rank = 3
		case strings.Contains(p.Name, "metrics-server"):
			rank = 2
		}
		if rank > best[p.Spec.NodeName] {
			best[p.Spec.NodeName] = rank
			out[p.Spec.NodeName] = p.Status.PodIP
		}
	}
	return out
}

// PodTargetList renders PodTargets as "node=ip" entries in node order.
func (s *Snapshot) PodTargetList() []string {
	t := s.PodTargets()
	var out []string
	for n, ip := range t {
		out = append(out, n+"="+ip)
	}
	sort.Strings(out)
	return out
}
