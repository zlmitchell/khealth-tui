package k8s

import (
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// NodeRoles returns the node-role.kubernetes.io/* labels of a node.
func NodeRoles(n *corev1.Node) []string {
	var roles []string
	for k := range n.Labels {
		if strings.HasPrefix(k, "node-role.kubernetes.io/") {
			if r := strings.TrimPrefix(k, "node-role.kubernetes.io/"); r != "" {
				roles = append(roles, r)
			}
		}
	}
	sort.Strings(roles)
	if len(roles) == 0 {
		roles = []string{"worker"}
	}
	return roles
}

// IsControlPlane reports whether the node carries a control-plane/master label.
func IsControlPlane(n *corev1.Node) bool {
	for _, r := range NodeRoles(n) {
		if r == "control-plane" || r == "master" {
			return true
		}
	}
	return false
}

// IsEtcdNode reports whether the node is expected to run etcd. rke2 labels
// etcd nodes explicitly; upstream clusters use control-plane nodes.
func IsEtcdNode(nodes []corev1.Node, n *corev1.Node) bool {
	hasEtcdLabel := false
	for i := range nodes {
		if _, ok := nodes[i].Labels["node-role.kubernetes.io/etcd"]; ok {
			hasEtcdLabel = true
			break
		}
	}
	if hasEtcdLabel {
		_, ok := n.Labels["node-role.kubernetes.io/etcd"]
		return ok
	}
	return IsControlPlane(n)
}

// NodeAddress picks an address of the given type, with fallbacks.
func NodeAddress(n *corev1.Node, prefer string) string {
	order := []corev1.NodeAddressType{corev1.NodeInternalIP, corev1.NodeExternalIP, corev1.NodeHostName}
	switch strings.ToLower(prefer) {
	case "externalip":
		order = []corev1.NodeAddressType{corev1.NodeExternalIP, corev1.NodeInternalIP, corev1.NodeHostName}
	case "hostname":
		order = []corev1.NodeAddressType{corev1.NodeHostName, corev1.NodeInternalIP, corev1.NodeExternalIP}
	}
	for _, t := range order {
		for _, a := range n.Status.Addresses {
			if a.Type == t && a.Address != "" {
				return a.Address
			}
		}
	}
	return n.Name
}

// NodeCondition returns the status of a node condition ("True", "False", "Unknown" or "").
func NodeCondition(n *corev1.Node, t corev1.NodeConditionType) (corev1.ConditionStatus, string) {
	for _, c := range n.Status.Conditions {
		if c.Type == t {
			return c.Status, c.Message
		}
	}
	return "", ""
}

// NodeReady reports whether the Ready condition is True.
func NodeReady(n *corev1.Node) bool {
	s, _ := NodeCondition(n, corev1.NodeReady)
	return s == corev1.ConditionTrue
}

// PodStatus mimics kubectl's STATUS column.
func PodStatus(p *corev1.Pod) string {
	if p.DeletionTimestamp != nil && p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
		return "Terminating"
	}
	if p.Status.Reason == "Evicted" {
		return "Evicted"
	}
	status := string(p.Status.Phase)
	if p.Status.Reason != "" {
		status = p.Status.Reason
	}
	for _, cs := range p.Status.InitContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" && cs.State.Waiting.Reason != "PodInitializing" {
			return "Init:" + cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0 {
			return "Init:Error"
		}
		if cs.State.Running != nil {
			return "Init:Running"
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" && p.Status.Phase != corev1.PodSucceeded {
			status = cs.State.Terminated.Reason
		}
	}
	return status
}

// PodReady returns ready/total container counts.
func PodReady(p *corev1.Pod) (int, int) {
	ready := 0
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Ready {
			ready++
		}
	}
	return ready, len(p.Spec.Containers)
}

// PodRestarts returns the total restart count and the most recent restart time.
func PodRestarts(p *corev1.Pod) (int32, time.Time) {
	var total int32
	var last time.Time
	for _, cs := range p.Status.ContainerStatuses {
		total += cs.RestartCount
		if cs.LastTerminationState.Terminated != nil {
			if t := cs.LastTerminationState.Terminated.FinishedAt.Time; t.After(last) {
				last = t
			}
		}
	}
	return total, last
}

// PodHealthy reports whether a pod is in a state that needs no attention.
func PodHealthy(p *corev1.Pod) bool {
	if p.Status.Phase == corev1.PodSucceeded {
		return true
	}
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	st := PodStatus(p)
	if st != "Running" {
		return false
	}
	r, t := PodReady(p)
	return r == t
}

// SumRequests totals CPU (milli) and memory (bytes) requests of the pods.
func SumRequests(pods []corev1.Pod) (int64, int64) {
	var cpu, mem int64
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, c := range p.Spec.Containers {
			if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
				cpu += q.MilliValue()
			}
			if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
				mem += q.Value()
			}
		}
	}
	return cpu, mem
}

// QuantityMilli returns MilliValue of a resource in a list, or 0.
func QuantityMilli(l corev1.ResourceList, name corev1.ResourceName) int64 {
	if q, ok := l[name]; ok {
		return q.MilliValue()
	}
	return 0
}

// QuantityValue returns Value of a resource in a list, or 0.
func QuantityValue(l corev1.ResourceList, name corev1.ResourceName) int64 {
	if q, ok := l[name]; ok {
		return q.Value()
	}
	return 0
}

// ParseQuantityValue parses a quantity string leniently.
func ParseQuantityValue(s string) int64 {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0
	}
	return q.Value()
}

// ComponentArgs extracts the command-line flags of a control-plane component
// from its static/mirror pods in kube-system, keyed by node name.
// Flags are returned as name -> value ("true" for bare flags).
func ComponentArgs(pods []corev1.Pod, component string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" {
			continue
		}
		if p.Labels["component"] != component && !strings.HasPrefix(p.Name, component+"-") {
			continue
		}
		node := p.Spec.NodeName
		if node == "" {
			node = p.Name
		}
		flags := map[string]string{}
		for _, c := range p.Spec.Containers {
			if c.Name != component && !strings.Contains(c.Name, component) && len(p.Spec.Containers) > 1 {
				continue
			}
			for _, a := range append(append([]string{}, c.Command...), c.Args...) {
				if !strings.HasPrefix(a, "--") {
					continue
				}
				a = strings.TrimPrefix(a, "--")
				k, v, found := strings.Cut(a, "=")
				if !found {
					v = "true"
				}
				flags[k] = v
			}
		}
		if len(flags) > 0 {
			out[node] = flags
		}
	}
	return out
}

// IsSystemNamespace reports whether a namespace is owned by the platform.
func IsSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease", "default":
		return true
	}
	for _, p := range []string{"cattle-", "fleet-", "rancher-", "cis-operator", "longhorn-", "calico-", "tigera-", "cilium", "istio-", "linkerd", "kube-", "monitoring", "ingress-nginx", "cert-manager", "metallb-", "velero", "gatekeeper-", "kyverno", "harvester-", "neuvector", "openebs", "rook-", "olm", "operators", "local-path-storage", "kubevirt", "cdi", "argocd", "gitlab-runner", "gpu-operator", "nvidia", "system-upgrade", "trident", "portworx", "vmware-system", "cattle-system"} {
		if strings.HasPrefix(ns, p) {
			return true
		}
	}
	return false
}
