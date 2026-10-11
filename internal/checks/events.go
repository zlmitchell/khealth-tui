package checks

import (
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalEvents raises what the cluster's own events say in the last hour and
// no object status shows: the kubelet failing to garbage-collect images
// (the node heads into DiskPressure), pod sandboxes failing for lack of IPs,
// eviction storms per node, and nodes that are gone for good while their
// pods and volumes wait (the out-of-service taint).
func evalEvents(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	now := in.Now
	gc := map[string][]string{} // node -> reasons
	ipam := map[string]string{} // node -> last message
	for i := range s.Events {
		e := &s.Events[i]
		if now.Sub(k8s.EventTime(e)) > time.Hour {
			continue
		}
		node := e.Source.Host
		if e.InvolvedObject.Kind == "Node" {
			node = e.InvolvedObject.Name
		}
		switch e.Reason {
		case "ImageGCFailed", "FreeDiskSpaceFailed", "ContainerGCFailed":
			if node != "" && !slices.Contains(gc[node], e.Reason) {
				gc[node] = append(gc[node], e.Reason)
			}
		case "FailedCreatePodSandBox":
			m := strings.ToLower(e.Message)
			if strings.Contains(m, "no ip addresses available") || strings.Contains(m, "failed to allocate for range") || strings.Contains(m, "ipam") && strings.Contains(m, "allocate") {
				if node == "" {
					node = podNode(s, e.InvolvedObject.Namespace, e.InvolvedObject.Name)
				}
				if node != "" {
					ipam[node] = strutil.TruncStr(strutil.FirstLine(e.Message), 160)
				}
			}
		}
	}
	for _, n := range strutil.SortedKeys(gc) {
		add(SevWarn, "node", n, "the kubelet could not free disk space in the last hour ("+strings.Join(gc[n], ", ")+"): images in use or pinned (airgap tarballs) keep the disk full, DiskPressure and evictions follow", "crictl rmi --prune; move the containerd root to a larger disk; rke2 airgap: remove old tarballs in agent/images (they are re-imported and pinned at every start)")
	}
	for _, n := range strutil.SortedKeys(ipam) {
		add(SevCrit, "network", n, "pod sandboxes fail for lack of IPs on this node: "+ipam[n], "the node's pod CIDR is used up or IPAM leaked addresses: see the IPAM finding for the node; host-local: clean /var/lib/cni/networks/<net> on a drained node; Calico: calicoctl ipam check")
	}

	// ---- eviction storms ----
	evicted := map[string][]string{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status.Reason != "Evicted" || p.Spec.NodeName == "" {
			continue
		}
		at := p.CreationTimestamp.Time
		for _, c := range p.Status.Conditions {
			if c.LastTransitionTime.After(at) {
				at = c.LastTransitionTime.Time
			}
		}
		if now.Sub(at) < time.Hour {
			evicted[p.Spec.NodeName] = append(evicted[p.Spec.NodeName], p.Namespace+"/"+p.Name)
		}
	}
	for _, n := range strutil.SortedKeys(evicted) {
		if len(evicted[n]) >= 3 {
			add(SevWarn, "node", n, fmt.Sprintf("%d pods evicted from the node in the last hour (%s): it ran short of memory or disk", len(evicted[n]), strutil.TruncList(evicted[n], 3)), "kubectl describe node "+n+" (conditions, the eviction thresholds); the Incidents tab names the pod that caused it; then kubectl delete pod --field-selector=status.phase=Failed to clean up")
		}
	}

	// ---- nodes gone for good: the out-of-service taint ----
	attached := map[string]bool{}
	for i := range s.VolumeAttachments {
		if s.VolumeAttachments[i].Status.Attached {
			attached[s.VolumeAttachments[i].Spec.NodeName] = true
		}
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		var since time.Time
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue {
				since = c.LastTransitionTime.Time
			}
		}
		if since.IsZero() || now.Sub(since) < 5*time.Minute {
			continue
		}
		stuck := 0
		for j := range s.Pods {
			p := &s.Pods[j]
			if p.Spec.NodeName == n.Name && p.DeletionTimestamp != nil {
				stuck++
			}
		}
		if stuck == 0 && !attached[n.Name] {
			continue
		}
		tainted := false
		for _, t := range n.Spec.Taints {
			if t.Key == "node.kubernetes.io/out-of-service" {
				tainted = true
			}
		}
		if tainted {
			continue
		}
		what := fmt.Sprintf("%d pod(s) stuck Terminating there", stuck)
		if attached[n.Name] {
			what += " and volumes still attached to it"
		}
		add(SevWarn, "node", n.Name, fmt.Sprintf("NotReady for %s with %s: StatefulSet pods and RWO volumes wait for the node forever", strutil.HumanDur(now.Sub(since)), what), "only once the node is confirmed powered off: kubectl taint nodes "+n.Name+" node.kubernetes.io/out-of-service=nodeshutdown:NoExecute (non-graceful node shutdown force-deletes its pods and detaches the volumes); remove the taint when the node is back")
	}
}

// podNode is the node a pod is bound to ("" when unknown).
func podNode(s *k8s.Snapshot, ns, name string) string {
	for i := range s.Pods {
		if s.Pods[i].Namespace == ns && s.Pods[i].Name == name {
			return s.Pods[i].Spec.NodeName
		}
	}
	return ""
}
