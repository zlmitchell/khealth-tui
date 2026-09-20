package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k8s-health-tui/internal/nodeinfo"
)

// CNI / overlay network findings, area "network":
//
//   - MTU: the overlay interface (vxlan, wireguard, ipip) must fit inside the
//     underlay minus the encapsulation overhead, every node must agree, and
//     the CNI config's mtu must be what the interfaces carry - the classic
//     "small requests work, big ones hang" fault;
//   - history: a node whose NetworkUnavailable condition cleared recently,
//     CNI agent pods that restart;
//   - the active probes run from each node with the config tier (see
//     nodeinfo NETPROBE): pod-to-pod over the overlay, DNS through the
//     CoreDNS pods and the service, TCP to the kubernetes service. Which
//     ones fail together says what is broken.

// overlay describes a tunnel interface: the encapsulation overhead it adds
// on top of the underlay MTU and the firewall port it needs between nodes.
type overlay struct {
	kind, port string
	overhead   int
}

// overlays maps interface names to their encapsulation.
var overlays = map[string]overlay{
	"flannel.1":      {"vxlan (flannel/canal)", "8472/udp", 50},
	"flannel-wg":     {"wireguard (flannel)", "51820/udp", 80},
	"flannel-wg-v6":  {"wireguard (flannel, IPv6)", "51821/udp", 80},
	"vxlan.calico":   {"vxlan (calico)", "4789/udp", 50},
	"tunl0":          {"ipip (calico)", "protocol 4", 20},
	"wireguard.cali": {"wireguard (calico)", "51820/udp", 60},
	"cilium_vxlan":   {"vxlan (cilium)", "8472/udp", 50},
	"cilium_wg0":     {"wireguard (cilium)", "51871/udp", 80},
	"vxlan0":         {"vxlan", "4789/udp", 50},
	"genev_sys_6081": {"geneve (ovn/kube-ovn)", "6081/udp", 60},
}

// bridges are the pod-side interfaces whose MTU is what pods get.
var bridges = []string{"cni0", "cilium_host", "kube-bridge", "cbr0"}

func evalNetwork(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	// ---- condition history and CNI pod restarts (API side) ----
	for i := range s.Nodes {
		n := &s.Nodes[i]
		for _, c := range n.Status.Conditions {
			if c.Type != corev1.NodeNetworkUnavailable || c.Status != corev1.ConditionFalse || c.LastTransitionTime.IsZero() {
				continue
			}
			if since := in.Now.Sub(c.LastTransitionTime.Time); since < time.Hour && since >= 0 {
				add(SevInfo, "network", n.Name, fmt.Sprintf("network was unavailable until %s ago (NetworkUnavailable cleared %s)", durText(since), c.LastTransitionTime.Time.Format("15:04:05")), "the CNI (re)started on this node: check its pod's restarts and the node's journal for the reason")
			}
		}
	}
	for _, p := range s.CNIPods() {
		for _, cs := range p.Status.ContainerStatuses {
			if cs.RestartCount == 0 {
				continue
			}
			last := ""
			if t := cs.LastTerminationState.Terminated; t != nil && !t.FinishedAt.IsZero() {
				last = fmt.Sprintf(", last %s ago", durText(in.Now.Sub(t.FinishedAt.Time)))
				if t.Reason != "" {
					last += " (" + t.Reason + ")"
				}
			}
			sev := SevInfo
			if cs.RestartCount >= 5 {
				sev = SevWarn
			}
			add(sev, "network", p.Spec.NodeName, fmt.Sprintf("CNI pod %s container %s restarted %dx%s", p.Name, cs.Name, cs.RestartCount, last), "a CNI agent that keeps restarting drops every pod's network on the node while it is down: kubectl -n "+p.Namespace+" logs "+p.Name+" -c "+cs.Name+" -p")
		}
	}

	// ---- MTU (every probe) ----
	type ovl struct {
		node string
		name string
		mtu  int
	}
	byOverlay := map[string][]ovl{}
	for _, name := range sortedNodes(in.Nodes) {
		ni := in.Nodes[name]
		if ni == nil || ni.Err != nil || len(ni.Links) == 0 {
			continue
		}
		under := 0
		if ni.DefaultDev != "" {
			if l := ni.Link(ni.DefaultDev); l != nil {
				under = l.MTU
			}
		}
		for _, l := range ni.Links {
			o, ok := overlays[l.Name]
			if !ok {
				continue
			}
			byOverlay[l.Name] = append(byOverlay[l.Name], ovl{name, l.Name, l.MTU})
			if under > 0 && l.MTU > under-o.overhead {
				add(SevCrit, "network", name, fmt.Sprintf("%s MTU %d does not fit the underlay %s MTU %d minus the %d-byte %s overhead", l.Name, l.MTU, ni.DefaultDev, under, o.overhead, o.kind), fmt.Sprintf("packets over %d bytes are fragmented or dropped between nodes (large responses hang, small ones work): set the CNI mtu to %d or raise the underlay MTU", under-o.overhead, under-o.overhead))
			}
			if l.State == "DOWN" {
				add(SevCrit, "network", name, l.Name+" ("+o.kind+") is DOWN", "the CNI agent has not brought the tunnel up: check its pod on this node; between nodes "+o.port+" must be open")
			}
		}
		// the pod-side MTU vs the CNI config
		for _, b := range bridges {
			l := ni.Link(b)
			if l == nil {
				continue
			}
			for _, c := range ni.CNI {
				if c.MTU > 0 && c.MTU != l.MTU {
					add(SevWarn, "network", name, fmt.Sprintf("%s MTU %d but %s sets mtu %d", b, l.MTU, shortFile(c.Path), c.MTU), "pods created before the CNI config changed keep the old MTU: restart the CNI agent, then the pods")
				}
			}
			if m := ni.Flannel["mtu"]; m != "" && m != fmt.Sprint(l.MTU) {
				add(SevWarn, "network", name, fmt.Sprintf("%s MTU %d but flannel computed %s (/run/flannel/subnet.env)", b, l.MTU, m), "restart the CNI agent so the bridge follows the backend MTU")
			}
		}
	}
	for name, list := range byOverlay {
		if len(list) < 2 {
			continue
		}
		mtus := map[int][]string{}
		for _, o := range list {
			mtus[o.mtu] = append(mtus[o.mtu], o.node)
		}
		if len(mtus) > 1 {
			var parts []string
			for m, nodes := range mtus {
				sort.Strings(nodes)
				parts = append(parts, fmt.Sprintf("%d on %s", m, strings.Join(nodes, ",")))
			}
			sort.Strings(parts)
			add(SevWarn, "network", "cluster", fmt.Sprintf("%s MTU differs across nodes: %s", name, strings.Join(parts, "; ")), "nodes with different underlay MTUs (a mixed jumbo-frame network) or a CNI config that changed after some nodes joined: pin the CNI mtu to the smallest path")
		}
	}

	// ---- active probes (config tier) ----
	for _, name := range sortedNodes(in.Nodes) {
		ni := in.Nodes[name]
		if ni == nil || ni.Err != nil || !ni.NetProbed {
			continue
		}
		var pingFail, pingOK, dnsPodOK, dnsPodFail, dnsSvcOK, dnsSvcFail, tcpFail []string
		dnsSvc := s.ClusterDNSIP()
		for _, p := range ni.NetProbes {
			if p.Skip {
				add(SevInfo, "network", name, p.Kind+" probe skipped: "+p.Detail, "")
				continue
			}
			switch p.Kind {
			case "PING":
				if p.OK {
					pingOK = append(pingOK, p.Node)
				} else {
					pingFail = append(pingFail, p.Node+" ("+p.Target+")")
				}
			case "DNS":
				svc := p.Target == dnsSvc
				switch {
				case p.OK && svc:
					dnsSvcOK = append(dnsSvcOK, p.Target)
				case p.OK:
					dnsPodOK = append(dnsPodOK, p.Target)
				case svc:
					dnsSvcFail = append(dnsSvcFail, p.Target+": "+p.Detail)
				default:
					dnsPodFail = append(dnsPodFail, p.Target+": "+p.Detail)
				}
			case "TCP":
				if !p.OK {
					tcpFail = append(tcpFail, p.Target+": "+p.Detail)
				}
			}
		}
		ports := overlayPorts(ni)
		switch {
		case len(pingFail) > 0 && len(pingOK) == 0 && len(pingFail) > 1:
			add(SevCrit, "network", name, "pod-to-pod probe failed to every other node: "+strings.Join(pingFail, ", "), "this node's overlay is not forwarding: the CNI agent on this node, or the tunnel port ("+ports+") blocked by the host firewall (firewalld/nftables on RHEL: add the node CIDR to a trusted zone or open the port)")
		case len(pingFail) > 0:
			add(SevCrit, "network", name, "pod-to-pod probe failed to "+strings.Join(pingFail, ", "), "the overlay path between these two nodes is broken while others work: the tunnel port ("+ports+") blocked one way, an MTU mismatch, or the CNI agent on the far node; a pod on this node cannot reach pods there")
		}
		switch {
		case len(dnsPodFail) > 0 && len(dnsPodOK) == 0 && len(pingFail) == 0:
			add(SevCrit, "network", name, "CoreDNS pods answer no query from this node: "+strings.Join(dnsPodFail, "; "), "the overlay works (ping) but CoreDNS does not answer: check the coredns pods' logs and readiness; a NetworkPolicy in kube-system that blocks 53/udp from nodes shows the same")
		case len(dnsPodFail) > 0:
			add(SevWarn, "network", name, "a CoreDNS pod did not answer from this node: "+strings.Join(dnsPodFail, "; "), "one replica unreachable while another answers: its node's overlay path, or that replica is not ready")
		}
		if len(dnsSvcFail) > 0 {
			if len(dnsPodOK) > 0 {
				add(SevCrit, "network", name, "cluster DNS service does not answer from this node but the CoreDNS pods do: "+strings.Join(dnsSvcFail, "; "), "service routing (kube-proxy) is broken on this node: kube-proxy pod / iptables vs nftables backend (RHEL 9 needs the nft backend, not iptables-legacy), or the kube-dns service has no endpoints")
			} else if len(dnsPodFail) == 0 {
				add(SevCrit, "network", name, "cluster DNS service does not answer from this node: "+strings.Join(dnsSvcFail, "; "), "kube-proxy on this node, or CoreDNS: every pod's DNS on this node fails the same way")
			}
		}
		if len(tcpFail) > 0 {
			hint := "kube-proxy on this node is not programming the service (pod / iptables vs nftables backend), or the apiserver endpoints are unreachable from the node"
			if len(dnsSvcOK) > 0 {
				hint = "the DNS service works, so kube-proxy runs: the apiserver endpoint (6443 on the servers) is unreachable from this node - firewall between the node and the control plane"
			}
			add(SevCrit, "network", name, "kubernetes service (ClusterIP) unreachable from this node: "+strings.Join(tcpFail, "; "), hint)
		}

	}
}

// overlayPorts names the tunnel ports of the overlays present on a node.
func overlayPorts(ni *nodeinfo.Info) string {
	var ports []string
	for _, l := range ni.Links {
		if o, ok := overlays[l.Name]; ok {
			ports = append(ports, o.port)
		}
	}
	if len(ports) == 0 {
		return "8472/udp for vxlan, 51820/udp for wireguard, 4789/udp for calico vxlan, 179/tcp for BGP"
	}
	sort.Strings(ports)
	return strings.Join(ports, ", ")
}

func sortedNodes(m map[string]*nodeinfo.Info) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func shortFile(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// durText renders a duration for a finding: "3m", "2h10m", "5d".
func durText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
