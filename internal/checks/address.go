package checks

import (
	"fmt"
	"net"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalAddresses covers a node whose address changed under a running
// cluster: rke2/k3s render every listener (etcd peer and client URLs, the
// kubelet's node address) from node-ip in config.yaml, so a pinned value
// the node no longer holds stops etcd with "bind: cannot assign requested
// address", and the other servers' server: URL keeps pointing at the old
// address. Both come from the node probes (config.yaml settings and the
// addresses on the interfaces), nothing from the API, which still shows
// the stale InternalIP the kubelet last reported.
func evalAddresses(in Input, add func(Severity, string, string, string, string)) {
	// stale: address -> node that was known by it and no longer holds it
	stale := map[string]string{}
	for name, ni := range in.Nodes {
		if ni == nil || ni.Err != nil || len(ni.Addrs) == 0 {
			continue
		}
		if in.Snap != nil {
			if n := in.Snap.Node(name); n != nil {
				for _, a := range n.Status.Addresses {
					if net.ParseIP(a.Address) != nil && !ni.HasAddr(a.Address) {
						stale[a.Address] = name
					}
				}
			}
		}
		if ip := ni.Settings["node-ip"]; ip != "" && !ni.HasAddr(ip) {
			stale[ip] = name
		}
	}
	for _, name := range strutil.SortedKeys(in.Nodes) {
		ni := in.Nodes[name]
		if ni == nil || ni.Err != nil || len(ni.Addrs) == 0 || !distro.IsRancher(ni.Dist) {
			continue
		}
		v := distro.For(ni.Dist)
		if ip := ni.Settings["node-ip"]; ip != "" && !ni.HasAddr(ip) {
			add(SevCrit, "node", name, fmt.Sprintf("%s pins node-ip: %s but the node holds %s: etcd and the kubelet bind their listeners to node-ip, so %s cannot come up (etcd: listen tcp %s:2380: bind: cannot assign requested address)", v.ConfigName, ip, strutil.TruncList(ni.Addrs, 3), v.Server, ip),
				fmt.Sprintf("set node-ip to %s (or remove it) in %s and restart %s; the etcd tab's rescue rejoins the member under its new address (X > rejoin one server) - the cluster still lists the member at %s, which the rejoin removes", nodeinfo.FirstAddr(ni), v.ConfigFile, v.Server, ip))
		}
		srv := ni.Settings["server"]
		h := strutil.URLHost(srv)
		if h == "" || net.ParseIP(h) == nil {
			continue // a VIP by name, or no server: (the cluster-init node)
		}
		if moved, ok := stale[h]; ok && moved != name {
			add(SevWarn, "node", name, fmt.Sprintf("%s server: %s points at the old address of %s, which now holds %s: nothing answers there, so a restart of %s here falls back on its saved server list (%s/agent/etc) - a fresh install could not join at all", v.ConfigName, srv, moved, strutil.TruncList(in.Nodes[moved].Addrs, 2), v.Server, ni.DataDir),
				"point server: at a VIP / load balancer in front of the servers, or at the new address, then restart "+v.Server+" (one server at a time)")
			continue
		}
		known := false
		for _, o := range in.Nodes {
			if o != nil && o.Err == nil && o.ControlPlane && len(o.Addrs) > 0 && o.HasAddr(h) {
				known = true
			}
		}
		if in.Snap != nil {
			for i := range in.Snap.Nodes {
				for _, a := range in.Snap.Nodes[i].Status.Addresses {
					if a.Address == h {
						known = true
					}
				}
			}
		}
		if !known && !strings.HasPrefix(h, "127.") {
			add(SevInfo, "node", name, fmt.Sprintf("%s server: %s is no address of a known server node: a VIP / load balancer (fine), or a server that is gone", v.ConfigName, srv), "")
		}
	}
}
