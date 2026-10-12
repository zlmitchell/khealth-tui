package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// Node health the API never shows: read-only filesystems, a full conntrack
// table, cgroup v1 under a kubelet that refuses it, kernel tunables the
// CNI needs, a loopback resolver handed to pods, VXLAN checksum offload on
// vmxnet3, and what the kernel's own log says (hung tasks, lockups, disk
// and NIC errors).

// keyPaths are the directories a node cannot lose write access to.
func keyPaths(ni *nodeinfo.Info) []string {
	p := []string{"/", "/var", "/var/lib", "/var/log", "/var/lib/rancher", "/var/lib/kubelet", "/var/lib/containerd", "/var/lib/etcd"}
	if ni.DataDir != "" {
		p = append(p, ni.DataDir)
	}
	return p
}

func evalNodeHealth(name string, ni *nodeinfo.Info, in Input, add func(Severity, string, string, string, string)) {
	nv := distro.For(ni.Dist)

	// ---- read-only filesystems ----
	for _, m := range ni.ROMounts {
		key := false
		for _, p := range keyPaths(ni) {
			if p == m.Mountpoint || strings.HasPrefix(p, strings.TrimSuffix(m.Mountpoint, "/")+"/") {
				key = true
			}
		}
		if key {
			add(SevCrit, "node", name, fmt.Sprintf("%s (%s) is mounted read-only: containers, the kubelet and %s cannot write - usually the kernel remounted it after disk errors (ext4 errors=remount-ro, XFS shutdown)", m.Mountpoint, m.FSType, nv.Server), "kubectl cordon/drain the node; journalctl -k | grep -iE 'ext4|xfs|I/O error'; check the disk or datastore, then fsck / xfs_repair from a rescue boot - remounting rw keeps writing to a failing disk")
		} else {
			add(SevInfo, "node", name, fmt.Sprintf("%s (%s) is mounted read-only", m.Mountpoint, m.FSType), "fine if deliberate; journalctl -k shows whether the kernel did it after errors")
		}
	}

	// ---- conntrack table ----
	if ni.ConntrackMax > 0 {
		pct := ni.ConntrackCount * 100 / ni.ConntrackMax
		hint := "sysctl -w net.netfilter.nf_conntrack_max=<2-4x> and persist it in /etc/sysctl.d/; kube-proxy conntrack-max-per-core (rke2: kube-proxy-arg); conntrack -L | awk '{print $5}' | sort | uniq -c | sort -n | tail shows who opens them"
		switch {
		case pct >= 95:
			add(SevCrit, "node", name, fmt.Sprintf("conntrack table %d%% full (%d/%d): new connections, DNS included, are dropped", pct, ni.ConntrackCount, ni.ConntrackMax), hint)
		case pct >= 80:
			add(SevWarn, "node", name, fmt.Sprintf("conntrack table %d%% full (%d/%d): at 100%% new connections are dropped", pct, ni.ConntrackCount, ni.ConntrackMax), hint)
		}
	}

	// ---- cgroup v1 ----
	if ni.CgroupFS == "tmpfs" { // cgroup v2 mounts cgroup2fs on /sys/fs/cgroup
		minor := -1
		if n := in.Snap.Node(name); n != nil {
			if _, m, _, ok := kubeVersion(n.Status.NodeInfo.KubeletVersion); ok {
				minor = m
			}
		}
		fix := "boot the node with cgroup v2: grubby --update-kernel=ALL --args=systemd.unified_cgroup_hierarchy=1 (RHEL 8) and reboot; RHEL 9 and Ubuntu 22.04+ use v2 by default"
		switch {
		case minor >= 35 && ni.KubeletFlags["fail-cgroupv1"] != "false":
			add(SevCrit, "node", name, "cgroup v1 host under kubelet 1."+fmt.Sprint(minor)+": since 1.35 the kubelet refuses to start on cgroup v1 (failCgroupV1 defaults to true) - the next kubelet restart leaves the node NotReady", fix+"; stopgap: "+kubeletSetting(nv, "fail-cgroupv1=false", "failCgroupV1: false"))
		default:
			add(SevWarn, "node", name, "cgroup v1 host: Kubernetes 1.35+ kubelets refuse to start on it by default - an upgrade blocker", fix)
		}
	}

	// ---- kernel tunables the CNI needs ----
	if len(ni.Sysctl) > 0 && !strings.Contains(strings.ToLower(ni.Settings["cni"]), "cilium") {
		switch v := ni.Sysctl["net.bridge.bridge-nf-call-iptables"]; v {
		case "1":
		case "":
			add(SevWarn, "node", name, "net.bridge.bridge-nf-call-iptables is missing: br_netfilter is not loaded, so traffic between pods on the same bridge bypasses iptables and Services between them break", "modprobe br_netfilter; echo br_netfilter > /etc/modules-load.d/k8s.conf; sysctl -w net.bridge.bridge-nf-call-iptables=1")
		default:
			add(SevWarn, "node", name, "net.bridge.bridge-nf-call-iptables="+v+": traffic between pods on the same bridge bypasses iptables, so Services between them break", "sysctl -w net.bridge.bridge-nf-call-iptables=1 and persist it in /etc/sysctl.d/; rke2/k3s set it at start, so 0 means something reset it later (tuned profile, wicked)")
		}
	}
	if w := strutil.AtoiOr(ni.Sysctl["fs.inotify.max_user_watches"], 0); w > 0 && w < 524288 {
		add(SevInfo, "node", name, fmt.Sprintf("fs.inotify.max_user_watches=%d (524288 recommended): the kubelet, log shippers and file-watching pods fail with 'no space left on device' when it runs out", w), "echo 'fs.inotify.max_user_watches = 524288' > /etc/sysctl.d/99-inotify-watches.conf; sysctl --system")
	}

	// ---- the resolver pods inherit ----
	conf, servers := "/etc/resolv.conf", ni.ResolvEtc
	if rc := ni.KubeletFlags["resolv-conf"]; rc != "" {
		conf = rc
		if strings.Contains(rc, "systemd/resolve") {
			servers = ni.ResolvResolved
		} else if rc != "/etc/resolv.conf" {
			servers = nil // a file we did not read
		}
	}
	for _, ns := range servers {
		if strings.HasPrefix(ns, "127.") || ns == "::1" {
			add(SevWarn, "node", name, fmt.Sprintf("the kubelet hands pods %s with nameserver %s (a local stub): CoreDNS forwards to itself (\"Loop ... detected\") and crash-loops, pods with dnsPolicy Default cannot resolve", conf, ns), "point the kubelet at the real upstreams: "+kubeletSetting(nv, "resolv-conf=/run/systemd/resolve/resolv.conf", "resolvConf: /run/systemd/resolve/resolv.conf")+"; or forward CoreDNS to explicit upstream IPs")
			break
		}
	}
	if len(servers) > 3 {
		add(SevInfo, "node", name, fmt.Sprintf("%s lists %d nameservers: the kubelet passes only 3 to pods (DNSConfigForming events)", conf, len(servers)), "keep at most 3 nameservers")
	}

	// ---- VXLAN checksum offload on vmxnet3 ----
	for dev, v := range ni.Offload {
		if v == "on" && ni.UnderlayDriver == "vmxnet3" {
			add(SevWarn, "network", name, dev+" has tx-checksum-ip-generic on over a vmxnet3 NIC: the known VXLAN checksum bug drops cross-node TCP to Services while ping works (63 s DNS / NodePort delays)", "ethtool -K "+dev+" tx-checksum-ip-generic off now; persist with a udev rule or NetworkManager dispatcher (Calico: FELIX_FEATUREDETECTOVERRIDE=ChecksumOffloadBroken=true)")
		}
	}
}

// kernelFindings turns the kernel-log patterns into node findings; the
// pattern's explanation is the hint.
var kernelFindings = []struct {
	pattern string
	sev     Severity
	what    string
}{
	{"fs-error", SevCrit, "filesystem / block I/O errors in the kernel log"},
	{"conntrack-full", SevCrit, "conntrack table full: the kernel dropped packets"},
	{"hung-task", SevWarn, "tasks blocked in I/O for over 2 minutes (hung_task)"},
	{"soft-lockup", SevWarn, "CPU soft lockup / RCU stall"},
	{"hw-error", SevWarn, "hardware errors (MCE/EDAC)"},
	{"link-down", SevWarn, "network link went down"},
	{"neigh-overflow", SevWarn, "neighbour (ARP) table overflow"},
}

func evalKernelLog(name string, ls *logs.Summary, ago func(logs.Match) string, add func(Severity, string, string, string, string)) {
	for _, k := range kernelFindings {
		n := ls.ByName[k.pattern]
		if n == 0 {
			continue
		}
		last := ls.Last(k.pattern)
		hint := ""
		if last.Pattern != nil {
			hint = last.Pattern.Explain
		}
		add(k.sev, "node", name, fmt.Sprintf("%s: %d line(s)%s - %s", k.what, n, ago(last), strutil.TruncStr(strings.TrimSpace(last.Line), 140)), hint)
	}
}

// kubeletSetting phrases one kubelet setting for the distribution: a
// kubelet-arg flag on rke2/k3s, a KubeletConfiguration field elsewhere.
func kubeletSetting(nv distro.Vocab, flag, field string) string {
	if distro.IsRancher(nv.Name) {
		return fmt.Sprintf(nv.KubeletArgHow, flag)
	}
	return fmt.Sprintf(nv.KubeletArgHow, field)
}

// evalNodeRuntime covers what needs two samples or the runtime itself:
// disk saturation, NIC errors and link flaps, degraded bonds, the ARP
// table, leaked IPAM allocations, a runtime that does not answer, and
// SELinux denials.
func evalNodeRuntime(name string, ni *nodeinfo.Info, in Input, add func(Severity, string, string, string, string)) {
	nv := distro.For(ni.Dist)
	// ---- disks ----
	mountsOf := map[string][]string{}
	for _, m := range ni.Mounts {
		if dev, ok := strings.CutPrefix(m.Filesystem, "/dev/mapper/"); ok {
			mountsOf[dev] = append(mountsOf[dev], m.Mountpoint)
		} else if dev, ok := strings.CutPrefix(m.Filesystem, "/dev/"); ok {
			mountsOf[dev] = append(mountsOf[dev], m.Mountpoint)
		}
	}
	for _, d := range ni.DiskBusy {
		if d.IOPS < 10 {
			continue // a handful of I/Os can look slow without hurting anyone
		}
		where := ""
		if ms := mountsOf[d.Name]; len(ms) > 0 {
			where = " (" + strings.Join(ms, ", ") + ")"
		}
		switch {
		case d.UtilPct >= 90:
			add(SevWarn, "node", name, fmt.Sprintf("disk %s%s busy %.0f%% of the time (%.0f IOPS, await %.1f ms): etcd fsyncs and container writes queue behind it", d.Name, where, d.UtilPct, d.IOPS, d.AwaitMs), "iostat -x 1 / iotop for the writer; give etcd its own low-latency disk; on a VM check the datastore and noisy neighbours")
		case d.AwaitMs >= 50:
			add(SevWarn, "node", name, fmt.Sprintf("disk %s%s answers slowly: average %.0f ms per I/O over %.0f IOPS (etcd wants single-digit ms)", d.Name, where, d.AwaitMs, d.IOPS), "check the storage path (iostat -x 1, multipath -ll, datastore latency)")
		}
	}
	// ---- NIC ----
	if g := ni.NICGrowth; len(g) > 0 {
		var errs []string
		for _, k := range []string{"rx_errors", "tx_errors", "rx_crc_errors", "rx_missed_errors"} {
			if g[k] > 0 {
				errs = append(errs, fmt.Sprintf("%s +%d", k, g[k]))
			}
		}
		if len(errs) > 0 {
			add(SevWarn, "node", name, fmt.Sprintf("%s counted new errors since the last refresh: %s", ni.NICDev, strings.Join(errs, ", ")), "ethtool -S "+ni.NICDev+" | grep -iE 'err|drop|miss'; cable/optic/switch port, or the vNIC ring size (ethtool -G)")
		}
		if n := g["carrier_changes"]; n > 0 {
			add(SevWarn, "node", name, fmt.Sprintf("%s lost and regained its link %d time(s) since the last refresh: every connection through it broke", ni.NICDev, n/2+n%2), "journalctl -k | grep -i 'link is'; check cable, switch port and the bond/vSwitch")
		}
	}
	for _, b := range ni.BondSlaves {
		if !strings.EqualFold(b.Status, "up") {
			add(SevWarn, "node", name, fmt.Sprintf("bond %s slave %s is %s: the node runs without link redundancy", b.Bond, b.Slave, b.Status), "cat /proc/net/bonding/"+b.Bond+"; check the cable and switch port of "+b.Slave)
		}
	}
	if ni.GCThresh3 > 0 && ni.Neigh*100/ni.GCThresh3 >= 80 {
		add(SevWarn, "node", name, fmt.Sprintf("ARP table holds %d entries of gc_thresh3=%d: at the limit the kernel drops traffic to new neighbours", ni.Neigh, ni.GCThresh3), "sysctl -w net.ipv4.neigh.default.gc_thresh1=4096 net.ipv4.neigh.default.gc_thresh2=8192 net.ipv4.neigh.default.gc_thresh3=16384 and persist it in /etc/sysctl.d/")
	}
	// ---- host-local IPAM ----
	if len(ni.IPAMFiles) > 0 && in.Snap != nil {
		pods := 0
		for i := range in.Snap.Pods {
			p := &in.Snap.Pods[i]
			if p.Spec.NodeName == name && !p.Spec.HostNetwork && p.Status.PodIP != "" && p.Status.Phase != "Succeeded" && p.Status.Phase != "Failed" {
				pods++
			}
		}
		size := 254
		if n := in.Snap.Node(name); n != nil && n.Spec.PodCIDR != "" && !strings.Contains(n.Spec.PodCIDR, ":") {
			if _, bits, ok := strings.Cut(n.Spec.PodCIDR, "/"); ok {
				if b := strutil.AtoiOr(bits, 24); b >= 16 && b <= 30 {
					size = 1<<(32-b) - 2
				}
			}
		}
		for _, net := range strutil.SortedKeys(ni.IPAMFiles) {
			n := ni.IPAMFiles[net]
			switch {
			case n*100/size >= 90:
				add(SevCrit, "network", name, fmt.Sprintf("host-local IPAM %s has %d of %d pod IPs allocated (%d pods with an IP run here): new pods fail with \"no IP addresses available\"", net, n, size, pods), ipamHint(net, roleUnit(nv, ni.ControlPlane)))
			case n > pods+20 && n > 2*pods:
				add(SevWarn, "network", name, fmt.Sprintf("host-local IPAM %s holds %d allocations for %d pods: leaked IPs (the rke2 Canal known issue) eat the node's range", net, n, pods), ipamHint(net, roleUnit(nv, ni.ControlPlane)))
			}
		}
	}
	// ---- container runtime ----
	if ni.RuntimeProbed {
		switch {
		case ni.RuntimeRC == 124:
			add(SevCrit, "node", name, "the container runtime does not answer: crictl ps timed out after 10 s - the kubelet's PLEG relist hangs the same way (\"PLEG is not healthy\")", "look for D-state shims (ps -eo stat,pid,comm | awk '$1 ~ /^D/'); restart "+nv.Server+"/"+nv.Agent+" (rke2/k3s: containerd is its child, pods keep running) or containerd on kubeadm; D-state tasks need a reboot")
		case ni.RuntimeRC != 0:
			add(SevWarn, "node", name, fmt.Sprintf("crictl ps failed (exit %d): the runtime socket does not answer cleanly", ni.RuntimeRC), "crictl info; systemctl status containerd (kubeadm) or the "+nv.Name+" journal")
		case ni.RuntimeMs > 5000:
			add(SevWarn, "node", name, fmt.Sprintf("crictl ps took %.1f s: the runtime is slow to answer (the kubelet's relist sees the same)", float64(ni.RuntimeMs)/1000), "look for many sandboxes / a busy containerd; journalctl for 'context deadline exceeded'")
		}
		if ni.NotReadySandboxes > 50 {
			add(SevWarn, "node", name, fmt.Sprintf("%d NotReady pod sandboxes are left on the node: leaked sandboxes slow every runtime call", ni.NotReadySandboxes), "crictl rmp $(crictl pods --state NotReady -q)")
		}
	}
	// ---- SELinux denials ----
	var k8sDeny, crit []string
	for _, a := range ni.Preflight.AVCs {
		if !k8sAVC(a) {
			continue
		}
		txt := fmt.Sprintf("%s (%s -> %s %s) x%d", a.Comm, a.SType, a.TType, a.Class, a.Count)
		k8sDeny = append(k8sDeny, txt)
		if (a.Comm == "etcd" || a.Comm == "containerd" || strings.Contains(a.SType, "etcd")) && !a.Last.IsZero() && in.Now.Sub(a.Last) < time.Hour {
			crit = append(crit, txt)
		}
	}
	if len(k8sDeny) > 0 {
		sev := SevWarn
		if len(crit) > 0 {
			sev = SevCrit
		}
		add(sev, "security", name, "SELinux denied container/Kubernetes access today: "+strutil.TruncList(k8sDeny, 3), "ausearch -m AVC -ts today -i | audit2why; files created over SSH or restored from tar keep the wrong label - restorecon -Rv "+strutil.FirstNonEmpty(ni.DataDir, "/var/lib/rancher")+" /var/lib/kubelet; keep "+nv.Name+"-selinux matching the "+nv.Name+" version; never setenforce 0 on a STIG host")
	}
}

func ipamHint(net, unit string) string {
	return "drain the node, systemctl stop " + unit + ", remove the files in /var/lib/cni/networks/" + net + " for IPs no pod uses (crictl pods -q; or all of them on a drained node), systemctl start " + unit + "; make sure iptables is installed on the host (missing binaries make the CNI leak)"
}

// roleUnit is the unit that runs the node's runtime: the server unit on a
// control-plane node, the agent unit elsewhere (kubelet on kubeadm).
func roleUnit(nv distro.Vocab, controlPlane bool) string {
	if controlPlane || nv.Agent == "" {
		return nv.Server
	}
	return nv.Agent
}

// k8sAVC: a denial that touches containers or the Kubernetes stack.
func k8sAVC(a nodeinfo.AVCDeny) bool {
	for _, t := range []string{a.SType, a.TType} {
		if strings.HasPrefix(t, "container_") || strings.HasPrefix(t, "spc_") || strings.Contains(t, "kubelet") || strings.Contains(t, "rke2") || strings.Contains(t, "k3s") || strings.Contains(t, "etcd") {
			return true
		}
	}
	switch a.Comm {
	case "etcd", "containerd", "containerd-shim", "runc", "kubelet", "rke2", "k3s", "kube-apiserver":
		return true
	}
	return false
}
