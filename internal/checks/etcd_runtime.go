package checks

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// etcdRuntime is how etcd is run on a node. It decides every command the
// triage prints: rke2/k3s supervise etcd through their server unit and rejoin
// members automatically; kubeadm runs it as a static pod that kubelet manages
// through /etc/kubernetes/manifests; kubespray-style installs run a plain
// etcd.service. The commands below follow each project's documented recovery
// procedure.
type etcdRuntime struct {
	kind    string // rke2 | k3s | kubeadm | systemd
	svc     string // unit that must be active for etcd to exist
	dataDir string // etcd member data dir (the one with member/wal)
	static  bool   // etcd is a container kubelet runs from a static pod
	stop    string // stop the local etcd member
	start   string // start it again
	restart string // bounce it in place
	logs    string // read the local member's own log
}

const kubeadmManifest = "/etc/kubernetes/manifests/etcd.yaml"
const kubeadmParked = "/etc/kubernetes/etcd.yaml.off"

// runtimeFor picks the runtime for one node from what the probe saw on it,
// falling back to the cluster distribution.
func runtimeFor(t *etcdTriage, dist string) etcdRuntime {
	kind := dist
	if t != nil && t.probe != nil {
		switch t.probe.Dist {
		case "rke2", "k3s", "kubeadm":
			kind = t.probe.Dist
		case "kubespray":
			kind = "systemd"
		}
		for _, src := range t.probe.Sources {
			if strings.HasPrefix(src, "systemd etcd.service") {
				kind = "systemd"
			}
		}
	}
	if t != nil && t.info != nil && kind != "rke2" && kind != "k3s" {
		for _, s := range t.info.Services {
			if s.Name == "etcd" && s.Load == "loaded" {
				kind = "systemd"
			}
		}
	}
	dd := ""
	if t != nil && t.probe != nil {
		dd = t.probe.DataDir
	}
	return runtimeOf(kind, dd)
}

func runtimeOf(kind, dataDir string) etcdRuntime {
	switch kind {
	case "rke2", "k3s":
		svc := "rke2-server"
		if kind == "k3s" {
			svc = "k3s"
		}
		if dataDir == "" {
			dataDir = "/var/lib/rancher/" + kind + "/server/db/etcd"
		}
		logs := "crictl logs --tail 200 $(crictl ps -a -q --name etcd | head -1)"
		if kind == "k3s" {
			logs = "journalctl -u k3s -n 500 --no-pager | grep -iE 'etcd|raft'" // in-process etcd
		}
		return etcdRuntime{kind: kind, svc: svc, dataDir: dataDir, static: kind == "rke2",
			stop: "systemctl stop " + svc, start: "systemctl start " + svc, restart: "systemctl restart " + svc, logs: logs}
	case "systemd":
		if dataDir == "" {
			dataDir = "/var/lib/etcd"
		}
		return etcdRuntime{kind: kind, svc: "etcd", dataDir: dataDir,
			stop: "systemctl stop etcd", start: "systemctl start etcd", restart: "systemctl restart etcd", logs: "journalctl -u etcd -n 200 --no-pager"}
	default: // kubeadm and anything else with a static pod
		if dataDir == "" {
			dataDir = "/var/lib/etcd"
		}
		return etcdRuntime{kind: "kubeadm", svc: "kubelet", dataDir: dataDir, static: true,
			stop:    "mv " + kubeadmManifest + " " + kubeadmParked + "   (kubelet stops the etcd pod within ~20s; confirm with crictl ps --name etcd)",
			start:   "mv " + kubeadmParked + " " + kubeadmManifest,
			restart: "crictl stop $(crictl ps -q --name etcd)   (kubelet recreates the static pod)",
			logs:    "crictl logs --tail 200 $(crictl ps -a -q --name etcd | head -1)   (or kubectl -n kube-system logs etcd-<node> --previous)"}
	}
}

// dbDir is what to wipe before a node rejoins after a cluster reset: rke2/k3s
// keep etcd plus bootstrap state under server/db, the others just the data dir.
func (r etcdRuntime) dbDir() string {
	if r.kind == "rke2" || r.kind == "k3s" {
		return strings.TrimSuffix(r.dataDir, "/etcd")
	}
	return r.dataDir
}

// resetName is what the "make this node the only truth" operation is called.
func (r etcdRuntime) resetName() string {
	if r.kind == "rke2" || r.kind == "k3s" {
		return "cluster-reset"
	}
	return "force-new-cluster"
}

func (r etcdRuntime) product() string {
	if r.kind == "systemd" {
		return "etcd"
	}
	return r.kind
}

// snapshotSave is the command that takes a fresh snapshot afterwards.
func (r etcdRuntime) snapshotSave() string {
	switch r.kind {
	case "rke2", "k3s":
		return r.kind + " etcd-snapshot save"
	}
	return "etcdctl snapshot save /var/lib/etcd-backup/$(date +%F).db  (with --cacert/--cert/--key)"
}

// joinHint is how a replacement control-plane node is added.
func (r etcdRuntime) joinHint() string {
	switch r.kind {
	case "rke2", "k3s":
		return "join a fresh server (" + r.kind + " with server: pointing at a surviving node; it becomes a member automatically)"
	case "systemd":
		return "provision a new etcd node and add it with etcdctl member add before starting etcd on it"
	}
	return "kubeadm join --control-plane on a fresh node (it adds itself as an etcd member)"
}

// rejoinSteps rebuilds one member from scratch and adds it back to a cluster
// that still has a leader: `target` is a healthy member to run etcdctl on.
func (r etcdRuntime) rejoinSteps(node, ip, memberID, target string) []string {
	peer := "https://" + ip + ":2380"
	switch r.kind {
	case "rke2", "k3s":
		return []string{
			"On " + node + ": " + r.stop + "; mv " + r.dataDir + " " + r.dataDir + ".bak-$(date +%F); " + r.start,
			"It rejoins as a learner and syncs from the leader; verify with etcdctl endpoint status --cluster -w table",
		}
	case "systemd":
		return []string{
			"On " + node + ": " + r.stop + "; mv " + r.dataDir + " " + r.dataDir + ".bak-$(date +%F)",
			"On " + target + ": etcdctl member remove " + memberID + " (if still listed); etcdctl member add " + node + " --peer-urls=" + peer + "   - note the ETCD_INITIAL_CLUSTER it prints",
			"On " + node + ": set ETCD_INITIAL_CLUSTER=<that list> and ETCD_INITIAL_CLUSTER_STATE=existing in /etc/etcd.env; " + r.start,
			"Wait until etcdctl endpoint health --cluster shows " + node + " healthy before touching another node",
		}
	}
	return []string{
		"On " + node + ": " + r.stop + "; mv " + r.dataDir + " " + r.dataDir + ".bak-$(date +%F)",
		"On " + target + ": etcdctl member remove " + memberID + " (if still listed); etcdctl member add " + node + " --peer-urls=" + peer + "   - note the ETCD_INITIAL_CLUSTER it prints",
		"On " + node + ": in " + kubeadmParked + " set --initial-cluster=<that list> and --initial-cluster-state=existing; then " + r.start,
		"Wait until etcdctl endpoint health --cluster shows " + node + " healthy before touching another node",
	}
}

// resetSteps is the full quorum-recovery sequence starting from `target`, the
// node with the freshest data. Every other member is stopped first so nothing
// else tries to form a cluster while the target resets.
func (r etcdRuntime) resetSteps(target, targetIP, snapshot string, others []string) []string {
	peer := "https://" + targetIP + ":2380"
	otherList := strings.Join(others, ", ")
	if otherList == "" {
		otherList = "<every other control-plane node>"
	}
	switch r.kind {
	case "rke2", "k3s":
		return []string{
			"If quorum has not returned: on EVERY other server first (" + otherList + "): " + r.stop + "   (nothing else may be trying to form a cluster while " + target + " resets)",
			"Before resetting, on EVERY node including agents: server: in /etc/rancher/" + r.kind + "/config.yaml(.d) must be the VIP/DNS the cluster joins through and token: the cluster token (/var/lib/rancher/" + r.kind + "/server/token on a server) — a node pointed at one specific server or carrying another token will not rejoin. On " + target + " itself: cluster-reset refuses to run while server: is set (\"remove server from configuration before resetting\"): comment it out for the reset, keep token: (the snapshot's bootstrap data is encrypted with it), put server: back before the next restart",
			"Then on " + target + ": " + r.stop + "; " + r.kind + " server --cluster-reset   (keeps its local data, drops the other members; the command exits when done)",
			r.start + " on " + target + "; wait until kubectl get nodes answers",
			"On each of the other servers, one at a time: rm -rf " + r.dbDir() + "; " + r.start + "   (they rejoin and resync from " + target + ")",
			"Only if " + target + "'s data dir is damaged (container log shows wal/snap corruption): " + r.kind + " server --cluster-reset --cluster-reset-restore-path=" + snapshot + " in the reset step instead; the rest is the same",
		}
	case "systemd":
		return []string{
			"If quorum has not returned: on EVERY other etcd node first (" + otherList + "): " + r.stop + "   (nothing else may be trying to form a cluster while " + target + " resets)",
			"Then on " + target + ": " + r.stop + "; add ETCD_FORCE_NEW_CLUSTER=true to /etc/etcd.env (or --force-new-cluster to ExecStart); " + r.start + "   (etcd comes up as a one-member cluster with its local data)",
			"On " + target + ": once etcdctl member list shows only " + target + " and kubectl get nodes answers, remove ETCD_FORCE_NEW_CLUSTER again and " + r.restart + "   (leaving it in would reset membership on every restart)",
			"On each other node, one at a time: mv " + r.dataDir + " " + r.dataDir + ".bak-$(date +%F); on " + target + ": etcdctl member add <node> --peer-urls=https://<node ip>:2380; on the node set ETCD_INITIAL_CLUSTER=<printed list> and ETCD_INITIAL_CLUSTER_STATE=existing in /etc/etcd.env; " + r.start + "; wait until etcdctl endpoint health --cluster shows it healthy",
			"Only if " + target + "'s data dir is damaged: etcdutl snapshot restore " + snapshot + " --data-dir " + r.dataDir + " --name " + target + " --initial-cluster " + target + "=" + peer + " --initial-advertise-peer-urls " + peer + "   (etcdctl snapshot restore on etcd < 3.5) after moving the old dir aside, and start etcd WITHOUT force-new-cluster; the rejoin of the others is the same",
		}
	}
	return []string{
		"If quorum has not returned: on EVERY other control-plane node first (" + otherList + "): " + r.stop,
		"Then on " + target + ": mv " + kubeadmManifest + " " + kubeadmParked + "; add '- --force-new-cluster' to the etcd container args in " + kubeadmParked + "; mv it back to " + kubeadmManifest + "   (etcd restarts as a one-member cluster with its local data)",
		"On " + target + ": once etcdctl member list shows only " + target + " and kubectl get nodes answers, move the manifest out again, remove --force-new-cluster, move it back   (leaving the flag in would reset membership on every restart)",
		"On each other node, one at a time: mv " + r.dataDir + " " + r.dataDir + ".bak-$(date +%F); on " + target + ": etcdctl member add <node> --peer-urls=https://<node ip>:2380; in that node's " + kubeadmParked + " set --initial-cluster=<printed list> and --initial-cluster-state=existing; mv it back to " + kubeadmManifest + "; wait until etcdctl endpoint health --cluster shows it healthy",
		"Only if " + target + "'s data dir is damaged: etcdutl snapshot restore " + snapshot + " --data-dir " + r.dataDir + " --name " + target + " --initial-cluster " + target + "=" + peer + " --initial-advertise-peer-urls " + peer + "   (etcdctl snapshot restore on etcd < 3.5) after moving the old dir aside; then start the manifest WITHOUT --force-new-cluster; the rejoin of the others is the same",
	}
}

// nodeIP is the address used in peer URLs for a node: the Node's InternalIP,
// else the member's peer URL host, else the SSH address.
func nodeIP(in Input, t *etcdTriage) string {
	if in.Snap != nil {
		for i := range in.Snap.Nodes {
			n := &in.Snap.Nodes[i]
			if n.Name != t.node {
				continue
			}
			for _, a := range n.Status.Addresses {
				if a.Type == corev1.NodeInternalIP && a.Address != "" {
					return a.Address
				}
			}
		}
	}
	if t.member != nil {
		for _, u := range t.member.PeerURLs {
			if h := urlHost(u); h != "" {
				return h
			}
		}
	}
	if t.info != nil && t.info.Host != "" {
		return t.info.Host
	}
	return "<" + t.node + " ip>"
}
