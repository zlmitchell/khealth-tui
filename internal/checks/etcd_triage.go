package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// raftLagWarn is how many raft entries a healthy member may trail the leader
// before it is reported (endpoint status is not taken atomically across
// members, so a small difference is normal).
const raftLagWarn = 1000

// etcdTriage is what triageEtcd knows about one etcd node / member.
type etcdTriage struct {
	node    string
	member  *etcd.Member
	status  *etcd.EndpointStatus
	healthy bool
	known   bool   // health is known (endpoint health or /health probe)
	reason  string // health error text
	ready   bool   // Node Ready condition
	sshOK   bool
	sshErr  string
	info    *nodeinfo.Info
	probe   *etcd.Probe
	pod     *corev1.Pod
	logs    map[string]int // journal pattern counts
}

// etcdQuorum summarizes the cluster-wide picture for the steps text.
type etcdQuorum struct {
	total, healthy int
	haveMembers    bool // a member list exists (else total is the node count)
	leader         string
	term           uint64
	leaderIndex    uint64
	lost           bool
}

func (q etcdQuorum) String() string {
	if q.total == 0 {
		return "quorum: unknown (no member list)"
	}
	need := q.total/2 + 1
	s := fmt.Sprintf("quorum: %d/%d members healthy (need %d)", q.healthy, q.total, need)
	if q.lost {
		s = fmt.Sprintf("QUORUM LOST: %d/%d members healthy, need %d - the apiserver cannot write until quorum is back", q.healthy, q.total, need)
	} else if q.leader != "" {
		s += fmt.Sprintf(", leader %s term %d", q.leader, q.term)
	} else {
		s += ", no leader reported"
	}
	return s
}

// triageEtcd correlates etcd member health with node reachability, service
// state, container state and journal patterns, and emits one finding per
// problem member with the ordered steps to fix it. It returns the node and
// member names it reported so the generic per-endpoint checks skip them.
func triageEtcd(in Input, add func(Finding)) map[string]bool {
	covered := map[string]bool{}
	s := in.Snap
	if s == nil {
		return covered
	}
	src := etcdMembershipSource(in)

	var etcdNodes []*corev1.Node
	for i := range s.Nodes {
		if k8s.IsEtcdNode(s.Nodes, &s.Nodes[i]) {
			etcdNodes = append(etcdNodes, &s.Nodes[i])
		}
	}
	apiDown := len(s.Nodes) == 0
	if len(etcdNodes) == 0 && src == nil && !apiDown {
		return covered
	}

	// index the cluster-wide probe
	healthByEP := map[string]etcd.EndpointHealth{}
	statusByID := map[string]*etcd.EndpointStatus{}
	var members []etcd.Member
	if src != nil {
		members = src.Members
		for _, h := range src.EndpointHealth {
			healthByEP[h.Endpoint] = h
		}
		for i := range src.Statuses {
			if src.Statuses[i].MemberID != "" {
				statusByID[src.Statuses[i].MemberID] = &src.Statuses[i]
			}
		}
	}

	// build one triage record per etcd node; with the apiserver down the SSH
	// probes that found an etcd layout are the node list
	var recs []*etcdTriage
	matched := map[string]bool{} // member IDs that map to a node
	if apiDown {
		for _, name := range strutil.SortedKeys(in.Etcd) {
			p := in.Etcd[name]
			if p == nil || p.Err != nil || p.Dist == "unknown" {
				continue
			}
			etcdNodes = append(etcdNodes, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}})
		}
	}
	for _, n := range etcdNodes {
		t := &etcdTriage{node: n.Name, info: in.Nodes[n.Name], probe: in.Etcd[n.Name], pod: etcdPodOn(s, n.Name)}
		st, _ := k8s.NodeCondition(n, corev1.NodeReady)
		t.ready = st == corev1.ConditionTrue || apiDown // no API: do not blame readiness
		if t.info != nil {
			t.sshOK = t.info.Err == nil
			if t.info.Err != nil {
				t.sshErr = strutil.FirstLine(t.info.Err.Error())
			}
		}
		if lg := in.Logs[n.Name]; lg != nil {
			t.logs = lg.ByName
		}
		if m := memberForNode(members, n); m != nil {
			t.member = m
			matched[m.ID] = true
			t.status = statusByID[m.ID]
			for _, u := range m.ClientURLs {
				if h, ok := healthByEP[u]; ok {
					t.known, t.healthy, t.reason = true, h.Healthy, strutil.FirstLine(h.Error)
					break
				}
			}
		}
		// SSH /health on the node itself is the fallback signal
		if !t.known && t.probe != nil && t.probe.Err == nil && t.probe.Health != nil {
			t.known, t.healthy, t.reason = true, t.probe.Health.Healthy, strutil.FirstLine(t.probe.Health.Reason)
		}
		// a status error (e.g. context deadline exceeded) also means unhealthy
		if t.status != nil && len(t.status.Errors) > 0 && (!t.known || t.healthy) {
			t.known, t.healthy, t.reason = true, false, strutil.FirstLine(t.status.Errors[0])
		}
		// an endpoint status the member answered (raft term, db size, no
		// error) is proof it serves, even when no /health line matched its
		// client URL (the exec probe asks 127.0.0.1, the member advertises
		// its node address)
		if !t.known && t.status != nil && len(t.status.Errors) == 0 && (t.status.RaftTerm > 0 || t.status.MemberID != "") {
			t.known, t.healthy = true, true
		}
		recs = append(recs, t)
	}

	q := etcdQuorumOf(recs, members, statusByID)
	// "lost" needs evidence: members known unhealthy, or fewer healthy than
	// a majority. Members whose health nobody could read (no SSH, no exec)
	// are unknown, not down - the apiserver answering says as much.
	known := 0
	for _, t := range recs {
		if t.known {
			known++
		}
	}
	if known == 0 && !apiDown {
		q.lost = false
	}
	if q.lost || (known > 0 && q.healthy == 0) {
		add(triageClusterDown(in, recs, members, q))
		for _, t := range recs { // the cluster finding speaks for every member
			covered[t.node] = true
			if t.member != nil {
				covered[t.member.Name] = true
			}
		}
	}

	for _, t := range recs {
		if f, ok := triageOne(in, t, q); ok {
			covered[t.node] = true
			if t.member != nil {
				covered[t.member.Name] = true
			}
			add(f)
		}
	}

	// members with no node behind them
	for i := range members {
		m := &members[i]
		if matched[m.ID] {
			continue
		}
		covered[m.Name] = true
		add(Finding{Severity: SevWarn, Area: "etcd", Object: m.Name,
			Message: fmt.Sprintf("stale member %s (%s): no cluster node matches it", m.Name, m.ID),
			Hint:    "etcdctl member remove " + m.ID,
			Steps: []string{
				"Confirm: etcdctl member list -w table, and kubectl get nodes - the member's peer URL " + strings.Join(m.PeerURLs, ",") + " belongs to no node",
				"A stale member counts toward quorum: with it present, one more real failure can take the cluster down",
				"Remove it on a healthy member: etcdctl member remove " + m.ID,
				"rke2: if the node was removed with kubectl delete node while rke2-server was down, also clear the etcd node annotation before re-adding a node with that name",
				q.String(),
			}})
	}
	return covered
}

// nodeRank is the on-disk evidence used to pick the node to reset from.
type nodeRank struct {
	node        string
	memberID    string
	leaderTerm  uint64    // highest term at which this node was elected leader
	leaderAt    time.Time // when
	snapTerm    uint64
	snapIndex   uint64
	walIndex    uint64
	walWrite    time.Time
	lastElected string // the leader this node's log last saw
	lastTerm    uint64
}

// rankEtcdNodes orders nodes by freshest raft state: the last leader (highest
// term at which the node's own id was elected) first, then on-disk snapshot
// term/index, then WAL activity. Leader ids in the logs are mapped to nodes
// through each node's local-member-id, or the member list when there is one.
func rankEtcdNodes(recs []*etcdTriage, members []etcd.Member) []nodeRank {
	idToNode := map[string]string{}
	for _, t := range recs {
		if t.probe != nil && t.probe.LocalMemberID != "" {
			idToNode[t.probe.LocalMemberID] = t.node
		}
		if t.member != nil {
			idToNode[t.member.ID] = t.node
		}
	}
	byNode := map[string]*nodeRank{}
	var order []string
	for _, t := range recs {
		r := &nodeRank{node: t.node}
		if t.probe != nil {
			r.memberID = t.probe.LocalMemberID
			if t.probe.Raft != nil {
				r.snapTerm, r.snapIndex, r.walIndex, r.walWrite = t.probe.Raft.SnapTerm, t.probe.Raft.SnapIndex, t.probe.Raft.WALIndex, t.probe.Raft.WALLastWrite
			}
			if ev, ok := t.probe.LastLeader(); ok {
				r.lastElected, r.lastTerm = ev.Leader, ev.Term
			}
		}
		if r.memberID == "" && t.member != nil {
			r.memberID = t.member.ID
		}
		byNode[t.node] = r
		order = append(order, t.node)
	}
	// every node's log is evidence about who led at which term
	for _, t := range recs {
		if t.probe == nil {
			continue
		}
		for _, ev := range t.probe.LeaderEvents {
			n, ok := idToNode[ev.Leader]
			if !ok {
				continue
			}
			r := byNode[n]
			if ev.Term > r.leaderTerm || (ev.Term == r.leaderTerm && ev.Time.After(r.leaderAt)) {
				r.leaderTerm, r.leaderAt = ev.Term, ev.Time
			}
		}
	}
	out := make([]nodeRank, 0, len(order))
	for _, n := range order {
		out = append(out, *byNode[n])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.leaderTerm != b.leaderTerm {
			return a.leaderTerm > b.leaderTerm
		}
		if a.snapTerm != b.snapTerm {
			return a.snapTerm > b.snapTerm
		}
		if a.snapIndex != b.snapIndex {
			return a.snapIndex > b.snapIndex
		}
		if a.walIndex != b.walIndex {
			return a.walIndex > b.walIndex
		}
		return a.walWrite.After(b.walWrite)
	})
	return out
}

func (r nodeRank) String(now time.Time) string {
	var parts []string
	if r.leaderTerm > 0 {
		s := fmt.Sprintf("leader at term %d", r.leaderTerm)
		if !r.leaderAt.IsZero() {
			s += " (elected " + r.leaderAt.UTC().Format("2006-01-02 15:04 UTC") + ")"
		}
		parts = append(parts, s)
	} else {
		parts = append(parts, "never seen as leader in the logs collected")
	}
	if r.snapTerm > 0 || r.snapIndex > 0 {
		parts = append(parts, fmt.Sprintf("snapshot term %d index %d", r.snapTerm, r.snapIndex))
	}
	if r.walIndex > 0 {
		parts = append(parts, fmt.Sprintf("WAL from index %d", r.walIndex))
	}
	if !r.walWrite.IsZero() {
		parts = append(parts, "last WAL write "+strutil.HumanDur(now.Sub(r.walWrite))+" ago")
	}
	if r.memberID != "" {
		parts = append(parts, "id "+r.memberID)
	}
	return r.node + ": " + strings.Join(parts, ", ")
}

// triageClusterDown is the finding for a lost quorum: which node to start the
// recovery from, and the exact sequence for that node's etcd runtime.
func triageClusterDown(in Input, recs []*etcdTriage, members []etcd.Member, q etcdQuorum) Finding {
	ranked := rankEtcdNodes(recs, members)
	f := Finding{Severity: SevCrit, Area: "etcd", Object: "cluster"}
	f.Message = fmt.Sprintf("etcd quorum lost: %d/%d members healthy", q.healthy, q.total)
	var best *nodeRank
	if len(ranked) > 0 && (ranked[0].leaderTerm > 0 || ranked[0].snapTerm > 0 || ranked[0].walIndex > 0) {
		best = &ranked[0]
	}
	// the runtime of the target node decides the commands
	var targetRec *etcdTriage
	for _, t := range recs {
		if best != nil && t.node == best.node {
			targetRec = t
		}
	}
	if targetRec == nil && len(recs) > 0 {
		targetRec = recs[0]
	}
	rt := runtimeFor(targetRec, clusterDist(in))
	if best != nil && best.leaderTerm > 0 {
		f.Message += fmt.Sprintf("; last known leader %s (term %d)", best.node, best.leaderTerm)
		f.Hint = "if it does not recover on its own, " + rt.resetName() + " from " + best.node
	} else {
		f.Hint = "no leader history found on any node yet (needs ssh); see steps"
	}
	f.Steps = []string{
		"First: get every control-plane host powered on and " + rt.svc + " running, then wait ~5 minutes. With all members' data intact etcd re-elects a leader by itself; nothing below is needed while hosts are still booting",
		"Do NOT run " + rt.resetName() + " on more than one node, and not while other members are still coming up: it makes that node's data the only truth",
	}
	if len(ranked) > 0 {
		f.Steps = append(f.Steps, "Nodes ranked by freshest data (highest election term, then on-disk raft snapshot/WAL):")
		for i, r := range ranked {
			f.Steps = append(f.Steps, fmt.Sprintf("   %d. %s", i+1, r.String(in.Now)))
		}
		for _, r := range ranked {
			if best != nil && r.lastTerm > 0 && r.lastTerm < best.leaderTerm {
				f.Steps = append(f.Steps, fmt.Sprintf("   note: %s's log stops at term %d (it went down before %s's last election), so it is behind", r.node, r.lastTerm, best.node))
			}
		}
	}
	target, targetIP := "<the node ranked first above>", "<its ip>"
	var others []string
	if best != nil {
		target = best.node
		if targetRec != nil {
			targetIP = nodeIP(in, targetRec)
		}
		for _, t := range recs {
			if t.node != target {
				others = append(others, t.node+" ("+nodeIP(in, t)+")")
			}
		}
	}
	f.Steps = append(f.Steps, rt.resetSteps(target, targetIP, latestSnapshotPath(in, recs), others)...)
	f.Steps = append(f.Steps, "Afterward: etcdctl endpoint status --cluster -w table must show one leader and matching raft indexes; take a fresh snapshot: "+rt.snapshotSave())
	return f
}

// clusterDist is the distribution the API reported, defaulting to kubeadm
// semantics (static pod) when unknown.
func clusterDist(in Input) string {
	if in.Snap != nil {
		switch in.Snap.Distribution {
		case "rke2", "k3s", "kubeadm":
			return in.Snap.Distribution
		}
	}
	return "kubeadm"
}

// latestSnapshotPath picks the newest snapshot file the probes found on disk,
// else the newest cluster record name.
func latestSnapshotPath(in Input, recs []*etcdTriage) string {
	var best etcd.SnapshotFile
	dir, node := "", ""
	for _, t := range recs {
		if t.probe == nil {
			continue
		}
		if f, d, ok := t.probe.LatestSnapshot(); ok && f.ModTime.After(best.ModTime) {
			best, dir, node = f, d, t.node
		}
	}
	if node != "" {
		return dir + "/" + best.Name + " (on " + node + ", " + strutil.HumanDur(in.Now.Sub(best.ModTime)) + " old)"
	}
	if in.Snap != nil {
		var latest *k8s.EtcdSnapshotRecord
		for i := range in.Snap.RKE2Snapshots {
			r := &in.Snap.RKE2Snapshots[i]
			if r.Status != "failed" && (latest == nil || r.Created.After(latest.Created)) {
				latest = r
			}
		}
		if latest != nil {
			return latest.Name + " (cluster record on " + latest.Node + ")"
		}
	}
	return "<snapshot file>"
}

// triageOne classifies one etcd node and returns its finding, if any.
func triageOne(in Input, t *etcdTriage, q etcdQuorum) (Finding, bool) {
	rt := runtimeFor(t, clusterDist(in))
	svc := rt.svc
	podState := ""
	if t.pod != nil {
		podState = k8s.PodStatus(t.pod)
	}
	var restarts int32
	var lastRestart time.Time
	if t.pod != nil {
		restarts, lastRestart = k8s.PodRestarts(t.pod)
	}
	crashLooping := podState == "CrashLoopBackOff" || (restarts > 0 && !lastRestart.IsZero() && in.Now.Sub(lastRestart) < time.Hour)
	// container evidence only means something where etcd is a container
	containerDown := rt.static && (crashLooping || (t.pod != nil && t.pod.Status.Phase != corev1.PodRunning) || (len(containersOf(t.info)) > 0 && !hasContainer(t.info, "etcd")))
	problem := (t.known && !t.healthy) || (t.member == nil && q.total > 0) || !t.ready || containerDown
	if !problem {
		return triageLag(t, q, rt)
	}

	f := Finding{Severity: SevCrit, Area: "etcd", Object: t.node}
	memberTxt := "not in the member list"
	if t.member != nil {
		memberTxt = "member " + t.member.Name
	}
	cause, causeSteps := etcdCause(in, t, rt)
	healthyPeer := q.leader
	if healthyPeer == "" {
		healthyPeer = "a healthy member"
	}

	switch {
	// ---- node offline: NotReady and unreachable over SSH ----
	case !t.ready && (t.sshErr != "" || (!in.SSHEnabled && !t.known) || (!in.SSHEnabled && !t.healthy)):
		f.Message = fmt.Sprintf("node offline: NotReady and unreachable (%s); %s", strutil.FirstNonEmpty(t.sshErr, "ssh off"), memberTxt)
		f.Hint = "check the host; the member rejoins on its own when the node is back"
		f.Steps = []string{
			q.String(),
			"Confirm the host is down: ping / console / hypervisor or cloud console; kubelet last reported " + nodeHeartbeat(in, t.node),
			"If it is only unreachable from here, verify ssh.user/key/address in the config - the node may be fine",
			"When the host comes back " + svc + " starts, the etcd member catches up from the leader automatically; verify with etcdctl endpoint health --cluster",
			"If the host is permanently gone: on " + healthyPeer + " etcdctl member remove " + memberID(t) + "; then kubectl delete node " + t.node + "; then " + rt.joinHint(),
		}
		if q.lost {
			f.Steps = append(f.Steps, "Quorum is lost: if the majority of hosts cannot be recovered, follow the cluster finding above (reset from the node with the freshest data, restore from "+latestSnapshotPath(in, []*etcdTriage{t})+" only if its data is damaged)")
		}
		return f, true

	// ---- host up, the unit that runs etcd is down ----
	case t.sshOK && !serviceActive(t.info, svc):
		f.Message = fmt.Sprintf("host up but %s is %s; %s", svc, serviceState(t.info, svc), memberTxt)
		f.Hint = "systemctl status " + svc + "; journalctl -u " + svc + " -n 200"
		f.Steps = []string{
			q.String(),
			"systemctl status " + svc + "; journalctl -u " + svc + " -n 200 --no-pager (the Logs tab has the classified tail)",
		}
		if cause != "" {
			f.Steps = append(f.Steps, "Journal points at: "+cause)
			f.Steps = append(f.Steps, causeSteps...)
		}
		f.Steps = append(f.Steps, "systemctl restart "+svc+"; then watch etcdctl endpoint health --cluster until "+t.node+" reports healthy")
		return f, true

	// ---- recovered: the container restarted within the hour but the member
	// serves now - worth a look at why, not an outage ----
	case t.sshOK && containerDown && t.known && t.healthy && t.ready && t.pod != nil && t.pod.Status.Phase == corev1.PodRunning && podState != "CrashLoopBackOff":
		f.Severity = SevWarn
		ago := ""
		if !lastRestart.IsZero() {
			ago = ", last " + strutil.HumanDur(in.Now.Sub(lastRestart)) + " ago"
		}
		f.Message = fmt.Sprintf("etcd container restarted %d time(s) in the last hour%s, %s is healthy now", restarts, ago, memberTxt)
		f.Hint = "crictl logs --previous on the etcd container shows what the last exit was"
		f.Steps = []string{q.String(), "Read the previous container's log: " + strings.ReplaceAll(rt.logs, "<node>", t.node)}
		if cause != "" {
			f.Steps = append(f.Steps, "Journal points at: "+cause)
		}
		f.Steps = append(f.Steps, "Nothing to do while it stays up; the restart count resets with the next pod recreation")
		return f, true

	// ---- unit up, etcd container not running / crash-looping (static pod runtimes) ----
	case t.sshOK && containerDown:
		state := podState
		if state == "" {
			state = "no etcd container in crictl ps"
		}
		f.Message = fmt.Sprintf("host and %s up but the etcd container is %s (%d restarts); %s", svc, state, restarts, memberTxt)
		f.Hint = "crictl ps -a --name etcd; crictl logs <id>"
		f.Steps = []string{
			q.String(),
			"Read the container's own log: " + strings.ReplaceAll(rt.logs, "<node>", t.node),
		}
		if cause != "" {
			f.Steps = append(f.Steps, "Journal points at: "+cause)
			f.Steps = append(f.Steps, causeSteps...)
		} else {
			f.Steps = append(f.Steps, "No known pattern in the journal yet: the container log will show the exit reason (data dir corruption, peer TLS, bind failure)")
		}
		if t.probe != nil && len(t.probe.Sources) == 0 {
			switch rt.kind {
			case "rke2", "k3s":
				f.Steps = append(f.Steps, "No etcd static-pod manifest found on the node: check disable-etcd / etcd-only role settings in /etc/rancher/"+rt.kind+"/config.yaml")
			default:
				f.Steps = append(f.Steps, "No "+kubeadmManifest+" on the node: kubelet has nothing to run; restore the manifest (kubeadm init phase etcd local, or copy from another control-plane node and fix the node-specific args)")
			}
		}
		return f, true

	// ---- everything is up but the member is unhealthy / not joined ----
	case t.known && !t.healthy, t.member == nil:
		if q.lost && cause == "" {
			// the cluster finding carries the recovery; a per-node entry
			// without a node-specific cause would only repeat it
			return f, false
		}
		what := "unhealthy"
		if t.member == nil && q.haveMembers {
			what = "running but not a cluster member"
		}
		f.Message = fmt.Sprintf("etcd on %s is %s: %s", t.node, what, strutil.FirstNonEmpty(t.reason, cause, "no error text"))
		f.Hint = strutil.FirstNonEmpty(cause, "check peer connectivity on 2380 and the member's log")
		f.Steps = []string{q.String()}
		if cause != "" {
			f.Steps = append(f.Steps, "Cause: "+cause)
			f.Steps = append(f.Steps, causeSteps...)
		} else {
			f.Steps = append(f.Steps,
				"From another member: nc -vz "+peerHost(t)+" 2380 and 2379 - firewall / security group between control-plane nodes is the usual cause",
				"On "+t.node+": "+strings.ReplaceAll(rt.logs, "<node>", t.node)+" for peer TLS or raft errors; check clock sync (etcd needs it)",
				"If the member never recovers, rebuild it:")
			f.Steps = append(f.Steps, rt.rejoinSteps(t.node, nodeIP(in, t), memberID(t), healthyPeer)...)
		}
		return f, true

	// ---- NotReady but reachable and etcd healthy: kubelet problem, not etcd ----
	case !t.ready:
		f.Severity = SevWarn
		f.Message = "node NotReady but its etcd member is healthy; kubelet/CNI problem rather than etcd"
		f.Hint = "see the node finding; etcd quorum is unaffected"
		units := "kubelet"
		if svc != "kubelet" {
			units = svc + " kubelet"
		}
		f.Steps = []string{q.String(), "systemctl status " + units + "; journalctl -u " + strings.ReplaceAll(units, " ", " -u ") + " -n 100 | grep -iE 'kubelet|cni'", "This member still votes and replicates - no etcd action needed"}
		return f, true
	}
	return f, false
}

// triageLag reports a healthy member that trails the leader or is a learner.
func triageLag(t *etcdTriage, q etcdQuorum, rt etcdRuntime) (Finding, bool) {
	if t.member == nil || t.status == nil {
		return Finding{}, false
	}
	if t.member.IsLearner {
		return Finding{Severity: SevInfo, Area: "etcd", Object: t.node,
			Message: "member " + t.member.Name + " is a learner (not voting)",
			Hint:    "promote once it has caught up",
			Steps: []string{
				q.String(),
				"A learner receives the log but does not vote; " + map[bool]string{true: "rke2/k3s promote it automatically", false: "etcd does not promote it by itself"}[rt.kind == "rke2" || rt.kind == "k3s"] + " once its raft index matches the leader",
				fmt.Sprintf("Current index %d vs leader %d - if this does not converge, check disk and network on %s", t.status.RaftIndex, q.leaderIndex, t.node),
				"Manual promotion: etcdctl member promote " + t.member.ID,
			}}, true
	}
	if q.leaderIndex > 0 && t.status.RaftIndex+raftLagWarn < q.leaderIndex {
		lag := q.leaderIndex - t.status.RaftIndex
		return Finding{Severity: SevWarn, Area: "etcd", Object: t.node,
			Message: fmt.Sprintf("member %s is %d raft entries behind the leader (index %d vs %d)", t.member.Name, lag, t.status.RaftIndex, q.leaderIndex),
			Hint:    "slow disk or network on this node",
			Steps: []string{
				q.String(),
				"Compare WAL fsync latency for " + t.node + " with the other members on this tab (etcd_disk_wal_fsync_duration); >10ms average is too slow",
				"Check peer RTT: ping between the control-plane nodes; etcd wants <10ms",
				"If the lag keeps growing the member will be snapshotted from the leader; if it never converges: etcdctl member remove " + t.member.ID + " then rejoin the node",
			}}, true
	}
	if q.term > 0 && t.status.RaftTerm != q.term {
		return Finding{Severity: SevWarn, Area: "etcd", Object: t.node,
			Message: fmt.Sprintf("member %s reports raft term %d while the leader is at %d", t.member.Name, t.status.RaftTerm, q.term),
			Hint:    "partitioned member still electing",
			Steps: []string{
				q.String(),
				"A different term means this member is not following the leader: check 2380 connectivity from it to every other member",
				"crictl logs $(crictl ps -q --name etcd) on " + t.node + " for 'became candidate' / 'lost leader' loops",
			}}, true
	}
	return Finding{}, false
}

// etcdCause maps journal patterns, probe facts and node facts to a human cause
// and the steps that fix it on this node's runtime.
func etcdCause(in Input, t *etcdTriage, rt etcdRuntime) (string, []string) {
	dd := rt.dataDir
	lg := t.logs
	has := func(name string) bool { return lg != nil && lg[name] > 0 }
	healthyPeer := "a healthy member"
	ip := nodeIP(in, t)
	switch {
	case has("cluster-id"):
		steps := []string{"On " + healthyPeer + ": etcdctl member list; if " + t.node + " is listed, etcdctl member remove " + memberID(t)}
		return "cluster ID mismatch - this node's etcd data belongs to a different cluster (reinstalled or restored node)",
			append(steps, rt.rejoinSteps(t.node, ip, memberID(t), healthyPeer)...)
	case has("etcd-nospace") || hasAlarm(t, "NOSPACE"):
		return "NOSPACE alarm - the database hit quota-backend-bytes; the cluster is read-only until cleared", []string{
			"rev=$(etcdctl endpoint status -w json | grep -o '\"revision\":[0-9]*' | head -1 | cut -d: -f2); etcdctl compact $rev",
			"etcdctl defrag --endpoints=<one member at a time>; wait for each to come back healthy (D on the etcd tab does exactly that)",
			"etcdctl alarm disarm; then raise the quota if the working set really is this big (" + quotaHint(rt) + ")",
		}
	case has("disk-full") || dataDirFull(t, in):
		return "data-dir filesystem full - etcd stops writing when the disk fills", []string{
			"Free space on the etcd filesystem: crictl rmi --prune; journalctl --vacuum-size=500M; prune old " + snapshotHint(t, rt),
			"Give etcd its own disk if it shares one with images/logs",
			rt.restart + " once space is back",
		}
	case has("etcd-user") || (t.info != nil && !t.info.EtcdUser && t.info.Settings != nil && strings.HasPrefix(t.info.Settings["profile"], "cis")):
		return "CIS profile requires an etcd user/group on the host and it is missing", []string{
			"useradd -r -c 'etcd user' -s /sbin/nologin -M etcd -U",
			"chown -R etcd:etcd " + dd,
			rt.restart,
		}
	case expiredEtcdCert(t, in.Now) != "":
		return "expired etcd certificate: " + expiredEtcdCert(t, in.Now), certRenewSteps(rt)
	case t.probe != nil && len(t.probe.Missing) > 0:
		return "expected etcd cert/tool paths are missing on the node: " + strings.Join(t.probe.Missing, ", "), []string{
			"ls -l " + strings.Join(t.probe.Missing, " "),
			"If the layout is non-standard set etcd.ca_cert/client_cert/client_key/endpoint in the config; if the files are really gone the TLS material must be regenerated: " + strings.Join(certRenewSteps(rt), "; "),
		}
	case has("port-in-use"):
		return "a required port is already in use (2379/2380)", []string{
			"ss -lntp | grep -E ':(2379|2380) ' to see who holds it; stop the stray process (a leftover etcd, a second " + rt.product() + " instance)",
			rt.restart,
		}
	case has("wait-etcd") || has("conn-refused-local"):
		return rt.svc + " is still waiting for the local etcd to listen on 2379 - the member is not coming up", []string{
			strings.ReplaceAll(rt.logs, "<node>", t.node) + " shows why it exits",
			"Typical: data dir permissions, peer TLS mismatch, unreachable peers on 2380, wrong --initial-cluster after an IP change",
		}
	case has("clock-skew"):
		return "clock skew - TLS handshakes between members fail when clocks drift", []string{
			"timedatectl; chronyc tracking on every control-plane node",
			"Fix NTP, then " + rt.restart,
		}
	}
	return "", nil
}

func quotaHint(rt etcdRuntime) string {
	switch rt.kind {
	case "rke2", "k3s":
		return "config.yaml: etcd-arg: [quota-backend-bytes=8589934592]"
	case "systemd":
		return "ETCD_QUOTA_BACKEND_BYTES=8589934592 in /etc/etcd.env"
	}
	return "--quota-backend-bytes=8589934592 in " + kubeadmManifest
}

func snapshotHint(t *etcdTriage, rt etcdRuntime) string {
	if t.probe != nil {
		for _, d := range t.probe.SnapshotDirs {
			return "snapshots in " + d.Path
		}
	}
	switch rt.kind {
	case "rke2", "k3s":
		return "snapshots in /var/lib/rancher/" + rt.kind + "/server/db/snapshots"
	}
	return "backups / snapshots (etcd.backup_dirs in the config lists where to look)"
}

func certRenewSteps(rt etcdRuntime) []string {
	switch rt.kind {
	case "rke2", "k3s":
		return []string{rt.stop + "; " + rt.kind + " certificate rotate; " + rt.start}
	case "systemd":
		return []string{"Regenerate the etcd certs with the tool that provisioned them (kubespray: the etcd cert playbook); then " + rt.restart}
	}
	return []string{"kubeadm certs renew etcd-server etcd-peer etcd-healthcheck-client apiserver-etcd-client", rt.restart + "; also restart kube-apiserver the same way so it picks up apiserver-etcd-client"}
}

// ---- helpers ----

// etcdMembershipSource returns the probe that holds the member list: the
// kubectl-exec probe when it worked, else the first SSH probe with members.
func etcdMembershipSource(in Input) *etcd.Probe {
	if x := in.EtcdExec; x != nil && x.Err == nil && len(x.Members) > 0 {
		return x
	}
	for _, n := range strutil.SortedKeys(in.Etcd) {
		if p := in.Etcd[n]; p != nil && p.Err == nil && len(p.Members) > 0 {
			return p
		}
	}
	return nil
}

func etcdQuorumOf(recs []*etcdTriage, members []etcd.Member, statusByID map[string]*etcd.EndpointStatus) etcdQuorum {
	q := etcdQuorum{total: len(members), haveMembers: len(members) > 0}
	if q.total == 0 {
		q.total = len(recs)
	}
	for _, t := range recs {
		if t.known && t.healthy {
			q.healthy++
		}
	}
	// members without a node count as members but never as healthy
	for i := range members {
		m := &members[i]
		st := statusByID[m.ID]
		if st == nil {
			continue
		}
		if st.Leader != "" && st.Leader == st.MemberID {
			q.leader, q.term, q.leaderIndex = m.Name, st.RaftTerm, st.RaftIndex
		}
	}
	if q.leader == "" {
		// no member claims leadership: take the leader id most statuses agree on
		votes := map[string]int{}
		for _, st := range statusByID {
			if st.Leader != "" {
				votes[st.Leader]++
			}
		}
		best := ""
		for id, n := range votes {
			if n > votes[best] {
				best = id
			}
		}
		for i := range members {
			if members[i].ID == best {
				q.leader = members[i].Name
			}
		}
	}
	q.lost = q.total > 0 && q.healthy < q.total/2+1
	return q
}

// memberForNode matches a member to a node by name (kubeadm: node name;
// rke2: "<node>-<hash>") or by the host in its peer/client URLs.
func memberForNode(members []etcd.Member, n *corev1.Node) *etcd.Member {
	for i := range members {
		m := &members[i]
		if m.Name == n.Name || strings.HasPrefix(m.Name, n.Name+"-") {
			return m
		}
	}
	addrs := map[string]bool{n.Name: true}
	for _, a := range n.Status.Addresses {
		addrs[a.Address] = true
	}
	for i := range members {
		m := &members[i]
		for _, u := range append(append([]string{}, m.PeerURLs...), m.ClientURLs...) {
			if addrs[strutil.URLHost(u)] {
				return m
			}
		}
	}
	return nil
}

// etcdPodOn finds the static etcd pod for a node (any phase).
func etcdPodOn(s *k8s.Snapshot, node string) *corev1.Pod {
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Namespace != "kube-system" || p.Spec.NodeName != node {
			continue
		}
		if p.Labels["component"] == "etcd" || p.Name == "etcd-"+node {
			return p
		}
	}
	return nil
}

func serviceActive(ni *nodeinfo.Info, name string) bool {
	if ni == nil {
		return true // unknown: do not blame the service
	}
	for _, s := range ni.Services {
		if s.Name == name {
			return s.Active == "active"
		}
	}
	return true
}

func serviceState(ni *nodeinfo.Info, name string) string {
	if ni != nil {
		for _, s := range ni.Services {
			if s.Name == name {
				return s.Active + "/" + s.Sub
			}
		}
	}
	return "unknown"
}

func containersOf(ni *nodeinfo.Info) []nodeinfo.Container {
	if ni == nil {
		return nil
	}
	return ni.Containers
}

func hasContainer(ni *nodeinfo.Info, name string) bool {
	for _, c := range containersOf(ni) {
		if c.Name == name {
			return true
		}
	}
	return false
}

func hasAlarm(t *etcdTriage, typ string) bool {
	if t.probe == nil {
		return false
	}
	for _, a := range t.probe.Alarms {
		if a.Type == typ {
			return true
		}
	}
	return false
}

func dataDirFull(t *etcdTriage, in Input) bool {
	return t.probe != nil && t.probe.DataDirFS != nil && t.probe.DataDirFS.UsePct >= in.Cfg.Thresholds.DiskCritPct
}

func expiredEtcdCert(t *etcdTriage, now time.Time) string {
	if t.info == nil {
		return ""
	}
	for _, c := range t.info.Certs {
		if strings.Contains(c.Path, "etcd") && !c.NotAfter.IsZero() && c.NotAfter.Before(now) {
			return c.Path + " (expired " + strutil.HumanDur(now.Sub(c.NotAfter)) + " ago)"
		}
	}
	return ""
}

func memberID(t *etcdTriage) string {
	if t.member != nil {
		return t.member.ID
	}
	return "<member-id from etcdctl member list>"
}

func peerHost(t *etcdTriage) string {
	if t.member != nil {
		for _, u := range t.member.PeerURLs {
			if h := strutil.URLHost(u); h != "" {
				return h
			}
		}
	}
	return "<" + t.node + " ip>"
}

func nodeHeartbeat(in Input, node string) string {
	if in.Snap == nil {
		return "unknown"
	}
	for i := range in.Snap.Nodes {
		n := &in.Snap.Nodes[i]
		if n.Name != node {
			continue
		}
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && !c.LastHeartbeatTime.IsZero() {
				return strutil.HumanDur(in.Now.Sub(c.LastHeartbeatTime.Time)) + " ago"
			}
		}
	}
	return "unknown"
}
