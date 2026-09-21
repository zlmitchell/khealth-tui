package rescue

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/sshrun/sshtest"
)

// fakeCluster is the etcd membership the fake nodes share.
type fakeCluster struct {
	mu           sync.Mutex
	kind         Kind
	members      []string // node names, in join order
	learner      string   // a member that joined but is not promoted yet
	pending      string   // kubeadm: registered with member add, not started
	polls        map[string]int
	log          []string
	nodes        map[string]*fakeNode
	resetGivesUp bool // the cluster-reset exits 0 without resetting membership
	restoreNoop  bool // the first restoring reset leaves the data dir untouched
	stalePeers   bool // the restored member keeps the old peers until a plain reset
	resets       int  // cluster-resets run
	plainReset   bool // a reset without a snapshot ran
	verifies     int
}

type fakeNode struct {
	name, ip  string
	hasServer bool
	role      string
	// state written by the scripts
	stopped, backedUp, reset, restored, started, apiUp bool
	dropIn                                             bool
	initialCluster                                     string
	preflightFail                                      bool
}

func (c *fakeCluster) note(f string, a ...any) {
	c.log = append(c.log, fmt.Sprintf(f, a...))
}

var placeholder = regexp.MustCompile(`__[A-Z_]+__`)

func varOf(script, name string) string {
	m := regexp.MustCompile(`(?m)(?:^|; )` + name + `='([^']*)'`).FindStringSubmatch(script)
	if m == nil {
		return ""
	}
	return m[1]
}

func (c *fakeCluster) handle(n *fakeNode) sshtest.Handler {
	return func(cmd, stdin string) (string, string, int) {
		if strings.HasPrefix(stdin, "id -u;") {
			return "0\n", "", 0
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if left := placeholder.FindAllString(stdin, -1); len(left) > 0 {
			return "", "unsubstituted placeholders: " + strings.Join(left, " "), 1
		}
		if !strings.Contains(stdin, "KIND='"+string(c.kind)+"'") {
			return "", "wrong KIND in script", 1
		}
		var out []string
		say := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
		switch {
		case strings.Contains(stdin, `say "preflight=ok"`):
			c.note("%s preflight", n.name)
			if n.preflightFail {
				return "hostname=" + n.name + "\nERROR: simulated preflight failure\n", "", 1
			}
			say("hostname=%s", n.name)
			say("svc_state=active")
			say("datadir=/var/lib/rancher/rke2/server/db/etcd")
			say("owner=etcd:etcd")
			say("mode=700")
			say("size_kb=1000")
			say("member=yes")
			say("mountpoint=no")
			say("avail_kb=99999")
			if c.kind == Kubeadm {
				say("rescue_dir=/var/lib/etcd-rescue-x")
				say("manifest=/etc/kubernetes/manifests/etcd.yaml")
				say("name=%s", n.name)
				say("peer=https://%s:2380", n.ip)
				say("image=registry.k8s.io/etcd:3.5.15-0")
				say("tool=ctr")
				say("api_endpoint=https://10.0.0.1:6443") // the controlPlaneEndpoint is cp-1
			} else {
				say("rescue_dir=/var/lib/rancher/rke2/server/etcd-rescue-x")
				say("bin=/usr/local/bin/rke2")
				if n.hasServer {
					say("config: server: https://10.0.0.1:9345")
				} else {
					say("config: cluster-init: true")
				}
				say("etcd_user=998")
			}
			role := "other"
			if strings.Contains(stdin, `"target" = target`) {
				role = "target"
				say("snapshot=%s", varOf(stdin, "SNAP"))
				say("snapshot_size=%d", 5<<20)
			}
			n.role = role
			say("preflight=ok")
		case strings.Contains(stdin, `say "stopped=ok"`):
			c.note("%s stop", n.name)
			n.stopped = true
			c.members = remove(c.members, n.name)
			say("svc_state=inactive")
			say("stopped=ok")
		case strings.Contains(stdin, `say "backup=ok"`):
			c.note("%s backup", n.name)
			if !n.stopped {
				return "", "backup while running", 1
			}
			if varOf(stdin, "RESCUE") == "" {
				return "", "no RESCUE dir passed", 1
			}
			n.backedUp = true
			say("owner=etcd:etcd")
			say("mode=700")
			say("backup=ok")
		case strings.Contains(stdin, "tail -n 25"):
			c.polls["reset"]++
			say("---LOG")
			say("time=x level=info msg=restoring")
			if c.polls["reset"] >= 2 {
				out = append([]string{"exit=0"}, out...)
				if c.resetGivesUp {
					say(`level=error msg="Shutdown request received: failed to wait for API server to become ready"`)
				} else {
					say("Managed etcd cluster membership has been reset, restart without --cluster-reset flag now")
				}
			}
		case strings.Contains(stdin, `say "verify=ok"`):
			c.verifies++
			if c.restoreNoop && c.verifies == 1 {
				say("restored=no /var/lib/rancher/rke2/server/db/etcd/member/snap/db is older than the reset (not rewritten)")
			} else {
				say("old_dirs=/var/lib/rancher/rke2/server/db/etcd-old-1 ")
				say("restored=yes")
			}
			say("verify=ok")
		case strings.Contains(stdin, `say "cni=ok"`):
			if n.role != "target" || !n.started {
				return "", "CNI restart on the wrong node or before the start", 1
			}
			c.note("%s cni restart", n.name)
			say("restarted pod/rke2-canal-x")
			say("cni_running=1/1")
			say("cni=ok")
		case strings.Contains(stdin, `say "member_remove=ok"`):
			peer := varOf(stdin, "PEER")
			for name, o := range c.nodes {
				if o.ip == peer {
					c.members = remove(c.members, name)
					c.note("%s member remove %s", n.name, name)
				}
			}
			say("member_remove=ok")
		case strings.Contains(stdin, `say "wiped=ok"`):
			c.note("%s wipe again", n.name)
			say("wiped=ok")
		case strings.Contains(stdin, "cluster-reset.exit"):
			c.note("%s cluster-reset %s", n.name, varOf(stdin, "SNAP"))
			c.resets++
			if varOf(stdin, "SNAP") == "" {
				if !strings.Contains(stdin, `[ "1" = 1 ] || die "$DD/server/db/reset-flag exists`) {
					return "", "a second reset must clear the reset-flag", 1
				}
				c.plainReset = true
				c.members = []string{n.name}
				say("started=ok")
				break
			}
			if !n.stopped || !n.backedUp || n.role != "target" {
				return "", "cluster-reset out of order", 1
			}
			for _, o := range c.nodes {
				if !o.stopped && !o.preflightFail {
					return "", o.name + " still running during cluster-reset", 1
				}
			}
			if !strings.Contains(stdin, "--etcd-s3=false") {
				return "", "local restore must pass --etcd-s3=false", 1
			}
			n.reset = true
			c.members = []string{n.name}
			say("started=ok")
		case strings.Contains(stdin, `say "restore=ok"`):
			c.note("%s restore %s", n.name, varOf(stdin, "SNAP"))
			if !n.stopped || !n.backedUp || varOf(stdin, "NAME") != n.name || !strings.Contains(varOf(stdin, "PEER"), n.ip) {
				return "", "restore out of order or wrong member identity", 1
			}
			n.restored = true
			c.members = []string{n.name}
			say("via=ctr")
			say("restore=ok")
		case strings.Contains(stdin, `say "perms=ok"`):
			if varOf(stdin, "OWNER") != "etcd:etcd" {
				return "", "owner not carried over: " + varOf(stdin, "OWNER"), 1
			}
			say("perms=ok")
		case strings.Contains(stdin, `say "member_add=ok"`):
			name := varOf(stdin, "NAME")
			c.note("%s member add %s", n.name, name)
			c.pending = name
			say("initial_cluster=%s=https://%s:2380,%s=https://%s:2380", n.name, n.ip, name, c.nodes[name].ip)
			say("member_add=ok")
		case strings.Contains(stdin, `say "patched=ok"`):
			n.initialCluster = varOf(stdin, "IC")
			if n.initialCluster == "" {
				return "", "empty initial cluster", 1
			}
			say("patched=ok")
		case strings.Contains(stdin, `say "started=ok"`):
			c.note("%s start", n.name)
			if n.role == "other" {
				if tg := targetOf(c); tg != "" && !c.nodes[tg].started {
					return "", "follower started before the target", 1
				}
				if c.kind == Kubeadm && n.initialCluster == "" {
					return "", "follower started without a patched manifest", 1
				}
				if tg := targetOf(c); c.kind != Kubeadm && tg != "" && varOf(stdin, "JOIN") != "https://"+c.nodes[tg].ip+":9345" {
					return "", "follower started without the target's join URL: " + varOf(stdin, "JOIN"), 1
				}
				if c.kind != Kubeadm && varOf(stdin, "JOIN") == "" {
					return "", "follower started without a join URL", 1
				}
			}
			if varOf(stdin, "JOIN") != "" {
				n.dropIn = true
			}
			n.started = true
			c.polls[n.name] = 0
			say("started=ok")
		case strings.Contains(stdin, `say "unpark=ok"`):
			n.apiUp = true
			c.note("%s unpark", n.name)
			say("unpark=ok")
		case strings.Contains(stdin, `say "cleanup=ok"`):
			n.dropIn = false
			say("cleanup=ok")
		case strings.Contains(stdin, `say "snapshot=ok"`):
			c.note("%s snapshot", n.name)
			say("snapshot=ok")
		case strings.Contains(stdin, "---MEMBERS"):
			// a started follower becomes a learner on its first poll and a
			// voting member on the next
			// rke2 promotes learners itself; kubeadm only when the poll asks (__PROMOTE__)
			promote := strings.Contains(stdin, "if [ \"1\" = 1 ]; then\n  for id in")
			for _, o := range c.nodes {
				if !o.started || o.role != "other" || (slices.Contains(c.members, o.name) && c.learner != o.name) {
					continue
				}
				c.polls[o.name]++
				if c.polls[o.name] == 1 {
					c.members = append(c.members, o.name)
					c.learner = o.name
				} else if c.kind != Kubeadm || promote {
					c.learner = ""
				}
			}
			say("svc_state=active")
			say("health={\"health\":\"true\"}")
			if c.stalePeers && !c.plainReset && n.role == "target" && !slices.Contains(c.members, "ghost-a") {
				c.members = append(c.members, "ghost-a", "ghost-b")
			}
			if strings.Contains(stdin, "if [ \"1\" = 1 ]; then\n  say \"readyz=") {
				if n.apiUp || c.kind != Kubeadm {
					say("readyz=200")
				} else {
					say("readyz=000")
				}
			}
			say("%s", c.json())
		default:
			return "", "unknown script:\n" + stdin, 1
		}
		return strings.Join(out, "\n") + "\n", "", 0
	}
}

func targetOf(c *fakeCluster) string {
	for _, n := range c.nodes {
		if n.role == "target" {
			return n.name
		}
	}
	return ""
}

func (c *fakeCluster) json() string {
	var ms, hs, ss []string
	for i, name := range c.members {
		n := c.nodes[name]
		if n == nil {
			n = &fakeNode{name: name, ip: "10.0.9." + fmt.Sprint(i)} // a stale peer the restore kept
		}
		learner := "false"
		if name == c.learner {
			learner = "true"
		}
		ms = append(ms, fmt.Sprintf(`{"ID":%d,"name":"%s","peerURLs":["https://%s:2380"],"clientURLs":["https://%s:2379"],"isLearner":%s}`, i+1, name, n.ip, n.ip, learner))
		hs = append(hs, fmt.Sprintf(`{"endpoint":"https://%s:2379","health":true,"took":"1ms"}`, n.ip))
		ss = append(ss, fmt.Sprintf(`{"Endpoint":"https://%s:2379","Status":{"header":{"member_id":%d},"leader":1,"raftIndex":10,"raftTerm":2,"version":"3.5.15","dbSize":1}}`, n.ip, i+1))
	}
	return "---MEMBERS\n{\"members\":[" + strings.Join(ms, ",") + "]}\n\n---HEALTH\n[" + strings.Join(hs, ",") + "]\n\n---STATUS\n[" + strings.Join(ss, ",") + "]\n\n---ALARMS\n{}\n\n---LOG\nsome log line\n"
}

func remove(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// cluster starts three fake servers and returns the plan pointing at them.
func cluster(t *testing.T, kind Kind, tweak func(c *fakeCluster)) (*fakeCluster, *Plan) {
	t.Helper()
	c := &fakeCluster{kind: kind, polls: map[string]int{}, nodes: map[string]*fakeNode{}}
	c.nodes["cp-1"] = &fakeNode{name: "cp-1", ip: "10.0.0.1"} // cluster-init node
	c.nodes["cp-2"] = &fakeNode{name: "cp-2", ip: "10.0.0.2", hasServer: true}
	c.nodes["cp-3"] = &fakeNode{name: "cp-3", ip: "10.0.0.3", hasServer: true}
	c.members = []string{"cp-1", "cp-2", "cp-3"}
	if tweak != nil {
		tweak(c)
	}
	var first *sshtest.Server
	hosts := map[string]string{}
	for _, name := range []string{"cp-1", "cp-2", "cp-3"} {
		srv := sshtest.New(t, c.handle(c.nodes[name]))
		if first == nil {
			first = srv
		} else {
			srv.AcceptKey(first.ClientPub)
		}
		hosts[name] = srv.Addr
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	r, err := sshrun.New(config.SSH{User: "root", Key: first.KeyPath, Timeout: 5 * time.Second, Concurrency: 4, Become: "auto", Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	node := func(name string) Node {
		return Node{Name: name, Host: hosts[name], IP: c.nodes[name].ip, DataDir: "/var/lib/rancher/rke2/server/db/etcd"}
	}
	snap := "/var/lib/rancher/rke2/server/db/snapshots/etcd-snapshot-cp-2-1700000000"
	if kind == Kubeadm {
		snap = "/var/lib/etcd-backup/2024-01-01.db"
		node = func(name string) Node { return Node{Name: name, Host: hosts[name], IP: c.nodes[name].ip} }
	}
	p := New(kind, node("cp-2"), []Node{node("cp-1"), node("cp-3")}, snap, false)
	p.PollInterval = 10 * time.Millisecond
	p.WaitTimeout = 5 * time.Second
	if err := p.Preflight(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return c, p
}

func run(t *testing.T, p *Plan) (Event, []Event) {
	t.Helper()
	ch := make(chan Event, 256)
	go p.Run(context.Background(), ch)
	var all []Event
	var last Event
	for ev := range ch {
		all = append(all, ev)
		last = ev
	}
	if !last.Done {
		t.Fatal("no final event")
	}
	return last, all
}

func TestRKE2Restore(t *testing.T) {
	c, p := cluster(t, RKE2, nil)
	if len(p.Warnings) == 0 || !strings.Contains(strings.Join(p.Warnings, "\n"), "cp-1 has no server:") {
		t.Errorf("warnings: %v", p.Warnings)
	}
	if p.JoinURL() != "https://10.0.0.2:9345" {
		t.Errorf("join url %s", p.JoinURL())
	}
	titles := func() []string {
		var out []string
		for _, s := range p.Steps() {
			out = append(out, s.Node+": "+s.Title)
		}
		return out
	}
	want := []string{
		"cp-1: Stop rke2-server", "cp-3: Stop rke2-server", "cp-2: Stop rke2-server",
		"cp-2: Move etcd data to /var/lib/rancher/rke2/server/etcd-rescue-x", "cp-1: Move etcd data to /var/lib/rancher/rke2/server/etcd-rescue-x", "cp-3: Move etcd data to /var/lib/rancher/rke2/server/etcd-rescue-x",
		"cp-2: Restore etcd-snapshot-cp-2-1700000000 and reset membership (cluster-reset), verify the data dir was replaced", "cp-2: Set data dir owner/mode", "cp-2: Start rke2-server", "cp-2: Wait for etcd and the apiserver (second cluster-reset if the member does not come up alone)", "cp-2: Restart the CNI agent (it drops the local pod routes while the apiserver comes up)",
		"cp-1: Rejoin: start rke2-server (join via https://10.0.0.2:9345)", "cp-2: Wait until cp-1 is a healthy member (2/3)", "cp-1: Remove the join drop-in", "cp-2: Check etcd status",
		"cp-3: Rejoin: start rke2-server (join via https://10.0.0.2:9345)", "cp-2: Wait until cp-3 is a healthy member (3/3)", "cp-3: Remove the join drop-in", "cp-2: Check etcd status",
		"cp-2: Verify the cluster", "cp-2: Take a fresh snapshot",
	}
	if got := titles(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("steps:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	last, all := run(t, p)
	if last.Err != nil {
		t.Fatalf("rescue failed: %v\n%s", last.Err, strings.Join(c.log, "\n"))
	}
	for _, s := range last.Steps {
		if s.State != Done {
			t.Errorf("step %q on %s: %s %s", s.Title, s.Node, s.State, s.Err)
		}
	}
	if len(all) < len(want)*2 {
		t.Errorf("only %d events", len(all))
	}
	if got := strings.Join(c.members, ","); got != "cp-2,cp-1,cp-3" {
		t.Errorf("members %s", got)
	}
	for _, n := range []string{"cp-1", "cp-3"} {
		if c.nodes[n].dropIn {
			t.Errorf("join drop-in left behind on %s", n)
		}
	}
	// followers were stopped before the target, target restarted first, then one by one
	order := strings.Join(c.log, "\n")
	for _, seq := range [][2]string{{"cp-1 stop", "cp-2 stop"}, {"cp-2 backup", "cp-2 cluster-reset"}, {"cp-2 start", "cp-2 cni restart"}, {"cp-2 cni restart", "cp-1 start"}, {"cp-1 start", "cp-3 start"}, {"cp-3 start", "cp-2 snapshot"}} {
		if strings.Index(order, seq[0]) > strings.Index(order, seq[1]) {
			t.Errorf("%q should precede %q:\n%s", seq[0], seq[1], order)
		}
	}
	notes := strings.Join(p.Notes, "\n")
	if !strings.Contains(notes, "cp-2: previous etcd data kept in /var/lib/rancher/rke2/server/etcd-rescue-x") || !strings.Contains(notes, "99-khealth-rescue.yaml on cp-1") {
		t.Errorf("notes: %s", notes)
	}
}

func TestKubeadmRestore(t *testing.T) {
	c, p := cluster(t, Kubeadm, nil)
	if p.Svc() != "kubelet (etcd + kube-apiserver static pods)" {
		t.Errorf("svc %s", p.Svc())
	}
	var titles []string
	for _, s := range p.Steps() {
		titles = append(titles, s.Node+": "+s.Title)
	}
	joined := strings.Join(titles, "|")
	for _, w := range []string{"cp-2: Restore 2024-01-01.db as a one-member cluster", "cp-2: Register cp-1 as a learner member", "cp-1: Patch the etcd manifest (--initial-cluster, state=existing)", "cp-2: Wait until cp-1 has synced and is promoted (2/3)", "cp-1: Start kube-apiserver, restart controllers and kubelet", "cp-2: Register cp-3 as a learner member"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing step %q in\n%s", w, strings.Join(titles, "\n"))
		}
	}
	if w := strings.Join(p.Warnings, " "); !strings.Contains(w, "the API endpoint of cp-2 is https://10.0.0.1:6443: cp-1, a follower that stays stopped until it rejoins") {
		t.Errorf("no endpoint warning in %q", w)
	}
	last, _ := run(t, p)
	if last.Err != nil {
		t.Fatalf("rescue failed: %v\n%s", last.Err, strings.Join(c.log, "\n"))
	}
	if got := strings.Join(c.members, ","); got != "cp-2,cp-1,cp-3" {
		t.Errorf("members %s", got)
	}
	if ic := c.nodes["cp-3"].initialCluster; !strings.Contains(ic, "cp-2=https://10.0.0.2:2380") || !strings.Contains(ic, "cp-3=https://10.0.0.3:2380") {
		t.Errorf("cp-3 initial cluster %q", ic)
	}
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		if !c.nodes[n].apiUp {
			t.Errorf("%s apiserver not brought back", n)
		}
	}
	// the CNI restart on the target waits for every apiserver: kube-proxy
	// there is pinned to the controlPlaneEndpoint and still maps the service
	// VIP to the stopped followers until they are back
	order := strings.Join(c.log, "\n")
	for _, seq := range [][2]string{{"cp-3 unpark", "cp-2 cni restart"}, {"cp-2 cni restart", "cp-2 snapshot"}} {
		if strings.Index(order, seq[0]) > strings.Index(order, seq[1]) {
			t.Errorf("%q should precede %q:\n%s", seq[0], seq[1], order)
		}
	}
}

func TestPreflightSkipsFollower(t *testing.T) {
	c, p := cluster(t, RKE2, func(c *fakeCluster) { c.nodes["cp-3"].preflightFail = true })
	if len(p.Skipped) != 1 || p.Skipped[0].Name != "cp-3" || len(p.Others) != 1 {
		t.Fatalf("skipped %v others %v", p.Skipped, p.Others)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "cp-3 failed its preflight and is left out: simulated preflight failure") {
		t.Errorf("warnings %v", p.Warnings)
	}
	last, _ := run(t, p)
	if last.Err != nil {
		t.Fatalf("rescue failed: %v\n%s", last.Err, strings.Join(c.log, "\n"))
	}
	if got := strings.Join(c.members, ","); got != "cp-2,cp-1" {
		t.Errorf("members %s", got)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "cp-3 was left out") {
		t.Errorf("notes %v", p.Notes)
	}
}

func TestPreflightTargetFails(t *testing.T) {
	c := &fakeCluster{kind: RKE2, polls: map[string]int{}, nodes: map[string]*fakeNode{}}
	c.nodes["cp-1"] = &fakeNode{name: "cp-1", ip: "10.0.0.1", preflightFail: true}
	srv := sshtest.New(t, c.handle(c.nodes["cp-1"]))
	t.Setenv("SSH_AUTH_SOCK", "")
	r, err := sshrun.New(config.SSH{User: "root", Key: srv.KeyPath, Timeout: 5 * time.Second, Concurrency: 2, Become: "auto", Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p := New(RKE2, Node{Name: "cp-1", Host: srv.Addr, IP: "10.0.0.1"}, nil, "/x.db", false)
	if err := p.Preflight(context.Background(), r); err == nil || !strings.Contains(err.Error(), "cp-1: simulated preflight failure") {
		t.Errorf("err %v", err)
	}
	// an unreachable target
	p = New(RKE2, Node{Name: "cp-1", Host: "127.0.0.1:1", IP: "10.0.0.1"}, nil, "/x.db", false)
	if err := p.Preflight(context.Background(), r); err == nil || !strings.Contains(err.Error(), "cp-1: ") {
		t.Errorf("err %v", err)
	}
	if err := New(RKE2, Node{Name: "cp-1", Host: srv.Addr}, nil, "/x.db", false).Preflight(context.Background(), r); err == nil || !strings.Contains(err.Error(), "no address known") {
		t.Errorf("err %v", err)
	}
}

func TestAbortAndFailure(t *testing.T) {
	c, p := cluster(t, RKE2, nil)
	p.Abort()
	last, _ := run(t, p)
	if last.Err == nil || !strings.Contains(last.Err.Error(), "aborted") {
		t.Errorf("err %v", last.Err)
	}
	for _, s := range last.Steps {
		if s.State != Skipped {
			t.Errorf("step %q %s", s.Title, s.State)
		}
	}
	if c.nodes["cp-1"].stopped {
		t.Error("abort before the first step still stopped a node")
	}

	// a script failure stops the run and skips the rest
	_, p = cluster(t, RKE2, nil)
	steps := p.Steps()
	p.steps[2].run = func(ctx context.Context, s *Step) error { return fmt.Errorf("boom") }
	last, _ = run(t, p)
	if last.Err == nil || !strings.Contains(last.Err.Error(), "step 3/"+fmt.Sprint(len(steps))+" failed on cp-2: Stop rke2-server: boom") {
		t.Errorf("err %v", last.Err)
	}
	if last.Steps[2].State != Failed || last.Steps[3].State != Skipped || last.Steps[0].State != Done {
		t.Errorf("states %v %v %v", last.Steps[0].State, last.Steps[2].State, last.Steps[3].State)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "state the failed step left it") {
		t.Errorf("notes %v", p.Notes)
	}
}

// rke2 exits 0 even when the reset gave up: only the membership message counts.
func TestResetGivesUp(t *testing.T) {
	c, p := cluster(t, RKE2, func(c *fakeCluster) { c.resetGivesUp = true })
	last, _ := run(t, p)
	if last.Err == nil || !strings.Contains(last.Err.Error(), "cluster-reset exited 0 without resetting membership: level=error msg=\"Shutdown request received") {
		t.Errorf("err %v", last.Err)
	}
	if c.nodes["cp-2"].started {
		t.Error("the target was started after a failed reset")
	}
	for i, s := range last.Steps {
		if strings.HasPrefix(s.Title, "Restore") && s.State != Failed {
			t.Errorf("step %d %s: %s", i, s.Title, s.State)
		}
	}
}

// Rejoin mode: quorum is fine, one server is broken - it is stopped, its
// data moved aside and it rejoins through a healthy member; nothing is
// restored and the healthy members are never touched.
func TestRejoinOne(t *testing.T) {
	for _, kind := range []Kind{RKE2, Kubeadm} {
		c := &fakeCluster{kind: kind, polls: map[string]int{}, nodes: map[string]*fakeNode{}}
		c.nodes["cp-1"] = &fakeNode{name: "cp-1", ip: "10.0.0.1"}
		c.nodes["cp-2"] = &fakeNode{name: "cp-2", ip: "10.0.0.2", hasServer: true, started: true, apiUp: true}
		c.nodes["cp-3"] = &fakeNode{name: "cp-3", ip: "10.0.0.3", hasServer: true, started: true, apiUp: true}
		c.members = []string{"cp-1", "cp-2", "cp-3"}
		var first *sshtest.Server
		hosts := map[string]string{}
		for _, name := range []string{"cp-1", "cp-2", "cp-3"} {
			srv := sshtest.New(t, c.handle(c.nodes[name]))
			if first == nil {
				first = srv
			} else {
				srv.AcceptKey(first.ClientPub)
			}
			hosts[name] = srv.Addr
		}
		t.Setenv("SSH_AUTH_SOCK", "")
		r, err := sshrun.New(config.SSH{User: "root", Key: first.KeyPath, Timeout: 5 * time.Second, Concurrency: 4, Become: "auto", Sudo: true})
		if err != nil {
			t.Fatal(err)
		}
		node := func(name string) Node { return Node{Name: name, Host: hosts[name], IP: c.nodes[name].ip} }
		p := NewRejoin(kind, node("cp-2"), node("cp-1"))
		p.PollInterval = 10 * time.Millisecond
		p.WaitTimeout = 5 * time.Second
		if err := p.Preflight(context.Background(), r); err != nil {
			t.Fatalf("%s preflight: %v", kind, err)
		}
		if p.members != 3 || !strings.Contains(strings.Join(p.Warnings, "\n"), "cp-2 sees 3 members") {
			t.Errorf("%s: members %d warnings %v", kind, p.members, p.Warnings)
		}
		var titles []string
		for _, st := range p.Steps() {
			titles = append(titles, st.Node+": "+st.Title)
		}
		joined := strings.Join(titles, "|")
		want := []string{"cp-1: Stop", "cp-1: Move etcd data", "cp-2: Verify the cluster"}
		if kind != Kubeadm {
			want = append(want, "cp-2: Remove the stale member entry for cp-1")
		}
		for _, w := range want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: missing %q in %v", kind, w, titles)
			}
		}
		if strings.Contains(joined, "cp-2: Stop") || strings.Contains(joined, "cp-3:") || strings.Contains(joined, "Restore") || strings.Contains(joined, "snapshot") {
			t.Errorf("%s: rejoin touches more than the broken node: %v", kind, titles)
		}
		last, _ := run(t, p)
		if last.Err != nil {
			t.Fatalf("%s rejoin failed: %v\n%s", kind, last.Err, strings.Join(c.log, "\n"))
		}
		if c.nodes["cp-2"].stopped || c.nodes["cp-3"].stopped || c.resets != 0 {
			t.Errorf("%s: healthy members were touched (stopped %v/%v, resets %d)", kind, c.nodes["cp-2"].stopped, c.nodes["cp-3"].stopped, c.resets)
		}
		if got := strings.Join(c.members, ","); got != "cp-2,cp-3,cp-1" {
			t.Errorf("%s: members %s", kind, got)
		}
		if c.nodes["cp-1"].dropIn {
			t.Errorf("%s: drop-in left behind", kind)
		}
		notes := strings.Join(p.Notes, "\n")
		if strings.Contains(notes, "cp-2: previous etcd data kept") || !strings.Contains(notes, "cp-1: previous etcd data kept") {
			t.Errorf("%s: notes %v", kind, p.Notes)
		}
		r.Close()
	}
}

// Rejoin refuses when the surviving members do not serve a cluster.
func TestRejoinNeedsQuorum(t *testing.T) {
	c, restore := cluster(t, RKE2, nil)
	c.members = nil // the anchor answers with no members and no leader
	p := NewRejoin(RKE2, restore.Target, restore.Others[0])
	p.PollInterval, p.WaitTimeout = 10*time.Millisecond, 5*time.Second
	err := p.Preflight(context.Background(), restore.runner)
	if err == nil || !strings.Contains(err.Error(), "does not serve a working cluster") || !strings.Contains(err.Error(), "restore a snapshot instead") {
		t.Errorf("err %v", err)
	}
}

// The restoring reset left the data dir untouched: it is moved aside and the
// restore runs once more before anything is started.
func TestRestoreNotReplaced(t *testing.T) {
	c, p := cluster(t, RKE2, func(c *fakeCluster) { c.restoreNoop = true })
	last, _ := run(t, p)
	if last.Err != nil {
		t.Fatalf("rescue failed: %v\n%s", last.Err, strings.Join(c.log, "\n"))
	}
	if c.resets != 2 || c.verifies != 2 || !strings.Contains(strings.Join(c.log, "\n"), "cp-2 wipe again") {
		t.Errorf("resets %d verifies %d log %v", c.resets, c.verifies, c.log)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "did not replace the data dir") {
		t.Errorf("notes %v", p.Notes)
	}
	if got := strings.Join(c.members, ","); got != "cp-2,cp-1,cp-3" {
		t.Errorf("members %s", got)
	}
}

// The restored member came up with the old peers still listed: a plain
// second cluster-reset before the followers rejoin.
func TestSecondReset(t *testing.T) {
	c, p := cluster(t, RKE2, func(c *fakeCluster) { c.stalePeers = true })
	last, _ := run(t, p)
	if last.Err != nil {
		t.Fatalf("rescue failed: %v\n%s", last.Err, strings.Join(c.log, "\n"))
	}
	if !c.plainReset || c.resets != 2 {
		t.Errorf("plain reset %v resets %d", c.plainReset, c.resets)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "second cluster-reset was needed on cp-2 (the member list still has 3 members") {
		t.Errorf("notes %v", p.Notes)
	}
	if got := strings.Join(c.members, ","); got != "cp-2,cp-1,cp-3" {
		t.Errorf("members %s", got)
	}
	// the stop before the second reset and the restart are visible in the step log
	for _, s := range last.Steps {
		if strings.HasPrefix(s.Title, "Wait for etcd and the apiserver") {
			l := strings.Join(s.Log, "\n")
			if !strings.Contains(l, "second cluster-reset needed") || !strings.Contains(l, "stopped=ok") || !strings.Contains(l, "perms=ok") {
				t.Errorf("wait step log: %s", l)
			}
		}
	}
}

func TestParseStatusReady(t *testing.T) {
	c := &fakeCluster{kind: RKE2, nodes: map[string]*fakeNode{"a": {name: "a", ip: "10.0.0.1"}, "b": {name: "b", ip: "10.0.0.2"}}, members: []string{"a", "b"}}
	out := "svc_state=active\nhealth={\"health\":\"true\"}\nreadyz=401\n" + c.json()
	st := ParseStatus("a", out)
	if st.Members != 2 || st.Healthy != 2 || st.Leader != "1" || st.Readyz != "401" || st.Svc != "active" {
		t.Errorf("%+v", st)
	}
	if ok, why := st.Ready(2, true, "10.0.0.2"); !ok {
		t.Errorf("not ready: %s", why)
	}
	if ok, why := st.Ready(3, false, ""); ok || why != "2/3 members" {
		t.Errorf("%v %s", ok, why)
	}
	if ok, why := st.Ready(2, false, "10.0.0.9"); ok || !strings.Contains(why, "no member with peer address") {
		t.Errorf("%v %s", ok, why)
	}
	c.learner = "b"
	st = ParseStatus("a", c.json())
	if ok, why := st.Ready(2, false, ""); ok || !strings.Contains(why, "learner") {
		t.Errorf("%v %s", ok, why)
	}
	st = ParseStatus("a", "svc_state=activating\nhealth=\n---MEMBERS\nno etcd container running\n")
	if ok, why := st.Ready(1, false, ""); ok || why != "no member list yet" {
		t.Errorf("%v %s", ok, why)
	}
	st = ParseStatus("a", "svc_state=active\nreadyz=000\n"+c.json())
	c.learner = ""
	st = ParseStatus("a", "svc_state=active\nreadyz=000\n"+c.json())
	if ok, why := st.Ready(2, true, ""); ok || !strings.Contains(why, "apiserver not answering") {
		t.Errorf("%v %s", ok, why)
	}
}

func TestRenderSanitises(t *testing.T) {
	p := New(RKE2, Node{Name: "cp-1", DataDir: "/data/rke2/server/db/etcd"}, nil, "/snap/x y;rm -rf /", false)
	if p.DD != "/data/rke2" {
		t.Errorf("DD %s", p.DD)
	}
	s := p.render("reset_rke2", p.Target, map[string]string{"SNAP": p.Snapshot})
	if !strings.Contains(s, "SNAP='/snap/xyrm-rf/'") || strings.Contains(s, "__") {
		t.Errorf("render: %s", s)
	}
	if !strings.Contains(s, "KIND='rke2'") || !strings.Contains(s, "DATADIR='/data/rke2/server/db/etcd'") || !strings.Contains(s, "DD='/data/rke2'") {
		t.Errorf("render vars: %s", s[:400])
	}
}
