// Package rescue restores an etcd snapshot onto an rke2 / k3s / kubeadm
// control plane over SSH, following each project's documented procedure:
//
//   - stop the control plane on every server (followers first, target last)
//   - move every node's etcd member data into a timestamped rescue
//     directory that khealth never deletes
//   - restore the snapshot on the target and reset membership to that node
//     (rke2/k3s: `<bin> server --cluster-reset --cluster-reset-restore-path`;
//     kubeadm: `etcdutl snapshot restore` as a one-member cluster)
//   - give the restored data dir its previous owner and a 0700 mode
//   - start the target, wait for etcd and the apiserver
//   - rejoin the other servers one at a time and verify the member list,
//     endpoint health and leader after each one
//   - take a fresh snapshot
//
// The UI builds a Plan, runs Preflight (read-only, fills the facts the
// confirmation shows), then Run in the background, receiving an Event per
// change of step state so it can show live progress.
package rescue

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/sshrun"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

//go:embed scripts/*.sh
var scripts embed.FS

// Runner runs a script on a node as root (satisfied by *sshrun.Runner).
type Runner interface {
	Run(ctx context.Context, host, script string) sshrun.Result
}

// Kind is the control-plane flavor; it decides every command.
type Kind string

const (
	RKE2    Kind = "rke2"
	K3s     Kind = "k3s"
	Kubeadm Kind = "kubeadm"
)

// Supported reports whether the rescue knows the distribution.
func Supported(dist string) (Kind, bool) {
	switch dist {
	case "rke2", "k3s", "kubeadm":
		return Kind(dist), true
	}
	return "", false
}

// Node is a control-plane node taking part in the rescue.
type Node struct {
	Name    string // Kubernetes node name
	Host    string // SSH address
	IP      string // address peers reach it on (peer URLs, join URL)
	DataDir string // etcd member data dir as the probe found it ("" = default)
	Facts   Facts  // what Preflight found
}

// Facts is what preflight.sh reported about a node.
type Facts struct {
	OK       bool
	Err      string
	Hostname string
	Bin      string
	SvcState string
	Owner    string // data dir owner user:group
	Mode     string
	SizeKB   int64
	AvailKB  int64
	Member   string // yes | no | missing
	Mount    bool
	Rescue   string // where the data goes
	Config   []string
	// rke2 / k3s
	HasServer   bool // config.yaml has server: (join URL)
	ClusterInit bool
	Profile     string
	S3          bool
	S3Secret    string
	EtcdUser    bool
	// kubeadm
	Manifest       string
	APIEndpoint    string // server: of admin.conf (the controlPlaneEndpoint, or this node)
	MemberName     string
	PeerURL        string
	Image          string
	InitialCluster string
	Tools          []string
	// target only
	Snapshot     string
	SnapshotSize int64
	SnapshotTime time.Time
}

// State of a step.
type State int

const (
	Pending State = iota
	Running
	Done
	Failed
	Skipped
)

func (s State) String() string {
	return [...]string{"pending", "running", "done", "failed", "skipped"}[s]
}

// Step is one unit of the plan, on one node.
type Step struct {
	Title    string
	Node     string
	State    State
	Log      []string // durable output (what the scripts printed)
	Live     []string // latest poll output, replaced every poll
	Err      string
	Started  time.Time
	Finished time.Time

	run func(ctx context.Context, s *Step) error
}

// Event is the plan's state after a change; Steps is a copy.
type Event struct {
	Steps   []Step
	Current int // index of the running step, -1 when none
	Done    bool
	Err     error
}

// Plan is one rescue: what to restore, where, and the steps to do it.
type Plan struct {
	Kind         Kind
	DD           string // rke2/k3s data-dir (/var/lib/rancher/rke2)
	Target       Node
	Others       []Node // rejoined in this order
	Snapshot     string // path on the target, or S3 object name
	S3           bool
	TakeSnapshot bool
	Stamp        string

	// PollInterval / WaitTimeout tune the wait loops (tests shorten them).
	PollInterval time.Duration
	WaitTimeout  time.Duration

	// Rejoin: instead of a restore, put one server (Others[0]) back into the
	// surviving cluster through Target (a healthy member): stop it, move its
	// etcd data aside, rejoin, verify. For the case "quorum is fine, this
	// one member is broken", where a restore would throw away everything
	// written since the snapshot.
	Rejoin  bool
	members int // rejoin: members the surviving cluster has (from the anchor)

	Warnings []string // from Preflight
	Skipped  []Node   // Others that failed preflight: neither stopped nor rejoined
	Notes    []string // what to know afterward (backup locations, drop-ins)

	runner Runner
	mu     sync.Mutex
	steps  []*Step
	abort  atomic.Bool
}

// New prepares a plan; Preflight must run before Run.
func New(kind Kind, target Node, others []Node, snapshot string, s3 bool) *Plan {
	p := &Plan{Kind: kind, Target: target, Others: others, Snapshot: snapshot, S3: s3, TakeSnapshot: true,
		Stamp: time.Now().UTC().Format("20060102-150405"), PollInterval: 4 * time.Second, WaitTimeout: 15 * time.Minute}
	switch kind {
	case RKE2, K3s:
		p.DD = "/var/lib/rancher/" + string(kind)
		if dd := target.DataDir; strings.HasSuffix(dd, "/server/db/etcd") {
			p.DD = strings.TrimSuffix(dd, "/server/db/etcd")
		}
	}
	return p
}

// NewRejoin prepares a plan that rejoins one broken server to the cluster
// that anchor (a healthy member) still serves. No snapshot is involved.
func NewRejoin(kind Kind, anchor, node Node) *Plan {
	p := New(kind, anchor, []Node{node}, "", false)
	p.Rejoin = true
	p.TakeSnapshot = false
	return p
}

// Svc is the unit the rescue stops and starts.
func (p *Plan) Svc() string {
	switch p.Kind {
	case RKE2:
		return "rke2-server"
	case K3s:
		return "k3s"
	}
	return "kubelet (etcd + kube-apiserver static pods)"
}

func (p *Plan) dataDir(n Node) string {
	if n.DataDir != "" {
		return n.DataDir
	}
	switch p.Kind {
	case RKE2, K3s:
		return p.DD + "/server/db/etcd"
	}
	return "/var/lib/etcd"
}

// JoinURL is the supervisor URL followers join through.
func (p *Plan) JoinURL() string {
	port := "9345"
	if p.Kind == K3s {
		port = "6443"
	}
	return "https://" + p.Target.IP + ":" + port
}

// render returns the common prelude plus the named script with every
// __KEY__ placeholder substituted (values sanitized to a safe character set).
func (p *Plan) render(name string, n Node, vars map[string]string) string {
	common, _ := scripts.ReadFile("scripts/common.sh")
	body, _ := scripts.ReadFile("scripts/" + name + ".sh")
	s := string(common) + string(body)
	all := map[string]string{
		"KIND": string(p.Kind), "DD": p.DD, "DATADIR": p.dataDir(n), "STAMP": p.Stamp, "RESCUE": n.Facts.Rescue, "IP": n.IP,
		"ROLE": "other", "SNAP": "", "S3": "0", "API": "0", "PROMOTE": "0", "JOIN": "", "OWNER": "",
		"NAME": "", "PEER": "", "IMAGE": "", "INITIAL_CLUSTER": "", "LOG": "", "EXIT": "", "DIR": "", "FORCE": "0", "SINCE": "0", "NODE": "",
	}
	for k, v := range vars {
		all[k] = v
	}
	for k, v := range all {
		s = strings.ReplaceAll(s, "__"+k+"__", etcd.Clean(v))
	}
	return s
}

// Steps returns a copy of the plan's steps (titles before Run, states after).
func (p *Plan) Steps() []Step {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.copySteps()
}

func (p *Plan) copySteps() []Step {
	out := make([]Step, len(p.steps))
	for i, s := range p.steps {
		c := *s
		c.Log = append([]string(nil), s.Log...)
		c.Live = append([]string(nil), s.Live...)
		c.run = nil
		out[i] = c
	}
	return out
}

// Abort asks Run to stop after the step in progress (a step is never
// interrupted half-way: a half-stopped or half-restored node is worse).
func (p *Plan) Abort() { p.abort.Store(true) }

// Aborting reports whether Abort was called.
func (p *Plan) Aborting() bool { return p.abort.Load() }

// ---------- preflight ----------

// Preflight runs the read-only checks on every node and builds the steps.
// A failing target is an error; a failing follower is skipped with a
// warning (it is neither stopped nor rejoined; Notes says what to do).
func (p *Plan) Preflight(ctx context.Context, r Runner) error {
	p.runner = r
	if p.Target.Host == "" {
		return fmt.Errorf("no SSH address for %s", p.Target.Name)
	}
	if p.Target.IP == "" {
		return fmt.Errorf("no address known for %s (needed for the peer / join URL)", p.Target.Name)
	}
	type res struct {
		i     int
		facts Facts
	}
	ch := make(chan res, len(p.Others)+1)
	targetRole := "target"
	if p.Rejoin {
		targetRole = "other" // the anchor: no snapshot to check
	}
	go func() { ch <- res{-1, p.preflightNode(ctx, p.Target, targetRole)} }()
	for i := range p.Others {
		go func(i int) { ch <- res{i, p.preflightNode(ctx, p.Others[i], "other")} }(i)
	}
	for range len(p.Others) + 1 {
		x := <-ch
		if x.i < 0 {
			p.Target.Facts = x.facts
		} else {
			p.Others[x.i].Facts = x.facts
		}
	}
	if !p.Target.Facts.OK {
		return fmt.Errorf("%s: %s", p.Target.Name, p.Target.Facts.Err)
	}
	if p.Rejoin {
		if len(p.Others) != 1 || !p.Others[0].Facts.OK {
			return fmt.Errorf("%s: %s", p.Others[0].Name, p.Others[0].Facts.Err)
		}
		// the surviving cluster must actually be serving: quorum and a leader
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		res := p.runner.Run(cctx, p.Target.Host, p.render("status", p.Target, nil))
		cancel()
		st := ParseStatus(p.Target.Name, res.Stdout)
		if st.Members == 0 || st.Leader == "" || st.Healthy == 0 {
			return fmt.Errorf("%s does not serve a working cluster (members %d, healthy %d, leader %q): the surviving members have no quorum - restore a snapshot instead", p.Target.Name, st.Members, st.Healthy, st.Leader)
		}
		p.members = st.Members
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s sees %d members, %d healthy, leader %s; %s rejoins through it and keeps that data (nothing is restored)", p.Target.Name, st.Members, st.Healthy, st.Leader, p.Others[0].Name))
		p.build()
		return nil
	}
	var keep []Node
	p.Skipped, p.Warnings = nil, nil
	for _, n := range p.Others {
		if n.Facts.OK {
			keep = append(keep, n)
		} else {
			p.Skipped = append(p.Skipped, n)
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s failed its preflight and is left out: %s. It is NOT stopped and NOT rejoined; if its %s is running it keeps an orphaned etcd until you stop it, move %s aside and start it again", n.Name, n.Facts.Err, p.Svc(), p.dataDir(n)))
		}
	}
	p.Others = keep
	p.Warnings = append(p.Warnings, p.assess()...)
	p.build()
	return nil
}

func (p *Plan) preflightNode(ctx context.Context, n Node, role string) Facts {
	f := Facts{}
	if n.Host == "" {
		f.Err = "no SSH address"
		return f
	}
	vars := map[string]string{"ROLE": role}
	if role == "target" {
		vars["SNAP"] = p.Snapshot
		if p.S3 {
			vars["S3"] = "1"
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res := p.runner.Run(cctx, n.Host, p.render("preflight", n, vars))
	f = parseFacts(res.Stdout)
	if !f.OK {
		if f.Err == "" {
			f.Err = "preflight did not complete"
			if res.Err != nil {
				f.Err = strutil.FirstLine(res.Err.Error())
				if s := strings.TrimSpace(res.Stderr); s != "" {
					f.Err += ": " + strutil.FirstLine(s)
				}
			}
		}
	}
	return f
}

func parseFacts(out string) Facts {
	f := Facts{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, "ERROR: ") {
			f.Err = strings.TrimPrefix(l, "ERROR: ")
			continue
		}
		if strings.HasPrefix(l, "config: ") {
			c := strings.TrimPrefix(l, "config: ")
			f.Config = append(f.Config, c)
			k, v, _ := strings.Cut(c, ":")
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.TrimSpace(k) {
			case "server":
				f.HasServer = v != ""
			case "cluster-init":
				f.ClusterInit = v == "true"
			case "profile":
				f.Profile = v
			case "etcd-s3":
				f.S3 = v == "true"
			case "etcd-s3-config-secret":
				f.S3Secret = v
			}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "hostname":
			f.Hostname = v
		case "bin":
			f.Bin = v
		case "svc_state":
			f.SvcState = v
		case "owner":
			f.Owner = v
		case "mode":
			f.Mode = v
		case "size_kb":
			f.SizeKB, _ = strconv.ParseInt(v, 10, 64)
		case "avail_kb":
			f.AvailKB, _ = strconv.ParseInt(v, 10, 64)
		case "member":
			f.Member = v
		case "mountpoint":
			f.Mount = v == "yes"
		case "rescue_dir":
			f.Rescue = v
		case "etcd_user":
			f.EtcdUser = v != "none" && v != ""
		case "manifest":
			f.Manifest = v
		case "api_endpoint":
			f.APIEndpoint = v
		case "name":
			f.MemberName = v
		case "peer":
			f.PeerURL = v
		case "image":
			f.Image = v
		case "initial_cluster":
			f.InitialCluster = v
		case "tool":
			f.Tools = append(f.Tools, v)
		case "snapshot":
			f.Snapshot = v
		case "snapshot_size":
			f.SnapshotSize, _ = strconv.ParseInt(v, 10, 64)
		case "snapshot_mtime":
			if t, err := strconv.ParseInt(v, 10, 64); err == nil && t > 0 {
				f.SnapshotTime = time.Unix(t, 0)
			}
		case "preflight":
			f.OK = v == "ok"
		}
	}
	return f
}

// assess turns the facts into the warnings the confirmation shows.
func (p *Plan) assess() []string {
	var w []string
	t := p.Target.Facts
	if p.S3 && t.S3Secret != "" {
		w = append(w, "the S3 settings live in secret "+t.S3Secret+", which the cluster-reset cannot read while the apiserver is down: put them in config.yaml (etcd-s3-* keys) or restore a local file")
	}
	if !p.S3 && t.SnapshotSize > 0 && t.SnapshotSize < 1024*1024 {
		w = append(w, fmt.Sprintf("the snapshot is only %d bytes: is it a complete etcd snapshot?", t.SnapshotSize))
	}
	if t.AvailKB > 0 && t.SizeKB > 0 && t.AvailKB < t.SizeKB {
		w = append(w, fmt.Sprintf("%s has %d MB free on the etcd filesystem, less than the current data (%d MB): the restore may run out of space", p.Target.Name, t.AvailKB/1024, t.SizeKB/1024))
	}
	if t.Member == "missing" || t.Member == "no" {
		w = append(w, p.Target.Name+" has no etcd member data on disk right now")
	}
	if p.Kind == Kubeadm {
		if t.MemberName == "" || t.PeerURL == "" {
			w = append(w, "the etcd manifest on "+p.Target.Name+" has no --name / --initial-advertise-peer-urls: the restore cannot name the member")
		}
		if len(t.Tools) == 0 {
			w = append(w, "no etcdutl/etcdctl/ctr/podman on "+p.Target.Name+": nothing can run 'snapshot restore' there (install etcdutl)")
		}
		if ep := strutil.URLHost(t.APIEndpoint); ep != "" && ep != p.Target.IP && ep != "127.0.0.1" && ep != "localhost" {
			who := "an address outside the control plane (a VIP or load balancer: it must route to " + p.Target.Name + " once its apiserver is back, or the target cannot reach the API until the endpoint node has rejoined)"
			for _, o := range p.Others {
				if o.IP == ep || strutil.URLHost(o.Facts.PeerURL) == ep {
					who = o.Name + ", a follower that stays stopped until it rejoins"
				}
			}
			w = append(w, fmt.Sprintf("the API endpoint of %s is %s: %s. kubectl, kube-proxy and the CNI pods on %s use it, so the CNI agent is restarted only after every follower is back, and left alone if the endpoint still does not answer", p.Target.Name, t.APIEndpoint, who, p.Target.Name))
		}
		for _, o := range p.Others {
			if o.Facts.MemberName == "" || o.Facts.PeerURL == "" {
				w = append(w, "the etcd manifest on "+o.Name+" has no --name / --initial-advertise-peer-urls: it cannot be re-added")
			}
		}
	}
	for _, o := range p.Others {
		if (p.Kind == RKE2 || p.Kind == K3s) && !o.Facts.HasServer {
			w = append(w, o.Name+" has no server: in its config (cluster-init node): without the temporary join drop-in it would found a new cluster")
		}
		if o.Facts.SvcState != "active" && o.Facts.SvcState != "" {
			w = append(w, fmt.Sprintf("%s: %s is %s", o.Name, p.Svc(), o.Facts.SvcState))
		}
	}
	if (p.Kind == RKE2 || p.Kind == K3s) && len(p.Others) > 0 {
		w = append(w, "each follower rejoins through "+p.JoinURL()+" (temporary config.yaml.d/99-khealth-rescue.yaml, removed once it is a member): its own server: may point at a server that is still stopped")
	}
	if len(p.Others) == 0 && len(p.Skipped) == 0 {
		w = append(w, "single-server cluster: the restore reboots the only control plane")
	}
	return w
}

// ---------- steps ----------

func (p *Plan) add(title string, n Node, run func(ctx context.Context, s *Step) error) *Step {
	s := &Step{Title: title, Node: n.Name, run: run}
	p.steps = append(p.steps, s)
	return s
}

func (p *Plan) build() {
	p.steps = nil
	svc := p.Svc()
	if p.Rejoin {
		o := p.Others[0]
		p.add("Stop "+svc, o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "stop", nil, 8*time.Minute, "stopped=ok")
			return err
		})
		p.add("Move etcd data to "+o.Facts.Rescue, o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "backup", nil, 5*time.Minute, "backup=ok")
			return err
		})
		// the stale member entry for this node has to go first: rke2 refuses
		// a join while a member of that name exists (kubeadm: member_add.sh
		// removes it itself), so the count ends where it started
		if p.Kind == RKE2 || p.Kind == K3s {
			p.add("Remove the stale member entry for "+o.Name, p.Target, func(ctx context.Context, s *Step) error {
				_, err := p.exec(ctx, s, p.Target, "member_remove", map[string]string{"PEER": o.IP}, 2*time.Minute, "member_remove=ok")
				return err
			})
		}
		p.rejoinSteps(p.Target, o, p.members, p.members)
		p.add("Verify the cluster", p.Target, func(ctx context.Context, s *Step) error {
			return p.waitStatus(ctx, s, p.Target, p.members, true, false, "")
		})
		return
	}
	for _, o := range p.Others {
		o := o
		p.add("Stop "+svc, o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "stop", nil, 8*time.Minute, "stopped=ok")
			return err
		})
	}
	t := p.Target
	p.add("Stop "+svc, t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "stop", nil, 8*time.Minute, "stopped=ok")
		return err
	})
	for _, n := range append([]Node{t}, p.Others...) {
		n := n
		p.add("Move etcd data to "+n.Facts.Rescue, n, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, n, "backup", nil, 5*time.Minute, "backup=ok")
			return err
		})
	}
	switch p.Kind {
	case RKE2, K3s:
		p.buildRKE2()
	default:
		p.buildKubeadm()
	}
	want := 1 + len(p.Others)
	p.add("Verify the cluster", t, func(ctx context.Context, s *Step) error {
		return p.waitStatus(ctx, s, t, want, true, false, "")
	})
	if p.TakeSnapshot {
		p.add("Take a fresh snapshot", t, func(ctx context.Context, s *Step) error {
			dir := p.Snapshot
			if i := strings.LastIndex(dir, "/"); i > 0 {
				dir = dir[:i]
			} else {
				dir = "/var/lib/etcd-backup"
			}
			_, err := p.exec(ctx, s, t, "snapshot", map[string]string{"DIR": dir}, 5*time.Minute, "snapshot=ok")
			return err
		})
	}
}

func (p *Plan) buildRKE2() {
	t := p.Target
	svc := p.Svc()
	snapLabel := p.Snapshot
	if i := strings.LastIndex(snapLabel, "/"); i >= 0 {
		snapLabel = snapLabel[i+1:]
	}
	p.add("Restore "+snapLabel+" and reset membership (cluster-reset), verify the data dir was replaced", t, func(ctx context.Context, s *Step) error {
		return p.restoreVerified(ctx, s, t)
	})
	p.add("Set data dir owner/mode", t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "perms", map[string]string{"OWNER": t.Facts.Owner}, 5*time.Minute, "perms=ok")
		return err
	})
	p.add("Start "+svc, t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "start", map[string]string{"ROLE": "target"}, 2*time.Minute, "started=ok")
		return err
	})
	p.add("Wait for etcd and the apiserver (second cluster-reset if the member does not come up alone)", t, func(ctx context.Context, s *Step) error {
		return p.targetUp(ctx, s, t)
	})
	p.add("Restart the CNI agent (it drops the local pod routes while the apiserver comes up)", t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "cni_restart", map[string]string{"NODE": t.Name}, 4*time.Minute, "cni=ok")
		return err
	})
	for i, o := range p.Others {
		p.rejoinSteps(t, o, i+2, 1+len(p.Others))
	}
}

// rejoinSteps adds the steps that bring one server back as a member of the
// cluster t serves, then verifies: rke2/k3s start it with a join drop-in
// (every follower joins through t: its own server: may point at a server
// that is still stopped, or be absent on the cluster-init node) and wait;
// kubeadm registers it as a learner, patches its manifest, starts etcd,
// promotes it once synced and brings its apiserver back. want is the
// member count once it is in, total the count at the end of the rescue.
func (p *Plan) rejoinSteps(t, o Node, want, total int) {
	switch p.Kind {
	case RKE2, K3s:
		join := p.JoinURL()
		p.add("Rejoin: start "+p.Svc()+" (join via "+join+")", o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "start", map[string]string{"JOIN": join, "ROLE": "other"}, 2*time.Minute, "started=ok")
			if err == nil {
				p.note("wrote " + p.confDir() + "/config.yaml.d/99-khealth-rescue.yaml on " + o.Name + " for the rejoin (removed again once it was a member)")
			}
			return err
		})
		p.add(fmt.Sprintf("Wait until %s is a healthy member (%d/%d)", o.Name, want, total), t, func(ctx context.Context, s *Step) error {
			return p.waitStatus(ctx, s, t, want, false, false, o.IP)
		})
		p.add("Remove the join drop-in", o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "join_cleanup", nil, time.Minute, "cleanup=ok")
			return err
		})
	default:
		var initialCluster string
		p.add("Register "+o.Name+" as a learner member", t, func(ctx context.Context, s *Step) error {
			out, err := p.exec(ctx, s, t, "member_add", map[string]string{"NAME": o.Facts.MemberName, "PEER": o.Facts.PeerURL}, 2*time.Minute, "member_add=ok")
			if err != nil {
				return err
			}
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "initial_cluster=") {
					initialCluster = strings.TrimSpace(strings.TrimPrefix(l, "initial_cluster="))
				}
			}
			if initialCluster == "" {
				return fmt.Errorf("member add printed no initial cluster list")
			}
			return nil
		})
		p.add("Patch the etcd manifest (--initial-cluster, state=existing)", o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "patch_manifest", map[string]string{"INITIAL_CLUSTER": initialCluster}, 2*time.Minute, "patched=ok")
			return err
		})
		p.add("Start etcd (static pod)", o, func(ctx context.Context, s *Step) error {
			_, err := p.exec(ctx, s, o, "start", map[string]string{"ROLE": "other"}, 2*time.Minute, "started=ok")
			return err
		})
		p.add(fmt.Sprintf("Wait until %s has synced and is promoted (%d/%d)", o.Name, want, total), t, func(ctx context.Context, s *Step) error {
			return p.waitStatus(ctx, s, t, want, false, true, strutil.FirstNonEmpty(strutil.URLHost(o.Facts.PeerURL), o.IP))
		})
		p.add("Start kube-apiserver, restart controllers and kubelet", o, func(ctx context.Context, s *Step) error {
			if _, err := p.exec(ctx, s, o, "unpark_api", nil, 3*time.Minute, "unpark=ok"); err != nil {
				return err
			}
			return p.waitStatus(ctx, s, o, want, true, false, "")
		})
	}
	p.add("Check etcd status", t, func(ctx context.Context, s *Step) error {
		return p.waitStatus(ctx, s, t, want, false, false, "")
	})
}

// clusterReset runs `<bin> server --cluster-reset` on the target, restoring
// snapshot when given, detached and polled until it reports the membership
// reset. force clears the reset-flag a previous reset left (a deliberate
// second reset).
func (p *Plan) clusterReset(ctx context.Context, s *Step, t Node, snapshot string, force bool) error {
	vars := map[string]string{"SNAP": snapshot}
	if p.S3 && snapshot != "" {
		vars["S3"] = "1"
	}
	if force {
		vars["FORCE"] = "1"
	}
	if _, err := p.exec(ctx, s, t, "reset_rke2", vars, 2*time.Minute, "started=ok"); err != nil {
		return err
	}
	log := t.Facts.Rescue + "/cluster-reset.log"
	exitF := t.Facts.Rescue + "/cluster-reset.exit"
	return p.poll(ctx, s, t, "poll", map[string]string{"LOG": log, "EXIT": exitF}, 2*p.WaitTimeout, func(out string) (bool, error) {
		code := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "exit=") {
				code = strings.TrimSpace(strings.TrimPrefix(l, "exit="))
			}
		}
		if code == "" {
			return false, nil
		}
		// rke2/k3s print this right before exiting 0; a reset that gave
		// up (etcd never came up, apiserver never ready) also exits 0
		// after "Shutdown request received", so the exit code alone
		// proves nothing
		if strings.Contains(out, "cluster membership has been reset") {
			p.logLine(s, "cluster-reset finished (exit "+code+"); log kept at "+log)
			return true, nil
		}
		return true, fmt.Errorf("cluster-reset exited %s without resetting membership: %s (full log: %s)", code, lastError(out), log)
	})
}

// restoreVerified runs the restoring cluster-reset and checks on disk that
// it replaced the data dir (verify_restore.sh); when it did not - the
// combined restore + reset has been seen to leave the old data in place -
// the dir is moved aside again and the restore runs once more.
func (p *Plan) restoreVerified(ctx context.Context, s *Step, t Node) error {
	for attempt := 1; ; attempt++ {
		since := fmt.Sprint(time.Now().Unix())
		if err := p.clusterReset(ctx, s, t, p.Snapshot, attempt > 1); err != nil {
			return err
		}
		vars := map[string]string{"SNAP": p.Snapshot, "SINCE": since}
		if p.S3 {
			vars["S3"] = "1"
		}
		out, err := p.exec(ctx, s, t, "verify_restore", vars, 2*time.Minute, "verify=ok")
		if err != nil {
			return err
		}
		why := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "restored=") {
				why = strings.TrimSpace(strings.TrimPrefix(l, "restored="))
			}
		}
		if why == "yes" {
			p.logLine(s, "data dir replaced by the restore (old data moved to etcd-old-<time>, member/snap/db rewritten)")
			return nil
		}
		why = strings.TrimPrefix(why, "no ")
		if attempt >= 2 {
			return fmt.Errorf("the cluster-reset did not replace %s (second attempt): %s", p.dataDir(t), why)
		}
		p.logLine(s, "the cluster-reset did not replace the data dir: "+why+"; moving it aside and restoring again")
		p.note("the first cluster-reset on " + t.Name + " did not replace the data dir (" + why + "); it was moved aside and the restore ran a second time")
		if _, err := p.exec(ctx, s, t, "wipe_again", map[string]string{"SINCE": since}, 5*time.Minute, "wiped=ok"); err != nil {
			return err
		}
	}
}

// needsReset says the restored member did not come up as a one-member
// cluster: rke2's combined restore + reset sometimes leaves the old peers in
// the member list, or the member never elects itself; a second plain
// cluster-reset is the known fix.
type needsReset struct{ reason string }

func (e *needsReset) Error() string { return e.reason }

// targetUp waits for the restored target to serve alone, and runs the second
// cluster-reset (stop, reset without a snapshot, perms, start) when it does
// not, then waits again.
func (p *Plan) targetUp(ctx context.Context, s *Step, t Node) error {
	err := p.waitTargetAlone(ctx, s, t)
	var nr *needsReset
	if err == nil || !errors.As(err, &nr) {
		return err
	}
	p.logLine(s, "second cluster-reset needed: "+nr.reason)
	p.note("a second cluster-reset was needed on " + t.Name + " (" + nr.reason + "): the restored member did not come up as a one-member cluster, a known rke2 behavior of the combined restore + reset")
	if _, err := p.exec(ctx, s, t, "stop", nil, 8*time.Minute, "stopped=ok"); err != nil {
		return err
	}
	if err := p.clusterReset(ctx, s, t, "", true); err != nil {
		return err
	}
	if _, err := p.exec(ctx, s, t, "perms", map[string]string{"OWNER": t.Facts.Owner}, 5*time.Minute, "perms=ok"); err != nil {
		return err
	}
	if _, err := p.exec(ctx, s, t, "start", map[string]string{"ROLE": "target"}, 2*time.Minute, "started=ok"); err != nil {
		return err
	}
	return p.waitStatus(ctx, s, t, 1, true, false, "")
}

// waitTargetAlone is waitStatus(want=1, api) that gives up early with
// needsReset when the member list still has other members, or no leader
// has appeared five minutes after the start.
func (p *Plan) waitTargetAlone(ctx context.Context, s *Step, t Node) error {
	start := time.Now()
	var last Status
	err := p.poll(ctx, s, t, "status", map[string]string{"API": "1"}, p.WaitTimeout, func(out string) (bool, error) {
		last = ParseStatus(t.Name, out)
		if strings.Contains(last.Svc, "failed") {
			return true, fmt.Errorf("%s is in state failed on %s", p.Svc(), t.Name)
		}
		if last.Members > 1 {
			return true, &needsReset{fmt.Sprintf("the member list still has %d members after the restore", last.Members)}
		}
		if time.Since(start) > p.aloneGrace() && (last.Members == 0 || last.Leader == "") {
			return true, &needsReset{fmt.Sprintf("no single-member leader %s after the start", p.aloneGrace().Round(time.Second))}
		}
		ok, why := last.Ready(1, true, "")
		if !ok {
			p.mu.Lock()
			s.Live = append([]string{"waiting: " + why}, s.Live...)
			p.mu.Unlock()
		}
		return ok, nil
	})
	if err != nil {
		return err
	}
	p.mu.Lock()
	s.Log = append(s.Log, fmt.Sprintf("%s: %d members, %d healthy, leader %s, %s", t.Name, last.Members, last.Healthy, last.Leader, statusSummary(last)))
	s.Live = nil
	p.mu.Unlock()
	return nil
}

// aloneGrace is how long the restored member gets to elect itself.
func (p *Plan) aloneGrace() time.Duration {
	if p.WaitTimeout < 5*time.Minute {
		return p.WaitTimeout / 3 // tests
	}
	return 5 * time.Minute
}

func (p *Plan) buildKubeadm() {
	t := p.Target
	snapLabel := p.Snapshot
	if i := strings.LastIndex(snapLabel, "/"); i >= 0 {
		snapLabel = snapLabel[i+1:]
	}
	p.add("Restore "+snapLabel+" as a one-member cluster", t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "restore_kubeadm", map[string]string{"SNAP": p.Snapshot, "NAME": t.Facts.MemberName, "PEER": t.Facts.PeerURL, "IMAGE": t.Facts.Image}, 15*time.Minute, "restore=ok")
		return err
	})
	p.add("Set data dir owner/mode", t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "perms", map[string]string{"OWNER": t.Facts.Owner}, 5*time.Minute, "perms=ok")
		return err
	})
	p.add("Start etcd (static pod)", t, func(ctx context.Context, s *Step) error {
		_, err := p.exec(ctx, s, t, "start", map[string]string{"ROLE": "target"}, 2*time.Minute, "started=ok")
		return err
	})
	p.add("Wait for etcd", t, func(ctx context.Context, s *Step) error {
		return p.waitStatus(ctx, s, t, 1, false, false, "")
	})
	p.add("Start kube-apiserver, restart controllers and kubelet", t, func(ctx context.Context, s *Step) error {
		if _, err := p.exec(ctx, s, t, "unpark_api", nil, 3*time.Minute, "unpark=ok"); err != nil {
			return err
		}
		return p.waitStatus(ctx, s, t, 1, true, false, "")
	})
	for i, o := range p.Others {
		p.rejoinSteps(t, o, i+2, 1+len(p.Others))
	}
	// only once every apiserver is back: the CNI pod reaches the API through
	// the service VIP, and kube-proxy on the target still maps it to every
	// apiserver (its own kubeconfig is pinned to the controlPlaneEndpoint,
	// which may be a follower that is still stopped) - a fresh calico
	// installer fails on the first refused connection and backs off
	p.add("Restart the CNI agent (it drops the local pod routes while the apiserver comes up)", t, func(ctx context.Context, s *Step) error {
		out, err := p.exec(ctx, s, t, "cni_restart", map[string]string{"NODE": t.Name}, 4*time.Minute, "cni=ok")
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "cni_skipped=") {
				p.note("the CNI agent on " + t.Name + " was NOT restarted: " + strings.TrimPrefix(l, "cni_skipped="))
			}
		}
		return err
	})
}

func (p *Plan) confDir() string { return "/etc/rancher/" + string(p.Kind) }

func (p *Plan) logLine(s *Step, l string) {
	p.mu.Lock()
	s.Log = append(s.Log, l)
	p.mu.Unlock()
}

func (p *Plan) note(s string) {
	p.mu.Lock()
	p.Notes = append(p.Notes, s)
	p.mu.Unlock()
}

// ---------- running ----------

// Run executes the steps in order, sending an Event on every change. It
// stops at the first failure (the remaining steps are marked skipped) or
// after the current step once Abort was called. The channel is closed
// when Run returns.
func (p *Plan) Run(ctx context.Context, events chan<- Event) {
	defer close(events)
	emit := func(cur int, done bool, err error) {
		p.mu.Lock()
		ev := Event{Steps: p.copySteps(), Current: cur, Done: done, Err: err}
		p.mu.Unlock()
		select {
		case events <- ev:
		case <-ctx.Done():
		}
	}
	p.mu.Lock()
	steps := p.steps
	p.mu.Unlock()
	var failed error
	for i, s := range steps {
		if failed != nil || p.abort.Load() || ctx.Err() != nil {
			p.mu.Lock()
			s.State = Skipped
			p.mu.Unlock()
			continue
		}
		p.mu.Lock()
		s.State, s.Started = Running, time.Now()
		p.mu.Unlock()
		emit(i, false, nil)
		err := s.run(ctx, s)
		p.mu.Lock()
		s.Finished = time.Now()
		if err != nil {
			s.State, s.Err = Failed, err.Error()
			failed = fmt.Errorf("step %d/%d failed on %s: %s: %v", i+1, len(steps), s.Node, s.Title, err)
		} else {
			s.State = Done
		}
		p.mu.Unlock()
		emit(i, false, nil)
	}
	if failed == nil && p.abort.Load() {
		failed = fmt.Errorf("aborted by the operator after the step in progress")
	}
	p.finishNotes(failed)
	emit(-1, true, failed)
}

// finishNotes records what the operator needs to know afterward.
func (p *Plan) finishNotes(failed error) {
	touched := append([]Node{p.Target}, p.Others...)
	if p.Rejoin {
		touched = p.Others // the anchor is not touched
	}
	for _, n := range touched {
		if n.Facts.Rescue != "" {
			p.note(fmt.Sprintf("%s: previous etcd data kept in %s (delete it once the cluster has been fine for a while)", n.Name, n.Facts.Rescue))
		}
	}
	if (p.Kind == RKE2 || p.Kind == K3s) && !p.Rejoin {
		p.note(fmt.Sprintf("%s also keeps the pre-restore data %s itself as %s/etcd-old-<time>", p.Kind, p.Target.Name, strings.TrimSuffix(p.dataDir(p.Target), "/etcd")))
	}
	for _, n := range p.Skipped {
		p.note(fmt.Sprintf("%s was left out (%s): when it is reachable again stop %s, move %s aside and start %s so it rejoins", n.Name, n.Facts.Err, p.Svc(), p.dataDir(n), p.Svc()))
	}
	if p.Kind == Kubeadm {
		p.note("worker kubelets were not restarted: if pods look stale on a worker, systemctl restart kubelet there")
	}
	if failed != nil {
		p.note("the cluster is in the state the failed step left it; the steps above say what was done on each node. Data moved aside is never deleted by khealth.")
	}
}

// exec runs one script on a node, appends its output to the step and
// checks for the marker line the script prints on success.
func (p *Plan) exec(ctx context.Context, s *Step, n Node, script string, vars map[string]string, timeout time.Duration, marker string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := p.runner.Run(cctx, n.Host, p.render(script, n, vars))
	out := strings.ReplaceAll(res.Stdout, "\r", "")
	p.mu.Lock()
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			s.Log = append(s.Log, n.Name+": "+l)
		}
	}
	p.mu.Unlock()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "ERROR: ") {
			return out, fmt.Errorf("%s", strings.TrimPrefix(l, "ERROR: "))
		}
	}
	if strings.Contains(out, "\n"+marker+"\n") || strings.HasSuffix(strings.TrimRight(out, "\n"), marker) {
		return out, nil
	}
	if res.Err != nil {
		msg := strutil.FirstLine(res.Err.Error())
		if e := strings.TrimSpace(res.Stderr); e != "" {
			msg += ": " + strutil.FirstLine(e)
		}
		return out, fmt.Errorf("ssh %s: %s", n.Host, msg)
	}
	if e := lastInteresting(out + "\n" + res.Stderr); e != "" {
		return out, fmt.Errorf("script did not report %s: %s", marker, e)
	}
	return out, fmt.Errorf("script did not report %s", marker)
}

// poll runs a script every PollInterval until check says done or the
// timeout passes; the latest output is the step's Live lines.
func (p *Plan) poll(ctx context.Context, s *Step, n Node, script string, vars map[string]string, timeout time.Duration, check func(out string) (bool, error)) error {
	deadline := time.Now().Add(timeout)
	failures := 0
	last := ""
	for {
		cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		res := p.runner.Run(cctx, n.Host, p.render(script, n, vars))
		cancel()
		out := strings.ReplaceAll(res.Stdout, "\r", "")
		if res.Err != nil && strings.TrimSpace(out) == "" {
			failures++
			p.mu.Lock()
			s.Live = []string{n.Name + ": ssh: " + strutil.FirstLine(res.Err.Error())}
			p.mu.Unlock()
			if failures >= 5 {
				return fmt.Errorf("ssh %s keeps failing: %v", n.Host, res.Err)
			}
		} else {
			failures = 0
			last = out
			p.mu.Lock()
			s.Live = liveLines(out)
			p.mu.Unlock()
			done, err := check(out)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s; last state: %s", timeout.Round(time.Second), lastInteresting(last))
		}
		select {
		case <-time.After(p.PollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Status is what status.sh reported, judged against what the step wants.
type Status struct {
	Svc      string
	Health   string
	Readyz   string
	Members  int
	Learners int
	Healthy  int
	Leader   string
	Alarms   int
	Probe    *etcd.Probe
}

// ParseStatus reads a status.sh output.
func ParseStatus(node, out string) Status {
	st := Status{}
	head := out
	if i := strings.Index(out, "---"); i >= 0 {
		head = out[:i]
	}
	for _, l := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "svc_state":
			st.Svc = v
		case "health":
			st.Health = v
		case "readyz":
			st.Readyz = v
		}
	}
	st.Probe = etcd.ParseCtl(node, out)
	st.Members = len(st.Probe.Members)
	for _, m := range st.Probe.Members {
		if m.IsLearner {
			st.Learners++
		}
	}
	for _, h := range st.Probe.EndpointHealth {
		if h.Healthy {
			st.Healthy++
		}
	}
	st.Leader = st.Probe.Leader()
	st.Alarms = len(st.Probe.Alarms)
	return st
}

// Ready says whether the cluster is in the wanted state: `want` voting
// members that are all healthy, one leader every status agrees on, no
// alarms, the apiserver answering when api is set, and a member with peer
// address `ip` when given. The string is why not.
func (st Status) Ready(want int, api bool, ip string) (bool, string) {
	switch {
	case st.Members == 0:
		if st.Health != "" && !strings.Contains(st.Health, `"true"`) {
			return false, "etcd not up yet (health: " + strutil.FirstLine(st.Health) + ")"
		}
		return false, "no member list yet"
	case st.Members < want:
		return false, fmt.Sprintf("%d/%d members", st.Members, want)
	case st.Members > want:
		return false, fmt.Sprintf("%d members, expected %d", st.Members, want)
	case st.Learners > 0:
		return false, fmt.Sprintf("%d learner(s) still syncing", st.Learners)
	case st.Healthy < st.Members:
		return false, fmt.Sprintf("%d/%d endpoints healthy", st.Healthy, st.Members)
	case st.Leader == "":
		return false, "no leader agreed by every member"
	case st.Alarms > 0:
		return false, fmt.Sprintf("%d alarm(s)", st.Alarms)
	}
	if ip != "" {
		found := false
		for _, m := range st.Probe.Members {
			for _, u := range m.PeerURLs {
				if strings.Contains(u, "//"+ip+":") || strings.Contains(u, "//["+ip+"]:") {
					found = true
				}
			}
		}
		if !found {
			return false, "no member with peer address " + ip
		}
	}
	if api {
		switch st.Readyz {
		case "200", "401", "403":
		default:
			return false, "apiserver not answering /readyz yet (" + strutil.FirstNonEmpty(st.Readyz, "-") + ")"
		}
	}
	return true, ""
}

// waitStatus polls status.sh on node until Status.Ready.
func (p *Plan) waitStatus(ctx context.Context, s *Step, n Node, want int, api, promote bool, ip string) error {
	vars := map[string]string{}
	if api {
		vars["API"] = "1"
	}
	if promote {
		vars["PROMOTE"] = "1"
	}
	var last Status
	err := p.poll(ctx, s, n, "status", vars, p.WaitTimeout, func(out string) (bool, error) {
		last = ParseStatus(n.Name, out)
		ok, why := last.Ready(want, api, ip)
		if strings.Contains(last.Svc, "failed") {
			return true, fmt.Errorf("%s is in state failed on %s (%s)", p.Svc(), n.Name, why)
		}
		if !ok {
			p.mu.Lock()
			s.Live = append([]string{"waiting: " + why}, s.Live...)
			p.mu.Unlock()
		}
		return ok, nil
	})
	if err != nil {
		return err
	}
	p.mu.Lock()
	s.Log = append(s.Log, fmt.Sprintf("%s: %d members, %d healthy, leader %s, %s", n.Name, last.Members, last.Healthy, last.Leader, statusSummary(last)))
	s.Live = nil
	p.mu.Unlock()
	return nil
}

func statusSummary(st Status) string {
	var parts []string
	for _, m := range st.Probe.Members {
		e := st.Probe.Status(m.ID)
		if e != nil {
			parts = append(parts, fmt.Sprintf("%s term %d idx %d", m.Name, e.RaftTerm, e.RaftIndex))
		} else {
			parts = append(parts, m.Name)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func liveLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") && !strings.HasPrefix(t, "---") {
			lines = append(lines, t)
		}
	}
	if len(lines) > 12 {
		lines = lines[len(lines)-12:]
	}
	return lines
}

// lastInteresting is the last non-empty line that looks like a message.
func lastInteresting(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "---") || strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") || strings.HasPrefix(t, "}") || strings.HasPrefix(t, "]") {
			continue
		}
		if len(t) > 200 {
			t = t[:200]
		}
		return t
	}
	return ""
}

// lastError is the last log line that reads like an error, else the last
// interesting line.
func lastError(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// the fatal/error line explains it; "Shutdown request received" only follows it
	for _, want := range []string{"level=fatal", "level=error", "Shutdown request"} {
		for i := len(lines) - 1; i >= 0; i-- {
			t := strings.TrimSpace(lines[i])
			if strings.Contains(t, want) {
				if len(t) > 300 {
					t = t[:300]
				}
				return t
			}
		}
	}
	return lastInteresting(out)
}
