package rca

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// DefaultWindow is how far around an incident its context reaches.
const DefaultWindow = 15 * time.Minute

// Context is everything around one incident: what else happened, the
// workload it belongs to, the node it ran on, the traffic it served, and
// who else may have caused it.
type Context struct {
	Incident Incident
	Window   time.Duration
	Timeline []Entry    // entries on the same node, in the same namespace, or control-plane-wide, within the window
	Related  []Incident // other incidents close by (same node, namespace or a dependency)
	Workload *WorkloadView
	Node     *NodeShape
	Cluster  []NodeSummary
	Ingress  *IngressView
	Suspects []Suspect // who else may have caused it, most likely first
	Verdict  string    // one-line reading of the suspects
	LogTail  []string  // the last lines of the container's previous run (or current, if none)
	LogRef   string

	src     Source
	episode []Entry // the node's evictions in the pressure episode around the incident
}

// Suspect is a candidate cause of the incident other than the victim.
type Suspect struct {
	Who     string // ns/pod (workload) or an event
	Score   float64
	Reasons []string
}

// WorkloadView is the workload around the incident.
type WorkloadView struct {
	Kind, Name, Namespace string
	Desired, Ready        int32
	Revisions             []Revision
	Pods                  []PodShape
	Nodes                 []string
}

// Revision is one ReplicaSet (or ControllerRevision) of the workload.
type Revision struct {
	Name     string
	Number   string
	Created  time.Time
	Images   []string
	Replicas int64
	Recent   bool // created within the window before the incident: a rollout right before it
}

// Build assembles the context of one incident.
func (in Incident) Context(src Source, tl *Timeline, all []Incident, window time.Duration) *Context {
	if window <= 0 {
		window = DefaultWindow
	}
	s := src.Snap()
	c := &Context{Incident: in, Window: window, Cluster: ClusterShape(s), src: src}
	t := in.Time
	from, to := t.Add(-window), in.Last.Add(window)
	for _, e := range tl.Entries {
		if e.Time.Before(from) || e.Time.After(to) {
			continue
		}
		if related(e, in) {
			c.Timeline = append(c.Timeline, e)
		}
	}
	c.episode = evictionEpisode(tl, in)
	pods := workloadPods(s.Pods, in)
	c.Workload = workloadView(src, in, pods, t, window)
	if in.Node != "" {
		c.Node = Shape(src, in.Node, t, window, in.Namespace+"/"+in.Pod)
		// what the kubelet measured in its eviction messages is the usage
		// at the moment, better than none (evicted pods have no metrics)
		for _, e := range c.episode {
			ev := ParseEviction(e.Text)
			_, ns, name := eventObject(e.Unit)
			for i := range c.Node.Pods {
				p := &c.Node.Pods[i]
				if ev.Using > 0 && p.UseMem < 0 && p.Namespace == ns && p.Name == name {
					p.UseMem = ev.Using
				}
			}
		}
	}
	if len(pods) > 0 {
		c.Ingress = Ingress(src, pods, t, window)
	}
	if ctr := containerOf(in, s.Pods); in.Pod != "" && ctr != "" {
		for _, prev := range []bool{true, false} {
			if lines, ref := src.PodLog(in.Namespace, in.Pod, ctr, prev); len(lines) > 0 {
				c.LogTail, c.LogRef = tail(lines, 40), ref
				break
			}
		}
	}
	deps := dependencies(c.LogTail, s.Services, in.Namespace)
	for _, o := range all {
		if o.ID == in.ID || o.Time.Before(from) || o.Time.After(to) {
			continue
		}
		// a drain explains pods that cannot be scheduled anywhere else
		drainForPending := o.Kind == KindDrain && in.Kind == KindSchedule
		if (o.Node != "" && o.Node == in.Node) || (o.Namespace != "" && o.Namespace == in.Namespace) || deps[o.Namespace+"/"+workloadName(o.Workload)] || drainForPending {
			c.Related = append(c.Related, o)
		}
	}
	sort.SliceStable(c.Related, func(i, j int) bool { return c.Related[i].Time.Before(c.Related[j].Time) })
	c.Suspects, c.Verdict = attribute(c, deps)
	return c
}

// containerOf is the container an incident is about: named, else the one
// an eviction message names, else the pod's first.
func containerOf(in Incident, pods []corev1.Pod) string {
	if in.Container != "" {
		return in.Container
	}
	if ev := ParseEviction(in.Summary); ev.Container != "" {
		return ev.Container
	}
	for i := range pods {
		if pods[i].Namespace == in.Namespace && pods[i].Name == in.Pod && len(pods[i].Spec.Containers) > 0 {
			return pods[i].Spec.Containers[0].Name
		}
	}
	return ""
}

// evictionEpisode is the run of evictions on the incident's node around
// its time: consecutive kubelet evictions (not admission rejections) less
// than two minutes apart.
func evictionEpisode(tl *Timeline, in Incident) []Entry {
	if in.Kind != KindEviction || in.Node == "" {
		return nil
	}
	var evs []Entry
	for _, e := range tl.Entries {
		if e.Kind == "event" && e.Pattern == "Evicted" && e.Node == in.Node && !rejected(e.Text) {
			evs = append(evs, e)
		}
	}
	at := -1
	for i, e := range evs {
		if !e.Time.Before(in.Time) {
			at = i
			break
		}
	}
	if at < 0 {
		return nil
	}
	lo, hi := at, at
	for lo > 0 && evs[lo].Time.Sub(evs[lo-1].Time) < 2*time.Minute {
		lo--
	}
	for hi+1 < len(evs) && evs[hi+1].Time.Sub(evs[hi].Time) < 2*time.Minute {
		hi++
	}
	return evs[lo : hi+1]
}

// related keeps an entry in an incident's timeline: its node, its
// namespace or object, and the control plane (etcd, leases), which can
// break everything at once.
func related(e Entry, in Incident) bool {
	if in.Node != "" && e.Node == in.Node {
		return true
	}
	if in.Namespace != "" && (strings.Contains(e.Unit, in.Namespace+"/") || strings.HasPrefix(e.Unit, in.Namespace+"/")) {
		return true
	}
	switch e.Pattern {
	case "etcd-slow-fsync", "leader-change", "lease-lost", "etcd-nospace", "NodeNotReady":
		return true
	}
	return strings.HasPrefix(e.Pattern, "node-")
}

// workloadPods are the pods of the incident's workload (every revision).
func workloadPods(all []corev1.Pod, in Incident) []*corev1.Pod {
	var out []*corev1.Pod
	for i := range all {
		p := &all[i]
		if p.Namespace != in.Namespace {
			continue
		}
		if p.Name == in.Pod || (in.Workload != "" && !strings.HasPrefix(in.Workload, "pod/") && OwnerOf(p) == in.Workload) {
			out = append(out, p)
		}
	}
	return out
}

func workloadName(w string) string {
	_, n, ok := strings.Cut(w, "/")
	if !ok {
		return w
	}
	return n
}

func workloadView(src Source, in Incident, pods []*corev1.Pod, t time.Time, window time.Duration) *WorkloadView {
	kind, name, _ := strings.Cut(in.Workload, "/")
	if name == "" || kind == "node" {
		return nil
	}
	w := &WorkloadView{Kind: kind, Name: name, Namespace: in.Namespace}
	s := src.Snap()
	switch kind {
	case "deploy":
		for i := range s.Deployments {
			d := &s.Deployments[i]
			if d.Namespace == in.Namespace && d.Name == name {
				if d.Spec.Replicas != nil {
					w.Desired = *d.Spec.Replicas
				}
				w.Ready = d.Status.ReadyReplicas
			}
		}
		for _, rs := range src.Objects("replicasets.apps") {
			if rs.GetNamespace() != in.Namespace || !ownedBy(rs.GetOwnerReferences(), "Deployment", name) {
				continue
			}
			r := Revision{Name: rs.GetName(), Number: rs.GetAnnotations()["deployment.kubernetes.io/revision"], Created: rs.GetCreationTimestamp().Time}
			r.Replicas, _, _ = unstructured.NestedInt64(rs.Object, "status", "replicas")
			cs, _, _ := unstructured.NestedSlice(rs.Object, "spec", "template", "spec", "containers")
			for _, ctr := range cs {
				if m, ok := ctr.(map[string]any); ok {
					r.Images = append(r.Images, str(m["image"]))
				}
			}
			r.Recent = !r.Created.Before(t.Add(-window)) && r.Created.Before(t)
			w.Revisions = append(w.Revisions, r)
		}
		sort.Slice(w.Revisions, func(i, j int) bool { return w.Revisions[i].Created.After(w.Revisions[j].Created) })
		if n := len(w.Revisions); n > 0 {
			w.Revisions[n-1].Recent = false // the first revision is a deploy, not a rollout
		}
	case "sts":
		for i := range s.StatefulSets {
			d := &s.StatefulSets[i]
			if d.Namespace == in.Namespace && d.Name == name {
				if d.Spec.Replicas != nil {
					w.Desired = *d.Spec.Replicas
				}
				w.Ready = d.Status.ReadyReplicas
			}
		}
	case "ds":
		for i := range s.DaemonSets {
			d := &s.DaemonSets[i]
			if d.Namespace == in.Namespace && d.Name == name {
				w.Desired, w.Ready = d.Status.DesiredNumberScheduled, d.Status.NumberReady
			}
		}
	}
	usage := podUsage(src)
	nodes := map[string]bool{}
	for _, p := range pods {
		w.Pods = append(w.Pods, podShape(p, usage))
		if p.Spec.NodeName != "" {
			nodes[p.Spec.NodeName] = true
		}
	}
	for n := range nodes {
		w.Nodes = append(w.Nodes, n)
	}
	sort.Strings(w.Nodes)
	return w
}

func ownedBy(refs []metav1.OwnerReference, kind, name string) bool {
	for _, r := range refs {
		if r.Kind == kind && r.Name == name {
			return true
		}
	}
	return false
}

// dependencies are the Services of the namespace that the container's last
// lines name ("cannot connect to db:5432" -> db), as ns/<workload name>.
func dependencies(lines []string, svcs []corev1.Service, ns string) map[string]bool {
	out := map[string]bool{}
	if len(lines) == 0 {
		return out
	}
	text := strings.ToLower(strings.Join(lines, " "))
	for i := range svcs {
		if svcs[i].Namespace == ns && hostRef(svcs[i].Name).MatchString(text) {
			out[ns+"/"+svcs[i].Name] = true
		}
	}
	return out
}

func hostRef(name string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^a-z0-9-])` + regexp.QuoteMeta(strings.ToLower(name)) + `([.:/][^\s]*|\s|$)`)
}

// attribute ranks who else may have caused the incident.
func attribute(c *Context, deps map[string]bool) ([]Suspect, string) {
	in := c.Incident
	var sus []Suspect
	add := func(who string, score float64, why ...string) {
		for i := range sus {
			if sus[i].Who == who {
				sus[i].Score += score
				sus[i].Reasons = append(sus[i].Reasons, why...)
				return
			}
		}
		sus = append(sus, Suspect{Who: who, Score: score, Reasons: why})
	}
	verdict := ""
	switch in.Kind {
	case KindEviction, KindNodeOOM, KindPressure, KindNotReady:
		resource := "memory"
		if in.Kind == KindEviction {
			ev := ParseEviction(in.Summary)
			if ev.Resource != "" {
				resource = ev.Resource
			}
			if strings.HasSuffix(ev.Resource, "(own limit)") {
				return nil, "the pod exceeded its own ephemeral-storage limit: it evicted itself"
			}
			if ev.Using > 0 {
				verdict = fmt.Sprintf("the evicted container was using %s against a request of %s", human(ev.Using), human(ev.Request))
			}
		}
		if in.Kind == KindNodeOOM {
			var lines []string
			for _, e := range in.Entries {
				lines = append(lines, e.Text)
			}
			k := ParseKernelOOM(lines...)
			if k.Process != "" {
				verdict = fmt.Sprintf("the kernel killed %s (%s resident)", k.Process, human(k.RSS))
				if !k.NodeWide {
					verdict += " for its own cgroup limit"
				}
			}
		}
		if c.Node == nil {
			break
		}
		// what the kubelet measured when it evicted the neighbours beats the
		// metrics of the gather: usage at the moment, per pod
		atEviction := map[string]Eviction{}
		for _, e := range c.episode {
			if ev := ParseEviction(e.Text); ev.Using > 0 {
				_, ns, name := eventObject(e.Unit)
				atEviction[ns+"/"+name] = ev
			}
		}
		// the kubelet evicts one pod at a time and stops as soon as the
		// node is back above its threshold: the last eviction of the
		// episode is the one that freed enough, whatever its message says
		relief := ""
		if n := len(c.episode); n > 0 && resource == "memory" {
			_, ns, name := eventObject(c.episode[n-1].Unit)
			relief = ns + "/" + name
			if relief == in.Namespace+"/"+in.Pod {
				verdict = strings.TrimPrefix(verdict+"; ", "; ") + "the evictions stopped after this pod went: it held the memory the node needed"
			}
		}
		for _, p := range c.Node.Pods {
			if p.Victim {
				continue
			}
			key := p.Namespace + "/" + p.Name
			who := key + " (" + p.Workload + ")"
			if resource != "memory" {
				if p.LimMem == 0 && strings.Contains(resource, "storage") {
					add(who, 0.1, "no ephemeral-storage limit")
				}
				continue
			}
			last := key == relief
			if last {
				add(who, 0.6, "the node stopped evicting once it was evicted: its memory was what the node lacked")
			}
			use, when := p.UseMem, "at gather time"
			if ev, ok := atEviction[key]; ok {
				use, when = ev.Using, "when the kubelet evicted it"
			}
			// a few MiB over a request does not push a node over: count it
			// from 64Mi or 1% of the node, whichever is larger
			above := use >= 0 && use-p.ReqMem >= max(64<<20, c.Node.AllocMem/100)
			if above {
				over := use - p.ReqMem
				add(who, 0.2+float64(over)/float64(max(c.Node.AllocMem, 1))*2,
					fmt.Sprintf("used %s of memory, %s above its request of %s (%s)", human(use), human(over), human(p.ReqMem), when))
			}
			if !above && !last {
				continue // requests cover what it uses: not what pushed the node over
			}
			if p.LimMem == 0 {
				add(who, 0.1, "no memory limit: nothing stops it growing until the node runs out")
			}
			if p.Priority > 0 {
				add(who, 0.05, fmt.Sprintf("priority %d: the kubelet evicts lower-priority pods before it", p.Priority))
			}
			if p.Arrived > 0 {
				add(who, 0.1, "scheduled onto the node "+p.Arrived.Round(time.Second).String()+" before")
			}
		}
		// the pod whose eviction ended the episode may be gone by now
		// (garbage-collected, deleted by a drain): the events still name it
		if relief != "" && relief != in.Namespace+"/"+in.Pod {
			found := false
			for _, p := range c.Node.Pods {
				if p.Namespace+"/"+p.Name == relief {
					found = true
				}
			}
			if !found {
				_, name, _ := strings.Cut(relief, "/")
				why := []string{"the node stopped evicting once it was evicted: its memory was what the node lacked (the pod no longer exists; the eviction events name it)"}
				if ev, ok := atEviction[relief]; ok && ev.Using > ev.Request {
					why = append(why, fmt.Sprintf("used %s of memory against a request of %s when the kubelet evicted it", human(ev.Using), human(ev.Request)))
				}
				add(relief+" ("+workloadFromPodName(name)+")", 0.7, why...)
			}
		}
	case KindSchedule:
		if !strings.Contains(in.Summary, "Insufficient") {
			break // taints, affinity, a cordon: not capacity
		}
		// capacity taken: the biggest requesters in the cluster
		res := "cpu"
		if strings.Contains(in.Summary, "memory") {
			res = "memory"
		}
		s := c.src.Snap()
		type req struct {
			who string
			v   int64
		}
		var reqs []req
		for i := range s.Pods {
			p := &s.Pods[i]
			if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				continue
			}
			ps := podShape(p, nil)
			v := ps.ReqCPU
			if res == "memory" {
				v = ps.ReqMem
			}
			reqs = append(reqs, req{p.Namespace + "/" + p.Name + " (" + ps.Workload + ")", v})
		}
		sort.Slice(reqs, func(i, j int) bool { return reqs[i].v > reqs[j].v })
		for i, r := range reqs {
			if i >= 5 || r.v == 0 {
				break
			}
			amount := fmt.Sprintf("%dm CPU", r.v)
			if res == "memory" {
				amount = human(r.v)
			}
			add(r.who, 0.5-float64(i)*0.08, "requests "+amount)
		}
		verdict = "the cluster's " + res + " is reserved by requests; the largest requesters are listed"
	}
	// a container at its own memory limit: the kernel killed it inside its
	// cgroup, whatever the neighbours did
	if in.Kind == KindOOM {
		lim := ""
		for i := range c.src.Snap().Pods {
			p := &c.src.Snap().Pods[i]
			if p.Namespace == in.Namespace && p.Name == in.Pod {
				for _, ct := range p.Spec.Containers {
					if ct.Name == in.Container {
						if q, ok := ct.Resources.Limits[corev1.ResourceMemory]; ok {
							lim = " of " + q.String()
						}
					}
				}
			}
		}
		verdict = "the container reached its own memory limit" + lim + " and the kernel killed it inside its cgroup: no other pod caused it. Raise the limit, or find what grows (a leak, a cache without a bound, a heap sized for the node instead of the container)"
	}
	if in.Kind == KindDrain {
		verdict = "the node was cordoned at " + in.Time.Local().Format("15:04:05") + ": " + in.Summary + " (kubectl drain, a node upgrade or an autoscaler scale-down)"
		if len(in.Pods) > 0 {
			shown := in.Pods
			if len(shown) > 10 {
				shown = append(append([]string{}, shown[:10]...), fmt.Sprintf("+%d more", len(in.Pods)-10))
			}
			verdict += ". Stopped: " + strings.Join(shown, ", ")
		}
	}
	// all kinds: a rollout right before, and dependencies that failed first
	if c.Workload != nil {
		for _, r := range c.Workload.Revisions {
			if r.Recent {
				add("rollout "+c.Workload.Kind+"/"+c.Workload.Name+" revision "+r.Number, 0.5, fmt.Sprintf("created %s before the incident (%s)", in.Time.Sub(r.Created).Round(time.Second), strings.Join(r.Images, ", ")))
			}
		}
	}
	for _, o := range c.Related {
		if !o.Time.Before(in.Time) {
			continue
		}
		// a drain before it: the pods on the node were evicted through the
		// Eviction API and rescheduled; what failed after may be only that
		if o.Kind == KindDrain && in.Kind != KindDrain {
			score := 0.55
			why := fmt.Sprintf("node %s was cordoned %s before (%s)", o.Node, in.Time.Sub(o.Time).Round(time.Second), o.Summary)
			if in.Kind == KindSchedule && strings.Contains(in.Summary, "unschedulable") {
				score, why = 0.9, why+": the scheduler reports the node as unschedulable"
			}
			add("node drain "+o.Node, score, why)
			continue
		}
		dep := deps[o.Namespace+"/"+workloadName(o.Workload)]
		switch {
		case dep:
			add(o.Namespace+"/"+o.Workload+" ("+o.Kind.Label()+")", 0.6, fmt.Sprintf("a dependency the logs name had %s %s before", o.Kind.Label(), in.Time.Sub(o.Time).Round(time.Second)))
		case o.Node != "" && o.Node == in.Node && in.Kind != KindEviction && in.Kind != KindRejected && (o.Kind == KindNodeOOM || o.Kind == KindPressure || o.Kind == KindNotReady):
			// node trouble explains restarts on it; for an eviction the
			// other evictions are fellow victims, not causes
			add("node "+o.Node+" ("+o.Kind.Label()+")", 0.45, fmt.Sprintf("%s on the same node %s before", o.Kind.Label(), in.Time.Sub(o.Time).Round(time.Second)))
		}
	}
	// control-plane trouble in the window: a weak, background suspect,
	// counted once however many lines the logs hold
	cp := map[string]int{}
	for _, e := range c.Timeline {
		if e.Pattern == "etcd-slow-fsync" || e.Pattern == "lease-lost" {
			cp[e.Pattern]++
		}
	}
	if len(cp) > 0 && in.Kind != KindDrain {
		var parts []string
		for _, p := range []string{"etcd-slow-fsync", "lease-lost"} {
			if cp[p] > 0 {
				parts = append(parts, fmt.Sprintf("%s x%d", p, cp[p]))
			}
		}
		add("control plane (etcd latency)", 0.15, "etcd / lease trouble in the window: "+strings.Join(parts, ", "))
	}
	if in.Kind == KindDrain {
		// an operator action (or an upgrade / autoscaler): nothing in the
		// cluster caused it; the audit log names who ran it
		return nil, verdict + ". Who ran it is in the apiserver audit log (verb patch on the node, then create on pods/eviction)"
	}
	sort.SliceStable(sus, func(i, j int) bool { return sus[i].Score > sus[j].Score })
	for i := range sus {
		sus[i].Reasons = dedupeStrings(sus[i].Reasons)
		if sus[i].Score > 1 {
			sus[i].Score = 1
		}
	}
	if len(sus) > 8 {
		sus = sus[:8]
	}
	if len(sus) > 0 && verdict == "" {
		verdict = "most likely: " + sus[0].Who
	} else if len(sus) > 0 {
		verdict += "; most likely pushed by " + sus[0].Who
	}
	return sus, verdict
}

func dedupeStrings(s []string) []string {
	seen := map[string]bool{}
	out := s[:0]
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func tail(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}

func human(b int64) string {
	const u = 1024
	switch {
	case b >= u*u*u:
		return fmt.Sprintf("%.1fGi", float64(b)/(u*u*u))
	case b >= u*u:
		return fmt.Sprintf("%.0fMi", float64(b)/(u*u))
	case b >= u:
		return fmt.Sprintf("%.0fKi", float64(b)/u)
	}
	return fmt.Sprintf("%d", b)
}
