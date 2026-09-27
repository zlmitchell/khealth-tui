package rca

import (
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// PodShape is one pod as the node saw it: what it asked for, what it was
// allowed, and what it used.
type PodShape struct {
	Namespace, Name, Workload string
	QoS                       string
	Priority                  int32
	Started                   time.Time
	ReqCPU, LimCPU            int64 // millicores (0: none)
	ReqMem, LimMem            int64 // bytes (0: none)
	UseCPU, UseMem            int64 // from metrics at gather time (-1: unknown)
	Restarts                  int32
	Phase                     string        // Running, Failed (Evicted), ...
	Arrived                   time.Duration // scheduled onto the node this long before the incident (0: not within the window)
	Victim                    bool          // the pod the incident happened to
}

// NodeShape is a node around a moment: its capacity and the pods on it.
type NodeShape struct {
	Name                   string
	Roles                  []string
	AllocCPU, AllocMem     int64
	ReqCPU, ReqMem         int64 // sum over the pods present
	UseCPU, UseMem         int64 // node metrics at gather time (-1: unknown)
	Conditions             []string
	Taints                 []string
	Pods                   []PodShape
	MetricsAt              time.Time // when the usage was measured (the gather), not the incident
	MemAvailable, MemTotal int64     // node probe at gather time (0: unknown)
}

// NodeSummary is one line of the cluster's shape.
type NodeSummary struct {
	Name                 string
	Roles                []string
	Ready                string
	Pressure             []string
	Pods                 int
	CPUReqPct, MemReqPct int // requests / allocatable
	CPUUsePct, MemUsePct int // -1: no metrics
	Taints               int
}

// Shape builds the node's shape at t: every pod bound to it that had
// started by t and not finished before it. Metrics are the gather's (the
// bundle has no history), flagged as such by MetricsAt.
func Shape(src Source, node string, t time.Time, window time.Duration, victim string) *NodeShape {
	s := src.Snap()
	var n *corev1.Node
	for i := range s.Nodes {
		if s.Nodes[i].Name == node {
			n = &s.Nodes[i]
		}
	}
	sh := &NodeShape{Name: node, UseCPU: -1, UseMem: -1, MetricsAt: s.Taken}
	if n != nil {
		sh.Roles = k8s.NodeRoles(n)
		sh.AllocCPU = n.Status.Allocatable.Cpu().MilliValue()
		sh.AllocMem = n.Status.Allocatable.Memory().Value()
		for _, c := range n.Status.Conditions {
			if (c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue) || (badWhenTrue[c.Type] && c.Status == corev1.ConditionTrue) {
				sh.Conditions = append(sh.Conditions, string(c.Type)+"="+string(c.Status))
			}
		}
		for _, tn := range n.Spec.Taints {
			sh.Taints = append(sh.Taints, tn.Key+":"+string(tn.Effect))
		}
	}
	if m, ok := s.NodeMetrics[node]; ok {
		sh.UseCPU, sh.UseMem = m.CPUMilli, m.MemBytes
	}
	if ni := src.Node(node); ni != nil {
		sh.MemTotal, sh.MemAvailable = int64(ni.MemTotal), int64(ni.MemAvail)
	}
	usage := podUsage(src)
	arrived := arrivals(s, node, t.Add(-window), t)
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.NodeName != node || !presentAt(p, t) {
			continue
		}
		ps := podShape(p, usage)
		if at, ok := arrived[p.Namespace+"/"+p.Name]; ok {
			ps.Arrived = max(t.Sub(at), time.Second)
		}
		ps.Victim = p.Namespace+"/"+p.Name == victim
		sh.ReqCPU += ps.ReqCPU
		sh.ReqMem += ps.ReqMem
		sh.Pods = append(sh.Pods, ps)
	}
	sort.SliceStable(sh.Pods, func(i, j int) bool {
		if sh.Pods[i].UseMem != sh.Pods[j].UseMem {
			return sh.Pods[i].UseMem > sh.Pods[j].UseMem
		}
		return sh.Pods[i].ReqMem > sh.Pods[j].ReqMem
	})
	return sh
}

// presentAt: started by t (or not started yet but already bound, a pod
// pending on the node), and not finished before t.
func presentAt(p *corev1.Pod, t time.Time) bool {
	if p.Status.StartTime != nil && p.Status.StartTime.After(t) {
		return false
	}
	if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		if end := endTime(p); !end.IsZero() && end.Before(t.Add(-time.Minute)) {
			return false
		}
	}
	return true
}

// endTime is when a finished pod stopped, zero when its status does not
// say (then it counts as present: better a pod too many in the shape than
// the culprit missing).
func endTime(p *corev1.Pod) time.Time {
	for _, c := range p.Status.Conditions {
		if c.Type == "DisruptionTarget" && !c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime.Time
		}
	}
	var end time.Time
	for _, cs := range p.Status.ContainerStatuses {
		if t := cs.State.Terminated; t != nil && t.FinishedAt.After(end) {
			end = t.FinishedAt.Time
		}
	}
	return end
}

func podShape(p *corev1.Pod, usage map[string][2]int64) PodShape {
	ps := PodShape{Namespace: p.Namespace, Name: p.Name, Workload: OwnerOf(p), QoS: string(p.Status.QOSClass), Phase: string(p.Status.Phase), UseCPU: -1, UseMem: -1}
	if p.Status.Reason != "" {
		ps.Phase += " (" + p.Status.Reason + ")"
	}
	if p.Spec.Priority != nil {
		ps.Priority = *p.Spec.Priority
	}
	if p.Status.StartTime != nil {
		ps.Started = p.Status.StartTime.Time
	}
	for _, c := range p.Spec.Containers {
		ps.ReqCPU += c.Resources.Requests.Cpu().MilliValue()
		ps.LimCPU += c.Resources.Limits.Cpu().MilliValue()
		ps.ReqMem += c.Resources.Requests.Memory().Value()
		ps.LimMem += c.Resources.Limits.Memory().Value()
	}
	for _, cs := range p.Status.ContainerStatuses {
		ps.Restarts += cs.RestartCount
	}
	if u, ok := usage[p.Namespace+"/"+p.Name]; ok {
		ps.UseCPU, ps.UseMem = u[0], u[1]
	}
	return ps
}

// podUsage reads pods.metrics.k8s.io: ns/pod -> {millicores, bytes}.
func podUsage(src Source) map[string][2]int64 {
	out := map[string][2]int64{}
	for _, o := range src.Objects("pods.metrics.k8s.io") {
		cs, _, _ := unstructuredSlice(o.Object, "containers")
		var cpu, mem int64
		for _, c := range cs {
			cm, _ := c.(map[string]any)
			u, _ := cm["usage"].(map[string]any)
			if q, err := resource.ParseQuantity(str(u["cpu"])); err == nil {
				cpu += q.MilliValue()
			}
			if q, err := resource.ParseQuantity(str(u["memory"])); err == nil {
				mem += q.Value()
			}
		}
		out[o.GetNamespace()+"/"+o.GetName()] = [2]int64{cpu, mem}
	}
	return out
}

var assigned = regexp.MustCompile(`Successfully assigned (\S+)/(\S+) to (\S+)`)

// arrivals are the pods scheduled onto node between from and to, from the
// scheduler's events (pods deleted since still count).
func arrivals(s *k8s.Snapshot, node string, from, to time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for i := range s.Events {
		ev := &s.Events[i]
		if ev.Reason != "Scheduled" {
			continue
		}
		t := eventTime(ev)
		if t.Before(from) || t.After(to) {
			continue
		}
		if m := assigned.FindStringSubmatch(ev.Message); m != nil && m[3] == node {
			out[m[1]+"/"+m[2]] = t
		}
	}
	return out
}

func eventTime(ev *corev1.Event) time.Time {
	switch {
	case !ev.EventTime.IsZero():
		return ev.EventTime.Time
	case !ev.LastTimestamp.IsZero():
		return ev.LastTimestamp.Time
	}
	return ev.FirstTimestamp.Time
}

// ClusterShape summarizes every node: requests and usage against what it
// can allocate, conditions and taints.
func ClusterShape(s *k8s.Snapshot) []NodeSummary {
	req := map[string][2]int64{}
	count := map[string]int{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		ps := podShape(p, nil)
		r := req[p.Spec.NodeName]
		req[p.Spec.NodeName] = [2]int64{r[0] + ps.ReqCPU, r[1] + ps.ReqMem}
		count[p.Spec.NodeName]++
	}
	var out []NodeSummary
	for i := range s.Nodes {
		n := &s.Nodes[i]
		ns := NodeSummary{Name: n.Name, Roles: k8s.NodeRoles(n), Pods: count[n.Name], Taints: len(n.Spec.Taints), CPUUsePct: -1, MemUsePct: -1}
		ready, _ := k8s.NodeCondition(n, corev1.NodeReady)
		ns.Ready = string(ready)
		for _, c := range n.Status.Conditions {
			if badWhenTrue[c.Type] && c.Status == corev1.ConditionTrue {
				ns.Pressure = append(ns.Pressure, string(c.Type))
			}
		}
		ac, am := n.Status.Allocatable.Cpu().MilliValue(), n.Status.Allocatable.Memory().Value()
		ns.CPUReqPct, ns.MemReqPct = pct(req[n.Name][0], ac), pct(req[n.Name][1], am)
		if m, ok := s.NodeMetrics[n.Name]; ok {
			ns.CPUUsePct, ns.MemUsePct = pct(m.CPUMilli, ac), pct(m.MemBytes, am)
		}
		out = append(out, ns)
	}
	return out
}

func pct(a, b int64) int {
	if b <= 0 {
		return 0
	}
	return int(a * 100 / b)
}

// ---- what the kubelet and the kernel said ------------------------------------

// Eviction is a parsed kubelet eviction message.
type Eviction struct {
	Resource  string // memory, ephemeral-storage, pid, nodefs...
	Container string
	Using     int64 // bytes (0: not stated)
	Request   int64
}

var (
	evResource  = regexp.MustCompile(`low on resource: ([a-z-]+)`)
	evContainer = regexp.MustCompile(`Container (\S+) was using (\S+?), request is (\S+?)[,.]`)
	evExceeds   = regexp.MustCompile(`(ephemeral local storage|emptyDir) usage exceeds`)
)

// ParseEviction reads "The node was low on resource: memory. Threshold
// quantity: 100Mi, available: 51Mi. Container app was using 812Mi, request
// is 64Mi, has larger consumption of memory."
func ParseEviction(msg string) Eviction {
	var ev Eviction
	if m := evResource.FindStringSubmatch(msg); m != nil {
		ev.Resource = m[1]
	} else if evExceeds.MatchString(msg) {
		ev.Resource = "ephemeral-storage (own limit)"
	}
	if m := evContainer.FindStringSubmatch(msg); m != nil {
		ev.Container = m[1]
		if q, err := resource.ParseQuantity(m[2]); err == nil {
			ev.Using = q.Value()
		}
		if q, err := resource.ParseQuantity(m[3]); err == nil {
			ev.Request = q.Value()
		}
	}
	return ev
}

// KernelOOM is a parsed kernel OOM-killer report.
type KernelOOM struct {
	Process  string
	PodUID   string // from task_memcg=/kubepods/.../pod<uid>/...
	NodeWide bool   // constraint=CONSTRAINT_NONE: the node ran out, not a cgroup limit
	RSS      int64  // anon-rss of the killed process, bytes
}

var (
	oomKilled = regexp.MustCompile(`Killed process \d+ \(([^)]+)\).*?anon-rss:(\d+)kB`)
	oomMemcg  = regexp.MustCompile(`task_memcg=\S*?pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
	oomCons   = regexp.MustCompile(`constraint=(CONSTRAINT_[A-Z]+)`)
)

// ParseKernelOOM reads the oom-kill and "Killed process" lines.
func ParseKernelOOM(lines ...string) KernelOOM {
	var k KernelOOM
	for _, l := range lines {
		if m := oomKilled.FindStringSubmatch(l); m != nil {
			k.Process = m[1]
			if n, err := resource.ParseQuantity(m[2] + "Ki"); err == nil {
				k.RSS = n.Value()
			}
		}
		if m := oomMemcg.FindStringSubmatch(l); m != nil {
			k.PodUID = strings.ReplaceAll(m[1], "_", "-")
		}
		if m := oomCons.FindStringSubmatch(l); m != nil {
			k.NodeWide = m[1] == "CONSTRAINT_NONE"
		}
	}
	return k
}

func unstructuredSlice(obj map[string]any, key string) ([]any, bool, error) {
	v, ok := obj[key].([]any)
	return v, ok, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
