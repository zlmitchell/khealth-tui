package rca

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
)

// Kind is the type of an incident.
type Kind string

// Incident kinds, in the order the explorer lists them.
const (
	KindOOM       Kind = "oom"       // a container hit its memory limit (OOMKilled)
	KindNodeOOM   Kind = "node-oom"  // the kernel OOM killer on a node short of memory
	KindEviction  Kind = "eviction"  // the kubelet evicted a pod for node pressure
	KindRejected  Kind = "rejected"  // the kubelet refused to admit a pod while the node was under pressure
	KindRestart   Kind = "restart"   // a container exited and was restarted
	KindProbe     Kind = "probe"     // killed by its liveness probe
	KindPull      Kind = "pull"      // its image could not be pulled
	KindSchedule  Kind = "schedule"  // could not be scheduled
	KindAdmission Kind = "admission" // pods could not be created (PodSecurity, quota, webhook)
	KindVolume    Kind = "volume"    // volumes did not attach or mount
	KindSandbox   Kind = "sandbox"   // the pod sandbox (CNI) failed
	KindNotReady  Kind = "notready"  // a node went NotReady
	KindDrain     Kind = "drain"     // a node was cordoned (and drained: its pods stopped after)
	KindPressure  Kind = "pressure"  // a node reported memory / disk / PID pressure
)

// Kinds lists every kind in display order.
var Kinds = []Kind{KindOOM, KindNodeOOM, KindEviction, KindRejected, KindRestart, KindProbe, KindPull, KindSchedule, KindAdmission, KindVolume, KindSandbox, KindNotReady, KindDrain, KindPressure}

// Label is a short human name for the kind.
func (k Kind) Label() string {
	switch k {
	case KindOOM:
		return "OOMKilled"
	case KindNodeOOM:
		return "node OOM"
	case KindEviction:
		return "evicted"
	case KindRejected:
		return "node refused"
	case KindRestart:
		return "restart"
	case KindProbe:
		return "liveness kill"
	case KindPull:
		return "image pull"
	case KindSchedule:
		return "unschedulable"
	case KindAdmission:
		return "create denied"
	case KindVolume:
		return "volume"
	case KindSandbox:
		return "sandbox/CNI"
	case KindNotReady:
		return "node NotReady"
	case KindDrain:
		return "node drain"
	case KindPressure:
		return "node pressure"
	}
	return string(k)
}

// Incident is one thing that happened to one object, its repeats folded.
type Incident struct {
	ID        string    `json:"id"` // stable within one analysis: kind-n
	Kind      Kind      `json:"kind"`
	Time      time.Time `json:"time"` // first occurrence
	Last      time.Time `json:"last"`
	Count     int       `json:"count"`
	Node      string    `json:"node,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Pod       string    `json:"pod,omitempty"`  // the most recent pod it happened to
	Pods      []string  `json:"pods,omitempty"` // every pod of the workload it happened to
	Container string    `json:"container,omitempty"`
	Workload  string    `json:"workload,omitempty"` // kind/name: deploy/web, sts/db, ds/agent, job/x, node/cp-1
	Summary   string    `json:"summary"`
	Entries   []Entry   `json:"entries"`
}

// Object names what the incident happened to, for lists: the workload
// (and container), with the number of its pods involved.
func (in Incident) Object() string {
	var o string
	switch {
	case in.Namespace != "" && in.Workload != "":
		o = in.Namespace + "/" + in.Workload
	case in.Pod != "":
		o = in.Namespace + "/" + in.Pod
	case in.Node != "":
		return "node/" + in.Node
	default:
		o = in.Workload
	}
	if in.Container != "" {
		o += "/" + in.Container
	}
	if len(in.Pods) > 1 {
		o += fmt.Sprintf(" (%d pods)", len(in.Pods))
	}
	return o
}

// Short is the incident's summary cut to what matters for a list: for an
// eviction the resource and the container's use against its request.
func (in Incident) Short() string {
	switch in.Kind {
	case KindEviction:
		ev := ParseEviction(in.Summary)
		res := orDefault(ev.Resource, "node")
		if ev.Using > 0 {
			return fmt.Sprintf("%s pressure: %s used %s, request %s", res, ev.Container, human(ev.Using), human(ev.Request))
		}
		return res + " pressure: evicted (the kubelet had no usage for it)"
	case KindRejected:
		if m := evResource.FindStringSubmatch(in.Summary); m != nil {
			return "not admitted: node low on " + m[1]
		}
		cond := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(in.Summary, "Pod was rejected: "), "The node had condition: ")), "[].")
		return "not admitted: the node had " + cond
	}
	return strings.Join(strings.Fields(in.Summary), " ")
}

// Extract turns the timeline into incidents, newest first within the
// order of Kinds. Repeats of the same kind on the same object become one
// incident with a count.
func Extract(tl *Timeline, snap *k8s.Snapshot) []Incident {
	pods := podIndex(snap)
	type key struct {
		kind Kind
		obj  string
	}
	byKey := map[key]*Incident{}
	var order []key
	// one incident per kind and workload (every replica of a crashing
	// Deployment is one problem, not one per pod)
	add := func(k Kind, e Entry, ns, pod, ctr, node, workload, summary string) {
		if pod != "" && workload == "" {
			if p := pods[ns+"/"+pod]; p != nil {
				workload = OwnerOf(p)
				if node == "" {
					node = p.Spec.NodeName
				}
			} else {
				workload = workloadFromPodName(pod)
			}
		}
		obj := ns + "|" + workload + "|" + ctr
		if pod == "" && ns == "" {
			obj += "|" + node // node-level kinds: one per node
		}
		ky := key{k, obj}
		in := byKey[ky]
		if in == nil {
			in = &Incident{Kind: k, Time: e.Time, Last: e.Time, Namespace: ns, Pod: pod, Container: ctr, Node: node, Workload: workload, Summary: summary}
			byKey[ky] = in
			order = append(order, ky)
		}
		in.Count++
		if e.Time.Before(in.Time) {
			in.Time = e.Time
		}
		if !e.Time.Before(in.Last) {
			in.Last = e.Time
			in.Summary = summary
			if pod != "" {
				in.Pod = pod
			}
			if node != "" {
				in.Node = node
			}
		}
		if pod != "" {
			in.Pods = appendOnce(in.Pods, pod)
		}
		in.Entries = append(in.Entries, e)
	}
	for _, e := range tl.Entries {
		switch e.Kind {
		case "status":
			if strings.HasPrefix(e.Pattern, "terminated-") {
				ns, pod, ctr := splitUnit(e.Unit)
				if e.Pattern == "terminated-oomkilled" {
					add(KindOOM, e, ns, pod, ctr, e.Node, "", e.Text)
				} else if e.Pattern != "terminated-completed" {
					add(KindRestart, e, ns, pod, ctr, e.Node, "", e.Text)
				}
			} else if e.Pattern == "node-cordoned" {
				add(KindDrain, e, "", "", "", e.Node, "node/"+e.Node, e.Text)
			} else if strings.HasPrefix(e.Pattern, "node-ready-") {
				add(KindNotReady, e, "", "", "", e.Node, "node/"+e.Node, e.Text)
			} else if strings.HasPrefix(e.Pattern, "node-") && strings.HasSuffix(e.Pattern, "pressure-true") {
				add(KindPressure, e, "", "", "", e.Node, "node/"+e.Node, e.Text)
			}
		case "event":
			kind, ns, name := eventObject(e.Unit)
			pod := ""
			if kind == "pod" {
				pod = name
			}
			switch e.Pattern {
			case "Evicted":
				if rejected(e.Text) {
					add(KindRejected, e, ns, pod, "", e.Node, "", e.Text)
				} else {
					add(KindEviction, e, ns, pod, "", e.Node, "", e.Text)
				}
			case "OOMKilling", "SystemOOM":
				add(KindNodeOOM, e, "", "", "", e.Node, "node/"+e.Node, e.Text)
			case "Killing":
				if strings.Contains(e.Text, "liveness probe") {
					add(KindProbe, e, ns, pod, containerIn(e.Text), e.Node, "", e.Text)
				}
			case "Failed", "BackOff":
				if strings.Contains(e.Text, "pull") || strings.Contains(e.Text, "ImagePull") || strings.Contains(e.Text, "ErrImage") {
					add(KindPull, e, ns, pod, "", e.Node, "", e.Text)
				}
			case "FailedScheduling":
				add(KindSchedule, e, ns, pod, "", "", "", e.Text)
			case "FailedCreate":
				add(KindAdmission, e, ns, "", "", "", ownerName(kind, name), e.Text)
			case "FailedMount", "FailedAttachVolume":
				add(KindVolume, e, ns, pod, "", e.Node, "", e.Text)
			case "FailedCreatePodSandBox":
				add(KindSandbox, e, ns, pod, "", e.Node, "", e.Text)
			case "NodeNotReady":
				add(KindNotReady, e, "", "", "", name, "node/"+name, e.Text)
			case "NodeNotSchedulable":
				add(KindDrain, e, "", "", "", name, "node/"+name, "node cordoned: "+e.Text)
			}
		default:
			if e.Pattern == "oom" && e.Class >= logs.ClassWarn {
				add(KindNodeOOM, e, "", "", "", e.Node, "node/"+e.Node, e.Text)
			}
		}
	}
	// pods evicted before the event window still say so in their status
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.Status.Reason != "Evicted" || rejected(p.Status.Message) {
			continue
		}
		if in := byKey[key{KindEviction, p.Namespace + "|" + OwnerOf(p) + "|"}]; in != nil && contains(in.Pods, p.Name) {
			continue
		}
		t := evictionTime(p)
		add(KindEviction, Entry{Time: t, Node: p.Spec.NodeName, Kind: "status", Unit: p.Namespace + "/" + p.Name, Class: logs.ClassWarn, Pattern: "Evicted", Text: p.Status.Message, Ref: Ref{File: "cluster/resources/pods.yaml"}},
			p.Namespace, p.Name, "", p.Spec.NodeName, "", p.Status.Message)
	}
	var out []Incident
	for _, k := range order {
		in := byKey[k]
		if in.Kind == KindDrain {
			drained(in, tl)
		}
		out = append(out, *in)
	}
	rank := map[Kind]int{}
	for i, k := range Kinds {
		rank[k] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].Time.After(out[j].Time)
	})
	n := map[Kind]int{}
	for i := range out {
		n[out[i].Kind]++
		out[i].ID = fmt.Sprintf("%s-%d", out[i].Kind, n[out[i].Kind])
	}
	return out
}

// drained adds to a cordon what followed it on the node: the pods stopped
// within half an hour (kubectl drain evicts through the Eviction API, so
// the pods are simply stopped and deleted, with no Evicted event), and an
// uncordon.
func drained(in *Incident, tl *Timeline) {
	t := in.Time
	var stopped []string
	uncordon := time.Time{}
	for _, e := range tl.Entries {
		if e.Node != in.Node || e.Time.Before(t) || e.Time.After(t.Add(30*time.Minute)) {
			continue
		}
		switch {
		case e.Kind == "event" && e.Pattern == "Killing" && strings.HasPrefix(e.Text, "Stopping container"):
			_, ns, name := eventObject(e.Unit)
			stopped = appendOnce(stopped, ns+"/"+name)
			in.Entries = append(in.Entries, e)
		case e.Kind == "event" && e.Pattern == "NodeSchedulable" && uncordon.IsZero():
			uncordon = e.Time
		}
	}
	in.Pods = stopped
	switch {
	case len(stopped) > 0:
		in.Summary = fmt.Sprintf("cordoned and drained: %d pods stopped after it", len(stopped))
	default:
		in.Summary = "cordoned: no new pods land on it (no pod stopped after it: cordon without drain)"
	}
	if !uncordon.IsZero() {
		in.Summary += fmt.Sprintf("; uncordoned %s later", uncordon.Sub(t).Round(time.Second))
	}
}

// rejected: the kubelet's admission refusing a pod under node pressure,
// reported with the Evicted reason but not an eviction of a running pod.
func rejected(msg string) bool {
	return strings.Contains(msg, "Pod was rejected") || strings.HasPrefix(strings.TrimSpace(msg), "The node had condition")
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// workloadFromPodName guesses the workload of a pod that no longer exists:
// <deploy>-<rs hash>-<5> is a Deployment's; otherwise the pod itself.
func workloadFromPodName(pod string) string {
	if m := rsPodName.FindStringSubmatch(pod); m != nil {
		return "deploy/" + m[1]
	}
	return "pod/" + pod
}

var rsPodName = regexp.MustCompile(`^(.+)-[a-z0-9]{8,10}-[a-z0-9]{5}$`)

func podIndex(s *k8s.Snapshot) map[string]*corev1.Pod {
	m := make(map[string]*corev1.Pod, len(s.Pods))
	for i := range s.Pods {
		m[s.Pods[i].Namespace+"/"+s.Pods[i].Name] = &s.Pods[i]
	}
	return m
}

// splitUnit reads "ns/pod/container" (status entries).
func splitUnit(u string) (ns, pod, ctr string) {
	parts := strings.SplitN(u, "/", 3)
	switch len(parts) {
	case 3:
		return parts[0], parts[1], parts[2]
	case 2:
		return parts[0], parts[1], ""
	}
	return "", u, ""
}

// eventObject reads "pod ns/name" / "node name" (event entries).
func eventObject(u string) (kind, ns, name string) {
	kind, rest, _ := strings.Cut(u, " ")
	if a, b, ok := strings.Cut(rest, "/"); ok {
		return kind, a, b
	}
	return kind, "", rest
}

// containerIn finds `Container app failed liveness probe` in an event text.
func containerIn(text string) string {
	if rest, ok := strings.CutPrefix(text, "Container "); ok {
		name, _, _ := strings.Cut(rest, " ")
		return name
	}
	return ""
}

// ownerName is the workload an event on a controller object stands for.
func ownerName(kind, name string) string {
	switch kind {
	case "replicaset":
		return "deploy/" + trimHash(name)
	case "statefulset":
		return "sts/" + name
	case "daemonset":
		return "ds/" + name
	case "job":
		return "job/" + name
	}
	return kind + "/" + name
}

// OwnerOf names the workload that runs a pod: deploy/<name> for a
// ReplicaSet with the pod-template hash, sts/ds/job/cronjob, else pod/<name>.
func OwnerOf(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		switch o.Kind {
		case "ReplicaSet":
			if h := p.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "deploy/" + strings.TrimSuffix(o.Name, "-"+h)
			}
			return "deploy/" + trimHash(o.Name) // a ReplicaSet is a Deployment's almost always
		case "StatefulSet":
			return "sts/" + o.Name
		case "DaemonSet":
			return "ds/" + o.Name
		case "Job":
			if i := strings.LastIndex(o.Name, "-"); i > 0 && isDigits(o.Name[i+1:]) {
				return "cronjob/" + o.Name[:i]
			}
			return "job/" + o.Name
		case "Node":
			return "static/" + p.Name
		}
		return strings.ToLower(o.Kind) + "/" + o.Name
	}
	return "pod/" + p.Name
}

func trimHash(rs string) string {
	if i := strings.LastIndex(rs, "-"); i > 0 {
		return rs[:i]
	}
	return rs
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// evictionTime is when the kubelet marked the pod for eviction: the
// DisruptionTarget condition (1.26+), else when its containers ended.
func evictionTime(p *corev1.Pod) time.Time {
	for _, c := range p.Status.Conditions {
		if c.Type == "DisruptionTarget" && !c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime.Time
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if t := cs.State.Terminated; t != nil && !t.FinishedAt.IsZero() {
			return t.FinishedAt.Time
		}
	}
	if p.Status.StartTime != nil {
		return p.Status.StartTime.Time
	}
	return time.Time{}
}
