package gather

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// resource is one object type the bundle dumps.
type resource struct {
	gvr        schema.GroupVersionResource
	namespaced bool
	scrub      func(*unstructured.Unstructured)
}

func gvr(g, v, r string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: g, Version: v, Resource: r}
}

// resources is what an RCA reads back: the objects, their status and the
// wiring between them. Secret and ConfigMap values never leave the cluster
// (only their keys, so a missing key still shows), nor does chart values
// content; env values whose name looks like a credential are masked.
var resources = []resource{
	{gvr("", "v1", "nodes"), false, nil},
	{gvr("", "v1", "namespaces"), false, nil},
	{gvr("", "v1", "pods"), true, scrubPodSpec("spec")},
	{gvr("", "v1", "events"), true, nil},
	{gvr("", "v1", "services"), true, nil},
	{gvr("", "v1", "persistentvolumeclaims"), true, nil},
	{gvr("", "v1", "persistentvolumes"), false, nil},
	{gvr("", "v1", "configmaps"), true, keysOnly("data", "binaryData")},
	{gvr("", "v1", "secrets"), true, keysOnly("data", "stringData")},
	{gvr("", "v1", "serviceaccounts"), true, nil},
	{gvr("", "v1", "resourcequotas"), true, nil},
	{gvr("", "v1", "limitranges"), true, nil},
	{gvr("apps", "v1", "deployments"), true, scrubPodSpec("spec", "template", "spec")},
	{gvr("apps", "v1", "replicasets"), true, scrubPodSpec("spec", "template", "spec")},
	{gvr("apps", "v1", "statefulsets"), true, scrubPodSpec("spec", "template", "spec")},
	{gvr("apps", "v1", "daemonsets"), true, scrubPodSpec("spec", "template", "spec")},
	{gvr("batch", "v1", "jobs"), true, scrubPodSpec("spec", "template", "spec")},
	{gvr("batch", "v1", "cronjobs"), true, scrubPodSpec("spec", "jobTemplate", "spec", "template", "spec")},
	{gvr("autoscaling", "v2", "horizontalpodautoscalers"), true, nil},
	{gvr("policy", "v1", "poddisruptionbudgets"), true, nil},
	{gvr("networking.k8s.io", "v1", "ingresses"), true, nil},
	{gvr("networking.k8s.io", "v1", "networkpolicies"), true, nil},
	{gvr("discovery.k8s.io", "v1", "endpointslices"), true, nil},
	{gvr("storage.k8s.io", "v1", "storageclasses"), false, nil},
	{gvr("storage.k8s.io", "v1", "volumeattachments"), false, nil},
	{gvr("storage.k8s.io", "v1", "csidrivers"), false, nil},
	{gvr("storage.k8s.io", "v1", "csinodes"), false, nil},
	{gvr("coordination.k8s.io", "v1", "leases"), true, nil},
	{gvr("admissionregistration.k8s.io", "v1", "validatingwebhookconfigurations"), false, nil},
	{gvr("admissionregistration.k8s.io", "v1", "mutatingwebhookconfigurations"), false, nil},
	{gvr("apiregistration.k8s.io", "v1", "apiservices"), false, nil},
	{gvr("scheduling.k8s.io", "v1", "priorityclasses"), false, nil},
	{gvr("apiextensions.k8s.io", "v1", "customresourcedefinitions"), false, dropSchemas},
	{gvr("metrics.k8s.io", "v1beta1", "nodes"), false, nil},
	{gvr("metrics.k8s.io", "v1beta1", "pods"), true, nil},
	// rke2 / k3s
	{gvr("helm.cattle.io", "v1", "helmcharts"), true, dropFields("spec", "valuesContent", "chartContent")},
	{gvr("helm.cattle.io", "v1", "helmchartconfigs"), true, dropFields("spec", "valuesContent")},
	{gvr("k3s.cattle.io", "v1", "addons"), true, nil},
	{gvr("k3s.cattle.io", "v1", "etcdsnapshotfiles"), false, nil},
	{gvr("upgrade.cattle.io", "v1", "plans"), true, nil},
	// Gateway API: which routes send traffic to a workload's Services
	{gvr("gateway.networking.k8s.io", "v1", "httproutes"), true, nil},
	{gvr("gateway.networking.k8s.io", "v1", "gateways"), true, nil},
}

// ResourceEntry records how one type's dump went.
type ResourceEntry struct {
	Resource string `json:"resource"`
	Count    int    `json:"count"`
	Error    string `json:"error,omitempty"`
}

func resourceFile(r schema.GroupVersionResource) string {
	if r.Group == "" {
		return r.Resource
	}
	return r.Resource + "." + r.Group
}

// dumpResources lists every type (in ns only for namespaced types when ns
// is set) into cluster/resources/<resource>[.<group>].yaml. Types the
// cluster does not serve are left out quietly.
func dumpResources(ctx context.Context, c *k8s.Client, st stage, ns string) []ResourceEntry {
	var out []ResourceEntry
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, r := range resources {
		wg.Add(1)
		go func(r resource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, err := listAll(ctx, c, r, ns)
			e := ResourceEntry{Resource: resourceFile(r.gvr), Count: len(items)}
			if err != nil {
				if apierrors.IsNotFound(err) || strings.Contains(err.Error(), "the server could not find the requested resource") {
					return
				}
				e.Error = strutil.FirstLine(err.Error())
			}
			if len(items) > 0 {
				list := map[string]any{"apiVersion": "v1", "kind": "List", "items": items}
				if werr := st.writeYAML("cluster/resources/"+e.Resource+".yaml", list); werr != nil && e.Error == "" {
					e.Error = werr.Error()
				}
			}
			mu.Lock()
			out = append(out, e)
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

func listAll(ctx context.Context, c *k8s.Client, r resource, ns string) ([]map[string]any, error) {
	var ri interface {
		List(context.Context, metav1.ListOptions) (*unstructured.UnstructuredList, error)
	} = c.Dyn.Resource(r.gvr)
	if r.namespaced && ns != "" {
		ri = c.Dyn.Resource(r.gvr).Namespace(ns)
	}
	var items []map[string]any
	opts := metav1.ListOptions{Limit: 500}
	for {
		lctx, cancel := context.WithTimeout(ctx, time.Minute)
		l, err := ri.List(lctx, opts)
		cancel()
		if err != nil {
			return items, err
		}
		for i := range l.Items {
			u := &l.Items[i]
			scrubCommon(u)
			if r.scrub != nil {
				r.scrub(u)
			}
			items = append(items, u.Object)
		}
		if l.GetContinue() == "" {
			return items, nil
		}
		opts.Continue = l.GetContinue()
	}
}

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// scrubCommon drops what only bloats a dump: managedFields, and the
// last-applied annotation (a full copy of the object, Secret data included).
func scrubCommon(u *unstructured.Unstructured) {
	unstructured.RemoveNestedField(u.Object, "metadata", "managedFields")
	if a := u.GetAnnotations(); a != nil {
		delete(a, lastApplied)
		if len(a) == 0 {
			a = nil
		}
		u.SetAnnotations(a)
	}
}

// keysOnly replaces every value of the given maps with its size.
func keysOnly(fields ...string) func(*unstructured.Unstructured) {
	return func(u *unstructured.Unstructured) {
		for _, f := range fields {
			m, ok, _ := unstructured.NestedMap(u.Object, f)
			if !ok {
				continue
			}
			for k, v := range m {
				m[k] = fmt.Sprintf("<value not collected, %d chars>", len(fmt.Sprint(v)))
			}
			_ = unstructured.SetNestedMap(u.Object, m, f)
		}
	}
}

func dropFields(parent string, fields ...string) func(*unstructured.Unstructured) {
	return func(u *unstructured.Unstructured) {
		for _, f := range fields {
			if s, ok, _ := unstructured.NestedString(u.Object, parent, f); ok && s != "" {
				_ = unstructured.SetNestedField(u.Object, fmt.Sprintf("<%d bytes, not collected>", len(s)), parent, f)
			}
		}
	}
}

// dropSchemas keeps a CRD's names, versions and conditions, not its
// OpenAPI schema (most of its size).
func dropSchemas(u *unstructured.Unstructured) {
	vs, ok, _ := unstructured.NestedSlice(u.Object, "spec", "versions")
	if !ok {
		return
	}
	for _, v := range vs {
		if m, ok := v.(map[string]any); ok {
			delete(m, "schema")
		}
	}
	_ = unstructured.SetNestedSlice(u.Object, vs, "spec", "versions")
}

var credName = regexp.MustCompile(`(?i)pass|secret|token|key|cred|auth|private`)

// scrubPodSpec masks literal env values that look like credentials in the
// pod spec at path (containers, init and ephemeral containers).
func scrubPodSpec(path ...string) func(*unstructured.Unstructured) {
	return func(u *unstructured.Unstructured) {
		for _, kind := range []string{"containers", "initContainers", "ephemeralContainers"} {
			p := append(append([]string{}, path...), kind)
			cs, ok, _ := unstructured.NestedSlice(u.Object, p...)
			if !ok {
				continue
			}
			for _, c := range cs {
				cm, ok := c.(map[string]any)
				if !ok {
					continue
				}
				env, _ := cm["env"].([]any)
				for _, e := range env {
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					if name, _ := em["name"].(string); credName.MatchString(name) {
						if _, has := em["value"]; has {
							em["value"] = "<masked>"
						}
					}
				}
			}
			_ = unstructured.SetNestedSlice(u.Object, cs, p...)
		}
	}
}

// apiHealth writes the apiserver's own view: /version, /readyz and /livez.
func apiHealth(ctx context.Context, c *k8s.Client, st stage) []string {
	var errs []string
	rc := c.CS.Discovery().RESTClient()
	for _, p := range []string{"/version", "/readyz?verbose", "/livez?verbose"} {
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		path, query, _ := strings.Cut(p, "?")
		req := rc.Get().AbsPath(path)
		if query != "" {
			req = req.Param(query, "")
		}
		b, err := req.DoRaw(pctx)
		cancel()
		name := "cluster/api/" + strings.TrimPrefix(path, "/") + ".txt"
		if err != nil {
			// /readyz answers 500 with the failing checks in the body
			b = append(b, []byte("\nerror: "+err.Error()+"\n")...)
			errs = append(errs, p+": "+strutil.FirstLine(err.Error()))
		}
		_ = st.write(name, b)
	}
	return errs
}

// PodLogStats counts the pod logs fetched through the API.
type PodLogStats struct {
	Pods       int      `json:"pods"`
	Containers int      `json:"containers"`
	Previous   int      `json:"previous"`
	Bytes      int64    `json:"bytes"`
	Errors     []string `json:"errors,omitempty"`
}

// needsLogs picks the pods of a cluster-scope bundle: every pod of a system
// namespace, and anywhere else the ones not running cleanly or restarted
// within the window.
func needsLogs(p *corev1.Pod, since time.Time) bool {
	if k8s.IsSystemNamespace(p.Namespace) {
		return true
	}
	switch p.Status.Phase {
	case corev1.PodPending, corev1.PodFailed, corev1.PodUnknown:
		return true
	case corev1.PodSucceeded:
		return false
	}
	if p.DeletionTimestamp != nil {
		return true
	}
	for _, s := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if s.State.Waiting != nil {
			return true
		}
		if s.State.Running != nil && !s.Ready && !isInit(p, s.Name) {
			return true
		}
		if t := s.LastTerminationState.Terminated; t != nil && t.FinishedAt.After(since) {
			return true
		}
	}
	return false
}

func isInit(p *corev1.Pod, name string) bool {
	for _, c := range p.Spec.InitContainers {
		if c.Name == name {
			return true
		}
	}
	return false
}

// podLogs fetches the current log (within the window) and, for containers
// that restarted, the previous one, of every container of pods, into
// cluster/pods/<ns>/<pod>/<container>[.previous].log. The API returns the
// oldest bytes of a limited read, so the tail is asked by line count and
// trimmed to the newest capBytes here.
func podLogs(ctx context.Context, c *k8s.Client, st stage, pods []corev1.Pod, since time.Duration, capBytes int64) PodLogStats {
	var stats PodLogStats
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	sinceSec := int64(since.Seconds())
	tail := max(capBytes/120, 1000)
	limit := capBytes * 2
	fetch := func(p *corev1.Pod, container string, previous bool) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		opts := &corev1.PodLogOptions{Container: container, Timestamps: true, TailLines: &tail, LimitBytes: &limit, Previous: previous}
		if !previous {
			opts.SinceSeconds = &sinceSec
		}
		lctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		rc, err := c.CS.CoreV1().Pods(p.Namespace).GetLogs(p.Name, opts).Stream(lctx)
		var b []byte
		if err == nil {
			b, err = io.ReadAll(rc)
			rc.Close()
		}
		name := container
		if previous {
			name += ".previous"
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if len(stats.Errors) < 50 {
				stats.Errors = append(stats.Errors, fmt.Sprintf("%s/%s %s: %s", p.Namespace, p.Name, name, strutil.FirstLine(err.Error())))
			}
			return
		}
		// the kubelet answers 200 with this text when the container's log
		// file is gone (container removed, log rotated away): not a log
		if bytes.HasPrefix(bytes.TrimSpace(b), []byte("unable to retrieve container logs")) {
			if len(stats.Errors) < 50 {
				stats.Errors = append(stats.Errors, fmt.Sprintf("%s/%s %s: %s", p.Namespace, p.Name, name, strutil.FirstLine(string(b))))
			}
			return
		}
		b = newest(b, capBytes)
		if werr := st.write(fmt.Sprintf("cluster/pods/%s/%s/%s.log", p.Namespace, p.Name, name), b); werr == nil {
			stats.Bytes += int64(len(b))
			stats.Containers++
			if previous {
				stats.Previous++
			}
		}
	}
	for i := range pods {
		p := &pods[i]
		stats.Pods++
		restarted := map[string]bool{}
		for _, s := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			restarted[s.Name] = s.RestartCount > 0 || s.LastTerminationState.Terminated != nil
		}
		for _, ctr := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			wg.Add(1)
			go fetch(p, ctr.Name, false)
			if restarted[ctr.Name] {
				wg.Add(1)
				go fetch(p, ctr.Name, true)
			}
		}
	}
	wg.Wait()
	sort.Strings(stats.Errors)
	return stats
}

// newest keeps the last n bytes of b, from the first full line.
func newest(b []byte, n int64) []byte {
	if int64(len(b)) <= n {
		return b
	}
	b = b[int64(len(b))-n:]
	if i := strings.IndexByte(string(b[:min(len(b), 64<<10)]), '\n'); i >= 0 {
		b = b[i+1:]
	}
	return b
}

// WorkloadInfo is what --gather-workload resolved to.
type WorkloadInfo struct {
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Selector  string   `json:"selector,omitempty"`
	Pods      []string `json:"pods"`
	Nodes     []string `json:"nodes"`
}

var workloadKinds = map[string]struct {
	kind string
	gvr  schema.GroupVersionResource
}{
	"deploy": {"Deployment", gvr("apps", "v1", "deployments")}, "deployment": {"Deployment", gvr("apps", "v1", "deployments")},
	"sts": {"StatefulSet", gvr("apps", "v1", "statefulsets")}, "statefulset": {"StatefulSet", gvr("apps", "v1", "statefulsets")},
	"ds": {"DaemonSet", gvr("apps", "v1", "daemonsets")}, "daemonset": {"DaemonSet", gvr("apps", "v1", "daemonsets")},
	"rs": {"ReplicaSet", gvr("apps", "v1", "replicasets")}, "replicaset": {"ReplicaSet", gvr("apps", "v1", "replicasets")},
	"job": {"Job", gvr("batch", "v1", "jobs")},
	"cj":  {"CronJob", gvr("batch", "v1", "cronjobs")}, "cronjob": {"CronJob", gvr("batch", "v1", "cronjobs")},
	"po": {"Pod", gvr("", "v1", "pods")}, "pod": {"Pod", gvr("", "v1", "pods")},
}

// parseWorkload splits namespace/kind/name (kind as kubectl abbreviates it,
// singular or plural).
func parseWorkload(ref string) (ns, kind, name string, err error) {
	parts := strings.Split(ref, "/")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("--gather-workload %q: want namespace/kind/name, e.g. shop/deploy/web", ref)
	}
	k := strings.ToLower(parts[1])
	if _, ok := workloadKinds[k]; !ok {
		k = strings.TrimSuffix(k, "s")
	}
	if _, ok := workloadKinds[k]; !ok {
		return "", "", "", fmt.Errorf("--gather-workload %q: kind %q is not deploy, sts, ds, rs, job, cronjob or pod", ref, parts[1])
	}
	return parts[0], k, parts[2], nil
}

// resolveWorkload finds the pods a workload owns: through its selector
// (every revision's pods, not only the current ReplicaSet's), for a
// CronJob through the Jobs it created.
func resolveWorkload(ctx context.Context, c *k8s.Client, ref string) (*WorkloadInfo, []corev1.Pod, error) {
	ns, k, name, err := parseWorkload(ref)
	if err != nil {
		return nil, nil, err
	}
	wk := workloadKinds[k]
	w := &WorkloadInfo{Namespace: ns, Kind: wk.kind, Name: name}
	obj, err := c.Dyn.Resource(wk.gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s/%s: %w", wk.kind, ns, name, err)
	}
	var pods []corev1.Pod
	switch wk.kind {
	case "Pod":
		var p corev1.Pod
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &p); err != nil {
			return nil, nil, err
		}
		pods = []corev1.Pod{p}
	case "CronJob":
		jobs, err := c.CS.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		owned := map[string]bool{}
		for _, j := range jobs.Items {
			for _, o := range j.OwnerReferences {
				if o.UID == obj.GetUID() {
					owned[string(j.UID)] = true
				}
			}
		}
		all, err := c.CS.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, p := range all.Items {
			for _, o := range p.OwnerReferences {
				if owned[string(o.UID)] {
					pods = append(pods, p)
					break
				}
			}
		}
	default:
		m, ok, _ := unstructured.NestedMap(obj.Object, "spec", "selector")
		if !ok {
			return nil, nil, fmt.Errorf("%s %s/%s has no spec.selector", wk.kind, ns, name)
		}
		var ls metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, &ls); err != nil {
			return nil, nil, err
		}
		sel, err := metav1.LabelSelectorAsSelector(&ls)
		if err != nil {
			return nil, nil, err
		}
		if sel.Empty() {
			return nil, nil, errors.New("empty selector: would match every pod in the namespace")
		}
		w.Selector = sel.String()
		l, err := c.CS.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
		if err != nil {
			return nil, nil, err
		}
		pods = l.Items
	}
	nodes := map[string]bool{}
	for _, p := range pods {
		w.Pods = append(w.Pods, p.Name)
		if p.Spec.NodeName != "" {
			nodes[p.Spec.NodeName] = true
		}
	}
	for n := range nodes {
		w.Nodes = append(w.Nodes, n)
	}
	sort.Strings(w.Pods)
	sort.Strings(w.Nodes)
	return w, pods, nil
}
