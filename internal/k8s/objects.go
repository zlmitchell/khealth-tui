package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"
)

// ObjRef points at another API object and says how it is related.
type ObjRef struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Via        string // owner, child, volume, env, envFrom, imagePullSecret, serviceAccount, node, field:<path>
}

// Key returns kind/ns/name for de-duplication.
func (r ObjRef) Key() string { return r.Kind + "/" + r.Namespace + "/" + r.Name }

// CRDInfo summarizes an API resource type: a CustomResourceDefinition or a
// built-in resource discovered from the API server.
type CRDInfo struct {
	Name        string // plural.group (plural for core)
	Group       string
	Kind        string
	Plural      string
	Scope       string // Namespaced | Cluster
	Versions    []string
	Storage     string // storage/preferred version
	Established bool
	Problems    []string // non-True conditions (CRDs)
	Count       int      // -1 = unknown
	Created     time.Time
	Custom      bool // defined by a CRD
}

// GVR returns the resource for the storage version.
func (c CRDInfo) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: c.Group, Version: c.Storage, Resource: c.Plural}
}

func (c *Client) mapper() meta.RESTMapper {
	c.mapperOnce.Do(func() {
		c.restMapper = restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(c.CS.Discovery()))
	})
	return c.restMapper
}

// gvrFor resolves apiVersion + kind to a resource using discovery.
func (c *Client) gvrFor(apiVersion, kind string) (schema.GroupVersionResource, bool, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}
	m, err := c.mapper().RESTMapping(schema.GroupKind{Group: gv.Group, Kind: kind}, gv.Version)
	if err != nil {
		// stale cache after a CRD was added: reset and retry once
		if d, ok := c.restMapper.(*restmapper.DeferredDiscoveryRESTMapper); ok {
			d.Reset()
			m, err = c.mapper().RESTMapping(schema.GroupKind{Group: gv.Group, Kind: kind}, gv.Version)
		}
		if err != nil {
			return schema.GroupVersionResource{}, false, err
		}
	}
	return m.Resource, m.Scope.Name() == meta.RESTScopeNameNamespace, nil
}

// GetObject fetches any object (core or custom) by apiVersion/kind/ns/name.
func (c *Client) GetObject(ctx context.Context, ref ObjRef) (*unstructured.Unstructured, error) {
	apiVersion := ref.APIVersion
	if apiVersion == "" {
		apiVersion = defaultAPIVersion(ref.Kind)
	}
	gvr, namespaced, err := c.gvrFor(apiVersion, ref.Kind)
	if err != nil {
		return nil, fmt.Errorf("resolve %s %s: %w", apiVersion, ref.Kind, err)
	}
	if namespaced {
		return c.Dyn.Resource(gvr).Namespace(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	}
	return c.Dyn.Resource(gvr).Get(ctx, ref.Name, metav1.GetOptions{})
}

// defaultAPIVersion maps well-known kinds referenced by name only.
func defaultAPIVersion(kind string) string {
	switch kind {
	case "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet":
		return "apps/v1"
	case "Job", "CronJob":
		return "batch/v1"
	case "Ingress", "NetworkPolicy":
		return "networking.k8s.io/v1"
	case "StorageClass", "CSIDriver", "VolumeAttachment":
		return "storage.k8s.io/v1"
	case "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding":
		return "rbac.authorization.k8s.io/v1"
	case "PriorityClass":
		return "scheduling.k8s.io/v1"
	case "HorizontalPodAutoscaler":
		return "autoscaling/v2"
	case "PodDisruptionBudget":
		return "policy/v1"
	case "HelmChart", "HelmChartConfig":
		return "helm.cattle.io/v1"
	case "Addon", "ETCDSnapshotFile":
		return "k3s.cattle.io/v1"
	}
	return "v1"
}

// ToUnstructured converts a typed object.
func ToUnstructured(obj runtime.Object) (*unstructured.Unstructured, error) {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	u := &unstructured.Unstructured{Object: m}
	if u.GetAPIVersion() == "" {
		gvk := obj.GetObjectKind().GroupVersionKind()
		if gvk.Kind == "" {
			switch obj.(type) {
			default:
				gvk = schema.GroupVersionKind{Version: "v1", Kind: strings.TrimPrefix(fmt.Sprintf("%T", obj), "*v1.")}
			}
		}
		u.SetAPIVersion(gvk.GroupVersion().String())
		u.SetKind(gvk.Kind)
	}
	return u, nil
}

// DumpYAML renders an object for display: managedFields dropped, Secret data
// replaced by key names and sizes, very long values truncated.
func DumpYAML(u *unstructured.Unstructured) string {
	if u == nil {
		return ""
	}
	obj := u.DeepCopy().Object
	if md, ok := obj["metadata"].(map[string]any); ok {
		delete(md, "managedFields")
	}
	if u.GetKind() == "Secret" {
		if data, ok := obj["data"].(map[string]any); ok {
			masked := map[string]any{}
			for k, v := range data {
				s, _ := v.(string)
				masked[k] = fmt.Sprintf("<%d bytes base64, masked>", len(s))
			}
			obj["data"] = masked
		}
		delete(obj, "stringData")
	}
	truncateLong(obj, 0)
	b, err := yaml.Marshal(obj)
	if err != nil {
		return fmt.Sprintf("%v", obj)
	}
	return string(b)
}

func truncateLong(v any, depth int) {
	if depth > 40 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if s, ok := x.(string); ok && len(s) > 4000 {
				t[k] = s[:4000] + fmt.Sprintf("... <%d more bytes>", len(s)-4000)
				continue
			}
			truncateLong(x, depth+1)
		}
	case []any:
		for i, x := range t {
			if s, ok := x.(string); ok && len(s) > 4000 {
				t[i] = s[:4000] + fmt.Sprintf("... <%d more bytes>", len(s)-4000)
				continue
			}
			truncateLong(x, depth+1)
		}
	}
}

// ExtractRefs finds objects an object refers to: owner references, and
// well-known name fields (secrets, configmaps, claims, service accounts) plus
// typed {kind,name} references anywhere in the spec (common in CRs).
func ExtractRefs(u *unstructured.Unstructured) []ObjRef {
	if u == nil {
		return nil
	}
	ns := u.GetNamespace()
	var refs []ObjRef
	seen := map[string]bool{}
	add := func(r ObjRef) {
		if r.Name == "" || r.Kind == "" {
			return
		}
		if r.Namespace == "" && isNamespacedKind(r.Kind) {
			r.Namespace = ns
		}
		if seen[r.Key()+r.Via] {
			return
		}
		seen[r.Key()+r.Via] = true
		refs = append(refs, r)
	}
	for _, o := range u.GetOwnerReferences() {
		add(ObjRef{APIVersion: o.APIVersion, Kind: o.Kind, Namespace: ns, Name: o.Name, Via: "owner"})
	}
	if u.GetKind() == "Pod" {
		podRefs(u, add)
	}
	walkRefs(u.Object, "", add, 0)
	if node, ok, _ := unstructured.NestedString(u.Object, "spec", "nodeName"); ok && node != "" {
		add(ObjRef{APIVersion: "v1", Kind: "Node", Name: node, Via: "node"})
	}
	if sc, ok, _ := unstructured.NestedString(u.Object, "spec", "storageClassName"); ok && sc != "" {
		add(ObjRef{APIVersion: "storage.k8s.io/v1", Kind: "StorageClass", Name: sc, Via: "storageClass"})
	}
	if vol, ok, _ := unstructured.NestedString(u.Object, "spec", "volumeName"); ok && vol != "" && u.GetKind() == "PersistentVolumeClaim" {
		add(ObjRef{APIVersion: "v1", Kind: "PersistentVolume", Name: vol, Via: "volume"})
	}
	if u.GetKind() == "PersistentVolume" {
		if cr, ok, _ := unstructured.NestedMap(u.Object, "spec", "claimRef"); ok {
			n, _ := cr["name"].(string)
			cns, _ := cr["namespace"].(string)
			add(ObjRef{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: cns, Name: n, Via: "claim"})
		}
	}
	sort.SliceStable(refs, func(i, j int) bool { return viaRank(refs[i].Via) < viaRank(refs[j].Via) })
	return refs
}

func viaRank(v string) int {
	switch {
	case v == "owner":
		return 0
	case v == "child":
		return 1
	case strings.HasPrefix(v, "field:"):
		return 5
	}
	return 2
}

func podRefs(u *unstructured.Unstructured, add func(ObjRef)) {
	if sa, ok, _ := unstructured.NestedString(u.Object, "spec", "serviceAccountName"); ok && sa != "" {
		add(ObjRef{APIVersion: "v1", Kind: "ServiceAccount", Name: sa, Via: "serviceAccount"})
	}
	if pc, ok, _ := unstructured.NestedString(u.Object, "spec", "priorityClassName"); ok && pc != "" {
		add(ObjRef{APIVersion: "scheduling.k8s.io/v1", Kind: "PriorityClass", Name: pc, Via: "priorityClass"})
	}
	if ips, ok, _ := unstructured.NestedSlice(u.Object, "spec", "imagePullSecrets"); ok {
		for _, x := range ips {
			if m, ok := x.(map[string]any); ok {
				n, _ := m["name"].(string)
				add(ObjRef{APIVersion: "v1", Kind: "Secret", Name: n, Via: "imagePullSecret"})
			}
		}
	}
	vols, _, _ := unstructured.NestedSlice(u.Object, "spec", "volumes")
	for _, x := range vols {
		v, _ := x.(map[string]any)
		vname, _ := v["name"].(string)
		via := "volume " + vname
		if s, ok := v["secret"].(map[string]any); ok {
			n, _ := s["secretName"].(string)
			add(ObjRef{APIVersion: "v1", Kind: "Secret", Name: n, Via: via})
		}
		if cm, ok := v["configMap"].(map[string]any); ok {
			n, _ := cm["name"].(string)
			add(ObjRef{APIVersion: "v1", Kind: "ConfigMap", Name: n, Via: via})
		}
		if pvc, ok := v["persistentVolumeClaim"].(map[string]any); ok {
			n, _ := pvc["claimName"].(string)
			add(ObjRef{APIVersion: "v1", Kind: "PersistentVolumeClaim", Name: n, Via: via})
		}
		if pr, ok := v["projected"].(map[string]any); ok {
			srcs, _ := pr["sources"].([]any)
			for _, sx := range srcs {
				sm, _ := sx.(map[string]any)
				if s, ok := sm["secret"].(map[string]any); ok {
					n, _ := s["name"].(string)
					add(ObjRef{APIVersion: "v1", Kind: "Secret", Name: n, Via: via})
				}
				if cm, ok := sm["configMap"].(map[string]any); ok {
					n, _ := cm["name"].(string)
					add(ObjRef{APIVersion: "v1", Kind: "ConfigMap", Name: n, Via: via})
				}
			}
		}
	}
	for _, field := range []string{"initContainers", "containers"} {
		cs, _, _ := unstructured.NestedSlice(u.Object, "spec", field)
		for _, cx := range cs {
			c, _ := cx.(map[string]any)
			cname, _ := c["name"].(string)
			envs, _ := c["env"].([]any)
			for _, ex := range envs {
				e, _ := ex.(map[string]any)
				vf, _ := e["valueFrom"].(map[string]any)
				if s, ok := vf["secretKeyRef"].(map[string]any); ok {
					n, _ := s["name"].(string)
					add(ObjRef{APIVersion: "v1", Kind: "Secret", Name: n, Via: "env " + cname})
				}
				if cm, ok := vf["configMapKeyRef"].(map[string]any); ok {
					n, _ := cm["name"].(string)
					add(ObjRef{APIVersion: "v1", Kind: "ConfigMap", Name: n, Via: "env " + cname})
				}
			}
			efs, _ := c["envFrom"].([]any)
			for _, ex := range efs {
				e, _ := ex.(map[string]any)
				if s, ok := e["secretRef"].(map[string]any); ok {
					n, _ := s["name"].(string)
					add(ObjRef{APIVersion: "v1", Kind: "Secret", Name: n, Via: "envFrom " + cname})
				}
				if cm, ok := e["configMapRef"].(map[string]any); ok {
					n, _ := cm["name"].(string)
					add(ObjRef{APIVersion: "v1", Kind: "ConfigMap", Name: n, Via: "envFrom " + cname})
				}
			}
		}
	}
}

// walkRefs scans arbitrary specs (CRs) for reference-shaped fields.
func walkRefs(v any, path string, add func(ObjRef), depth int) {
	if depth > 25 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		// typed reference: {kind, name[, apiVersion][, namespace]}
		if k, ok := t["kind"].(string); ok && k != "" {
			if n, ok := t["name"].(string); ok && n != "" && path != "" && !strings.HasSuffix(path, "ownerReferences") {
				av, _ := t["apiVersion"].(string)
				nsv, _ := t["namespace"].(string)
				add(ObjRef{APIVersion: av, Kind: k, Namespace: nsv, Name: n, Via: "field:" + path})
			}
		}
		for key, x := range t {
			p := key
			if path != "" {
				p = path + "." + key
			}
			if strings.HasPrefix(p, "metadata") || strings.HasPrefix(p, "status.") && depth > 3 {
				continue
			}
			lk := strings.ToLower(key)
			name := ""
			nsv := ""
			switch xv := x.(type) {
			case string:
				name = xv
			case map[string]any:
				name, _ = xv["name"].(string)
				nsv, _ = xv["namespace"].(string)
			}
			kind := ""
			switch {
			case lk == "secretname" || lk == "secretref" || lk == "secretkeyref" || lk == "tlssecret" || lk == "existingsecret" || lk == "credentialssecret" || strings.HasSuffix(lk, "secretname") || strings.HasSuffix(lk, "secretref"):
				kind = "Secret"
			case lk == "configmapref" || lk == "configmapkeyref" || lk == "configmapname" || strings.HasSuffix(lk, "configmapname") || strings.HasSuffix(lk, "configmapref"):
				kind = "ConfigMap"
			case lk == "claimname" || lk == "persistentvolumeclaim" || lk == "pvcname":
				kind = "PersistentVolumeClaim"
			case lk == "serviceaccountname" || lk == "serviceaccount":
				kind = "ServiceAccount"
			case lk == "storageclassname":
				kind = "StorageClass"
			case lk == "servicename":
				kind = "Service"
			case lk == "ingressclassname":
				kind = "IngressClass"
			}
			if kind != "" && name != "" {
				add(ObjRef{Kind: kind, Namespace: nsv, Name: name, Via: "field:" + p})
			}
			walkRefs(x, p, add, depth+1)
		}
	case []any:
		for i, x := range t {
			walkRefs(x, fmt.Sprintf("%s[%d]", path, i), add, depth+1)
		}
	}
}

func isNamespacedKind(kind string) bool {
	switch kind {
	case "Node", "PersistentVolume", "StorageClass", "ClusterRole", "ClusterRoleBinding", "Namespace", "CustomResourceDefinition", "PriorityClass", "IngressClass", "CSIDriver", "CSINode", "ETCDSnapshotFile":
		return false
	}
	return true
}

// Children finds objects in the snapshot owned by uid (controller chains).
func (s *Snapshot) Children(uid types.UID) []ObjRef {
	var out []ObjRef
	owned := func(refs []metav1.OwnerReference) bool {
		for _, o := range refs {
			if o.UID == uid {
				return true
			}
		}
		return false
	}
	for i := range s.Pods {
		if owned(s.Pods[i].OwnerReferences) {
			out = append(out, ObjRef{APIVersion: "v1", Kind: "Pod", Namespace: s.Pods[i].Namespace, Name: s.Pods[i].Name, Via: "child"})
		}
	}
	for i := range s.Deployments {
		if owned(s.Deployments[i].OwnerReferences) {
			out = append(out, ObjRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: s.Deployments[i].Namespace, Name: s.Deployments[i].Name, Via: "child"})
		}
	}
	for i := range s.DaemonSets {
		if owned(s.DaemonSets[i].OwnerReferences) {
			out = append(out, ObjRef{APIVersion: "apps/v1", Kind: "DaemonSet", Namespace: s.DaemonSets[i].Namespace, Name: s.DaemonSets[i].Name, Via: "child"})
		}
	}
	for i := range s.StatefulSets {
		if owned(s.StatefulSets[i].OwnerReferences) {
			out = append(out, ObjRef{APIVersion: "apps/v1", Kind: "StatefulSet", Namespace: s.StatefulSets[i].Namespace, Name: s.StatefulSets[i].Name, Via: "child"})
		}
	}
	for i := range s.Jobs {
		if owned(s.Jobs[i].OwnerReferences) {
			out = append(out, ObjRef{APIVersion: "batch/v1", Kind: "Job", Namespace: s.Jobs[i].Namespace, Name: s.Jobs[i].Name, Via: "child"})
		}
	}
	for i := range s.PVCs {
		if owned(s.PVCs[i].OwnerReferences) {
			out = append(out, ObjRef{APIVersion: "v1", Kind: "PersistentVolumeClaim", Namespace: s.PVCs[i].Namespace, Name: s.PVCs[i].Name, Via: "child"})
		}
	}
	return out
}

// ChildrenOf lists objects of a resource owned by uid (for ReplicaSets etc.
// that the snapshot does not hold).
func (c *Client) ChildrenOf(ctx context.Context, gvr schema.GroupVersionResource, ns string, uid types.UID) ([]ObjRef, error) {
	l, err := c.Dyn.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []ObjRef
	for _, it := range l.Items {
		for _, o := range it.GetOwnerReferences() {
			if o.UID == uid {
				out = append(out, ObjRef{APIVersion: it.GetAPIVersion(), Kind: it.GetKind(), Namespace: it.GetNamespace(), Name: it.GetName(), Via: "child"})
			}
		}
	}
	return out, nil
}

var crdGVR = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}

// ListCRDs returns all CustomResourceDefinitions (without instance counts).
func (c *Client) ListCRDs(ctx context.Context) ([]CRDInfo, error) {
	l, err := c.dynList(ctx, "customresourcedefinitions", crdGVR)
	if err != nil {
		return nil, err
	}
	out := make([]CRDInfo, 0, len(l.Items))
	for _, it := range l.Items {
		info := CRDInfo{Name: it.GetName(), Count: -1, Created: it.GetCreationTimestamp().Time}
		info.Group, _, _ = unstructured.NestedString(it.Object, "spec", "group")
		info.Kind, _, _ = unstructured.NestedString(it.Object, "spec", "names", "kind")
		info.Plural, _, _ = unstructured.NestedString(it.Object, "spec", "names", "plural")
		info.Scope, _, _ = unstructured.NestedString(it.Object, "spec", "scope")
		vers, _, _ := unstructured.NestedSlice(it.Object, "spec", "versions")
		for _, vx := range vers {
			v, _ := vx.(map[string]any)
			name, _ := v["name"].(string)
			if served, _ := v["served"].(bool); served {
				info.Versions = append(info.Versions, name)
			}
			if storage, _ := v["storage"].(bool); storage {
				info.Storage = name
			}
		}
		if info.Storage == "" && len(info.Versions) > 0 {
			info.Storage = info.Versions[0]
		}
		conds, _, _ := unstructured.NestedSlice(it.Object, "status", "conditions")
		for _, cx := range conds {
			cm, _ := cx.(map[string]any)
			t, _ := cm["type"].(string)
			st, _ := cm["status"].(string)
			if t == "Established" && st == "True" {
				info.Established = true
			}
			if (t == "Established" || t == "NamesAccepted") && st != "True" {
				msg, _ := cm["message"].(string)
				info.Problems = append(info.Problems, t+": "+msg)
			}
			if t == "Terminating" && st == "True" {
				info.Problems = append(info.Problems, "Terminating")
			}
			if t == "NonStructuralSchema" && st == "True" {
				info.Problems = append(info.Problems, "NonStructuralSchema")
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListResources returns every listable API resource type (built-in and
// custom), with CRD status merged in for the custom ones.
func (c *Client) ListResources(ctx context.Context) ([]CRDInfo, error) {
	lists, err := c.CS.Discovery().ServerPreferredResources()
	if err != nil && len(lists) == 0 {
		return nil, err
	}
	crds, _ := c.ListCRDs(ctx)
	byName := map[string]CRDInfo{}
	for _, cr := range crds {
		byName[cr.Name] = cr
	}
	var out []CRDInfo
	seen := map[string]bool{}
	for _, l := range lists {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range l.APIResources {
			if strings.Contains(r.Name, "/") || !hasVerb(r.Verbs, "list") || !hasVerb(r.Verbs, "get") {
				continue
			}
			name := r.Name
			if gv.Group != "" {
				name = r.Name + "." + gv.Group
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			info := CRDInfo{Name: name, Group: gv.Group, Kind: r.Kind, Plural: r.Name, Storage: gv.Version, Versions: []string{gv.Version}, Scope: "Cluster", Count: -1, Established: true}
			if r.Namespaced {
				info.Scope = "Namespaced"
			}
			if cr, ok := byName[name]; ok {
				info.Custom = true
				info.Versions = cr.Versions
				info.Storage = cr.Storage
				info.Established = cr.Established
				info.Problems = cr.Problems
				info.Created = cr.Created
			}
			out = append(out, info)
		}
	}
	// CRDs that discovery did not list (not established) still deserve a row
	for _, cr := range crds {
		if !seen[cr.Name] {
			cr.Custom = true
			out = append(out, cr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

func hasVerb(verbs []string, v string) bool {
	for _, x := range verbs {
		if x == v {
			return true
		}
	}
	return false
}

// CountCRs fills Count for each CRD using limit=1 list calls (parallel).
func (c *Client) CountCRs(ctx context.Context, crds []CRDInfo) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range crds {
		wg.Add(1)
		go func(info *CRDInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			l, err := c.Dyn.Resource(info.GVR()).List(ctx, metav1.ListOptions{Limit: 1})
			if err != nil {
				info.Count = -1
				return
			}
			n := int64(len(l.Items))
			if r := l.GetRemainingItemCount(); r != nil {
				n += *r
			}
			info.Count = int(n)
		}(&crds[i])
	}
	wg.Wait()
}

// CRInstance is one custom resource row.
type CRInstance struct {
	Namespace string
	Name      string
	Created   time.Time
	Phase     string
	Ready     string // condition summary
	Bad       bool
}

// ListCRs lists instances of a CRD (capped).
func (c *Client) ListCRs(ctx context.Context, info CRDInfo, limit int64) ([]CRInstance, error) {
	l, err := c.Dyn.Resource(info.GVR()).List(ctx, metav1.ListOptions{Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]CRInstance, 0, len(l.Items))
	for _, it := range l.Items {
		ci := CRInstance{Namespace: it.GetNamespace(), Name: it.GetName(), Created: it.GetCreationTimestamp().Time}
		ci.Phase, _, _ = unstructured.NestedString(it.Object, "status", "phase")
		if ci.Phase == "" {
			ci.Phase, _, _ = unstructured.NestedString(it.Object, "status", "state")
		}
		ci.Ready, ci.Bad = ConditionSummary(it.Object)
		if it.GetDeletionTimestamp() != nil {
			ci.Phase = "Terminating"
			ci.Bad = true
		}
		out = append(out, ci)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// ConditionSummary renders status.conditions compactly and flags failures.
func ConditionSummary(obj map[string]any) (string, bool) {
	conds, ok, _ := unstructured.NestedSlice(obj, "status", "conditions")
	if !ok || len(conds) == 0 {
		return "", false
	}
	var parts []string
	bad := false
	for _, cx := range conds {
		cm, _ := cx.(map[string]any)
		t, _ := cm["type"].(string)
		st, _ := cm["status"].(string)
		positive := t == "Ready" || t == "Available" || t == "Established" || t == "Healthy" || t == "Progressing" || t == "Installed" || t == "Deployed" || t == "Synced" || t == "Initialized" || t == "Succeeded" || t == "Complete" || t == "Accepted" || t == "Reconciled" || t == "Applied" || t == "Processed"
		negative := t == "Degraded" || t == "Failed" || t == "Error" || t == "Stalled" || t == "ReconcileError" || t == "Terminating"
		switch {
		case positive && st != "True":
			bad = true
			parts = append(parts, t+"=false")
		case negative && st == "True":
			bad = true
			parts = append(parts, t)
		case positive:
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, ","), bad
}
