package k8s

import (
	"context"
	"net/http"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func crd(name, group, kind, plural, scope string, versions []map[string]any, conds ...map[string]any) map[string]any {
	var vs []any
	for _, v := range versions {
		vs = append(vs, v)
	}
	var cs []any
	for _, c := range conds {
		cs = append(cs, c)
	}
	body := map[string]any{"spec": map[string]any{"group": group, "scope": scope, "names": map[string]any{"kind": kind, "plural": plural}, "versions": vs}}
	if len(cs) > 0 {
		body["status"] = map[string]any{"conditions": cs}
	}
	o := uobj("", name, body)
	o["metadata"].(map[string]any)["creationTimestamp"] = "2026-01-02T03:04:05Z"
	return o
}

func TestListCRDsAndResources(t *testing.T) {
	f := newFakeAPI(t)
	f.set("/apis/apiextensions.k8s.io/v1/customresourcedefinitions", ulist("apiextensions.k8s.io/v1", "CustomResourceDefinition",
		crd("helmcharts.helm.cattle.io", "helm.cattle.io", "HelmChart", "helmcharts", "Namespaced",
			[]map[string]any{{"name": "v1", "served": true, "storage": true}, {"name": "v1beta1", "served": true, "storage": false}, {"name": "v1alpha1", "served": false}},
			map[string]any{"type": "Established", "status": "True"}, map[string]any{"type": "NamesAccepted", "status": "True"}),
		crd("broken.example.com", "example.com", "Broken", "brokens", "Cluster",
			[]map[string]any{{"name": "v2", "served": true}},
			map[string]any{"type": "Established", "status": "False", "message": "not established"}, map[string]any{"type": "NamesAccepted", "status": "False", "message": "conflict"},
			map[string]any{"type": "Terminating", "status": "True"}, map[string]any{"type": "NonStructuralSchema", "status": "True"}),
	))
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	crds, err := c.ListCRDs(ctx)
	if err != nil || len(crds) != 2 {
		t.Fatalf("crds: %v %+v", err, crds)
	}
	if b := crds[0]; b.Name != "broken.example.com" || b.Established || b.Storage != "v2" || len(b.Problems) != 4 || b.Problems[0] != "Established: not established" || b.Problems[2] != "Terminating" || b.Count != -1 || b.Created.Year() != 2026 {
		t.Errorf("broken crd: %+v", b)
	}
	if h := crds[1]; !h.Established || h.Storage != "v1" || len(h.Versions) != 2 || h.Scope != "Namespaced" || h.GVR() != (schema.GroupVersionResource{Group: "helm.cattle.io", Version: "v1", Resource: "helmcharts"}) {
		t.Errorf("helmcharts crd: %+v", h)
	}

	all, err := c.ListResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]CRDInfo{}
	for i := 1; i < len(all); i++ {
		a, b := all[i-1], all[i]
		if a.Group > b.Group || (a.Group == b.Group && a.Kind > b.Kind) {
			t.Errorf("not sorted by group/kind: %s/%s before %s/%s", a.Group, a.Kind, b.Group, b.Kind)
		}
	}
	for _, r := range all {
		byName[r.Name] = r
	}
	if p, ok := byName["pods"]; !ok || p.Custom || p.Scope != "Namespaced" || p.Kind != "Pod" || p.Storage != "v1" || !p.Established {
		t.Errorf("built-in pods: %+v", p)
	}
	if n := byName["nodes"]; n.Scope != "Cluster" {
		t.Errorf("nodes scope: %+v", n)
	}
	if _, ok := byName["pods/log"]; ok {
		t.Error("subresources must be skipped")
	}
	if _, ok := byName["bindings"]; ok {
		t.Error("non-listable resources must be skipped")
	}
	if h := byName["helmcharts.helm.cattle.io"]; !h.Custom || len(h.Versions) != 2 || !h.Established || h.Created.IsZero() {
		t.Errorf("custom merged with discovery: %+v", h)
	}
	if b, ok := byName["broken.example.com"]; !ok || !b.Custom || b.Established {
		t.Errorf("CRD absent from discovery still listed: %+v", b)
	}

	// discovery failing entirely is an error; CRDs alone are not
	f.denyWith("/api", http.StatusInternalServerError)
	f.denyWith("/apis", http.StatusInternalServerError)
	c2 := f.client(t, DefaultOptions())
	if _, err := c2.ListResources(ctx); err == nil {
		t.Error("discovery failure must error")
	}
	f.denyWith("/apis/apiextensions.k8s.io/v1/customresourcedefinitions", http.StatusForbidden)
	if _, err := c.ListCRDs(ctx); err == nil {
		t.Error("forbidden CRD list must error")
	}
}

func TestCountAndListCRs(t *testing.T) {
	f := newFakeAPI(t)
	l := ulist("helm.cattle.io/v1", "HelmChart", uobj("kube-system", "rke2-canal", map[string]any{"status": map[string]any{"phase": "Deployed", "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}))
	l["metadata"] = map[string]any{"resourceVersion": "1", "remainingItemCount": int64(41)}
	f.set("/apis/helm.cattle.io/v1/helmcharts", l)
	f.set("/apis/k3s.cattle.io/v1/etcdsnapshotfiles", ulist("k3s.cattle.io/v1", "ETCDSnapshotFile",
		uobj("", "b-terminating", map[string]any{"status": map[string]any{"state": "Uploaded"}}),
		uobj("", "a-failed", map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False"}, map[string]any{"type": "Failed", "status": "True"}}}}),
	))
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	crds := []CRDInfo{
		{Name: "helmcharts.helm.cattle.io", Group: "helm.cattle.io", Storage: "v1", Plural: "helmcharts"},
		{Name: "etcdsnapshotfiles.k3s.cattle.io", Group: "k3s.cattle.io", Storage: "v1", Plural: "etcdsnapshotfiles"},
		{Name: "missing.example.com", Group: "example.com", Storage: "v1", Plural: "missings", Count: 7},
	}
	c.CountCRs(ctx, crds)
	if crds[0].Count != 42 || crds[1].Count != 2 || crds[2].Count != -1 {
		t.Errorf("counts: %d %d %d", crds[0].Count, crds[1].Count, crds[2].Count)
	}

	rows, err := c.ListCRs(ctx, crds[0], 50)
	if err != nil || len(rows) != 1 || rows[0].Namespace != "kube-system" || rows[0].Phase != "Deployed" || rows[0].Ready != "Ready" || rows[0].Bad {
		t.Errorf("helmchart rows: %v %+v", err, rows)
	}
	// deletionTimestamp on the second object
	l2 := ulist("k3s.cattle.io/v1", "ETCDSnapshotFile",
		uobj("", "b-terminating", map[string]any{"status": map[string]any{"state": "Uploaded"}}),
		uobj("", "a-failed", map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False"}, map[string]any{"type": "Failed", "status": "True"}}}}),
	)
	l2["items"].([]any)[0].(map[string]any)["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-19T00:00:00Z"
	f.set("/apis/k3s.cattle.io/v1/etcdsnapshotfiles", l2)
	rows, err = c.ListCRs(ctx, crds[1], 50)
	if err != nil || len(rows) != 2 || rows[0].Name != "a-failed" || rows[1].Name != "b-terminating" {
		t.Fatalf("snapshot rows: %v %+v", err, rows)
	}
	if rows[0].Ready != "Ready=false,Failed" || !rows[0].Bad {
		t.Errorf("failed row: %+v", rows[0])
	}
	if rows[1].Phase != "Terminating" || !rows[1].Bad {
		t.Errorf("terminating row (state fallback overridden): %+v", rows[1])
	}
	if _, err := c.ListCRs(ctx, crds[2], 1); err == nil {
		t.Error("missing type must error")
	}
}

func TestGetObjectAndChildrenOf(t *testing.T) {
	f := newFakeAPI(t)
	f.set("/api/v1/namespaces/web/pods/nginx-1", uobj("web", "nginx-1", map[string]any{"apiVersion": "v1", "kind": "Pod", "spec": map[string]any{"nodeName": "w-1"}}))
	f.set("/api/v1/nodes/w-1", uobj("", "w-1", map[string]any{"apiVersion": "v1", "kind": "Node"}))
	f.set("/apis/apps/v1/namespaces/web/deployments/nginx", uobj("web", "nginx", map[string]any{"apiVersion": "apps/v1", "kind": "Deployment"}))
	rs := ulist("apps/v1", "ReplicaSet",
		uobj("web", "nginx-abc", map[string]any{}),
		uobj("web", "other-xyz", map[string]any{}),
	)
	rs["items"].([]any)[0].(map[string]any)["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "nginx", "uid": "dep-uid"}}
	f.set("/apis/apps/v1/namespaces/web/replicasets", rs)
	c := f.client(t, DefaultOptions())
	ctx := context.Background()

	u, err := c.GetObject(ctx, ObjRef{Kind: "Pod", Namespace: "web", Name: "nginx-1"})
	if err != nil || u.GetName() != "nginx-1" || u.GetKind() != "Pod" {
		t.Errorf("pod by default apiVersion: %v %v", err, u)
	}
	u, err = c.GetObject(ctx, ObjRef{APIVersion: "v1", Kind: "Node", Name: "w-1"})
	if err != nil || u.GetName() != "w-1" {
		t.Errorf("cluster-scoped: %v %v", err, u)
	}
	u, err = c.GetObject(ctx, ObjRef{Kind: "Deployment", Namespace: "web", Name: "nginx"})
	if err != nil || u.GetAPIVersion() != "apps/v1" {
		t.Errorf("apps default: %v %v", err, u)
	}
	if _, err := c.GetObject(ctx, ObjRef{APIVersion: "made.up/v9", Kind: "Widget", Name: "x"}); err == nil || !strings.Contains(err.Error(), "resolve made.up/v9 Widget") {
		t.Errorf("unknown kind: %v", err)
	}
	if _, err := c.GetObject(ctx, ObjRef{APIVersion: "a/b/c", Kind: "X", Name: "x"}); err == nil {
		t.Error("bad apiVersion must error")
	}
	if _, err := c.GetObject(ctx, ObjRef{Kind: "Pod", Namespace: "web", Name: "gone"}); err == nil {
		t.Error("404 must error")
	}

	kids, err := c.ChildrenOf(ctx, schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, "web", "dep-uid")
	if err != nil || len(kids) != 1 || kids[0].Name != "nginx-abc" || kids[0].Kind != "ReplicaSet" || kids[0].Via != "child" || kids[0].APIVersion != "apps/v1" {
		t.Errorf("children: %v %+v", err, kids)
	}
	if _, err := c.ChildrenOf(ctx, schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, "nowhere", "x"); err == nil {
		t.Error("missing list must error")
	}
}

func TestDefaultAPIVersion(t *testing.T) {
	cases := map[string]string{"Deployment": "apps/v1", "CronJob": "batch/v1", "Ingress": "networking.k8s.io/v1", "StorageClass": "storage.k8s.io/v1", "ClusterRole": "rbac.authorization.k8s.io/v1",
		"PriorityClass": "scheduling.k8s.io/v1", "HorizontalPodAutoscaler": "autoscaling/v2", "PodDisruptionBudget": "policy/v1", "HelmChart": "helm.cattle.io/v1", "ETCDSnapshotFile": "k3s.cattle.io/v1", "Secret": "v1", "Whatever": "v1"}
	for kind, want := range cases {
		if got := defaultAPIVersion(kind); got != want {
			t.Errorf("%s: %s want %s", kind, got, want)
		}
	}
}

func TestToUnstructuredAndDumpYAML(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns", ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}}, Data: map[string][]byte{"password": []byte("hunter2")}, StringData: map[string]string{"x": "y"}}
	u, err := ToUnstructured(sec)
	if err != nil || u.GetKind() != "Secret" || u.GetAPIVersion() != "v1" {
		t.Fatalf("to unstructured: %v kind=%q api=%q", err, u.GetKind(), u.GetAPIVersion())
	}
	out := DumpYAML(u)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "aHVudGVyMg") || !strings.Contains(out, "password: <12 bytes base64, masked>") {
		t.Errorf("secret data not masked:\n%s", out)
	}
	if strings.Contains(out, "managedFields") || strings.Contains(out, "stringData") {
		t.Errorf("managedFields / stringData not dropped:\n%s", out)
	}
	// typed objects that carry their own TypeMeta keep it
	dep := &appsv1.Deployment{TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}}
	if u, _ := ToUnstructured(dep); u.GetAPIVersion() != "apps/v1" {
		t.Errorf("typed apiVersion lost: %q", u.GetAPIVersion())
	}
	if DumpYAML(nil) != "" {
		t.Error("nil dump")
	}
	// long values are truncated at any depth, in maps and lists
	long := strings.Repeat("x", 5000)
	obj := map[string]any{"data": map[string]any{"big": long, "small": "ok"}, "list": []any{long, map[string]any{"deep": long}, 7}}
	truncateLong(obj, 0)
	want := strings.Repeat("x", 4000) + "... <1000 more bytes>"
	if obj["data"].(map[string]any)["big"] != want || obj["data"].(map[string]any)["small"] != "ok" || obj["list"].([]any)[0] != want || obj["list"].([]any)[1].(map[string]any)["deep"] != want || obj["list"].([]any)[2] != 7 {
		t.Errorf("truncation: %v", obj)
	}
	cm := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "data": map[string]any{"big": long}}}
	if out := DumpYAML(cm); strings.Contains(out, strings.Repeat("x", 4001)) || !strings.Contains(out, "more bytes") {
		t.Errorf("dump not truncated: %d bytes", len(out))
	}
}

func TestExtractRefsPod(t *testing.T) {
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "web-1", "namespace": "web", "ownerReferences": []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web-abc", "uid": "u1"}}},
		"spec": map[string]any{
			"nodeName": "w-1", "serviceAccountName": "web-sa", "priorityClassName": "high",
			"imagePullSecrets": []any{map[string]any{"name": "regcred"}},
			"volumes": []any{
				map[string]any{"name": "cfg", "configMap": map[string]any{"name": "web-config"}},
				map[string]any{"name": "tls", "secret": map[string]any{"secretName": "web-tls"}},
				map[string]any{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": "web-data"}},
				map[string]any{"name": "proj", "projected": map[string]any{"sources": []any{map[string]any{"secret": map[string]any{"name": "proj-secret"}}, map[string]any{"configMap": map[string]any{"name": "proj-cm"}}}}},
			},
			"initContainers": []any{map[string]any{"name": "init", "env": []any{map[string]any{"name": "A", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "init-cm", "key": "a"}}}}}},
			"containers": []any{map[string]any{"name": "app",
				"env":     []any{map[string]any{"name": "PW", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db-secret", "key": "pw"}}}, map[string]any{"name": "PLAIN", "value": "x"}},
				"envFrom": []any{map[string]any{"secretRef": map[string]any{"name": "env-secret"}}, map[string]any{"configMapRef": map[string]any{"name": "env-cm"}}},
			}},
		},
	}}
	refs := ExtractRefs(pod)
	if len(refs) == 0 || refs[0].Via != "owner" || refs[0].Kind != "ReplicaSet" || refs[0].Namespace != "web" {
		t.Fatalf("owner first: %+v", refs)
	}
	want := map[string]string{ // kind/ns/name -> via
		"ServiceAccount/web/web-sa":          "serviceAccount",
		"PriorityClass//high":                "priorityClass",
		"Secret/web/regcred":                 "imagePullSecret",
		"ConfigMap/web/web-config":           "volume cfg",
		"Secret/web/web-tls":                 "volume tls",
		"PersistentVolumeClaim/web/web-data": "volume data",
		"Secret/web/proj-secret":             "volume proj",
		"ConfigMap/web/proj-cm":              "volume proj",
		"ConfigMap/web/init-cm":              "env init",
		"Secret/web/db-secret":               "env app",
		"Secret/web/env-secret":              "envFrom app",
		"ConfigMap/web/env-cm":               "envFrom app",
		"Node//w-1":                          "node",
		"ReplicaSet/web/web-abc":             "owner",
	}
	got := map[string]string{}
	fieldRefs := 0
	for _, r := range refs {
		if strings.HasPrefix(r.Via, "field:") {
			fieldRefs++
			continue
		}
		got[r.Key()] = r.Via
	}
	for k, via := range want {
		if got[k] != via {
			t.Errorf("%s: via %q want %q", k, got[k], via)
		}
	}
	if len(got) != len(want) {
		t.Errorf("extra refs: %v", got)
	}
	// the generic walker also sees the same names through their field paths, ranked last
	if fieldRefs == 0 || !strings.HasPrefix(refs[len(refs)-1].Via, "field:") {
		t.Errorf("field refs: %d, last=%+v", fieldRefs, refs[len(refs)-1])
	}
	if ExtractRefs(nil) != nil {
		t.Error("nil object")
	}
}

func TestExtractRefsStorageAndCRs(t *testing.T) {
	pvc := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": map[string]any{"name": "data", "namespace": "web"},
		"spec": map[string]any{"storageClassName": "fast", "volumeName": "pv-1"}}}
	refs := ExtractRefs(pvc)
	vias := map[string]ObjRef{}
	for _, r := range refs {
		vias[r.Via] = r
	}
	if r := vias["storageClass"]; r.Kind != "StorageClass" || r.Name != "fast" || r.Namespace != "" {
		t.Errorf("storage class: %+v", r)
	}
	if r := vias["volume"]; r.Kind != "PersistentVolume" || r.Name != "pv-1" {
		t.Errorf("volume: %+v", r)
	}

	pv := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "PersistentVolume", "metadata": map[string]any{"name": "pv-1"},
		"spec": map[string]any{"claimRef": map[string]any{"kind": "PersistentVolumeClaim", "namespace": "web", "name": "data"}, "volumeName": "ignored-on-pv"}}}
	refs = ExtractRefs(pv)
	var claim, byField, volume bool
	for _, r := range refs {
		switch {
		case r.Via == "claim" && r.Kind == "PersistentVolumeClaim" && r.Namespace == "web" && r.Name == "data":
			claim = true
		case r.Via == "field:spec.claimRef" && r.Kind == "PersistentVolumeClaim":
			byField = true
		case r.Via == "volume":
			volume = true
		}
	}
	if !claim || !byField || volume {
		t.Errorf("pv refs: claim=%v field=%v volume=%v %+v", claim, byField, volume, refs)
	}

	// a CR with typed references, name fields and a nested status
	cr := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.com/v1", "kind": "Backup", "metadata": map[string]any{"name": "nightly", "namespace": "ops"},
		"spec": map[string]any{
			"target":            map[string]any{"kind": "Deployment", "apiVersion": "apps/v1", "name": "api"},
			"credentialsSecret": "s3-creds",
			"existingSecret":    map[string]any{"name": "ext", "namespace": "other"},
			"tlsSecret":         "",
			"serviceName":       "api-svc",
			"ingressClassName":  "nginx",
			"storageClassName":  "fast",
			"pvcName":           "cache",
			"serviceAccount":    "runner",
			"items":             []any{map[string]any{"configMapRef": map[string]any{"name": "cm-a"}}, map[string]any{"secretRef": map[string]any{"name": "sec-b"}}},
		},
		"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}, "lastSecretName": "should-be-skipped-deep"},
	}}
	refs = ExtractRefs(cr)
	got := map[string]string{}
	for _, r := range refs {
		got[r.Via] = r.Key()
	}
	checks := map[string]string{
		"field:spec.target":                "Deployment/ops/api",
		"field:spec.credentialsSecret":     "Secret/ops/s3-creds",
		"field:spec.existingSecret":        "Secret/other/ext",
		"field:spec.serviceName":           "Service/ops/api-svc",
		"field:spec.ingressClassName":      "IngressClass//nginx",
		"field:spec.storageClassName":      "StorageClass//fast",
		"field:spec.pvcName":               "PersistentVolumeClaim/ops/cache",
		"field:spec.serviceAccount":        "ServiceAccount/ops/runner",
		"field:spec.items[0].configMapRef": "ConfigMap/ops/cm-a",
		"field:spec.items[1].secretRef":    "Secret/ops/sec-b",
		"storageClass":                     "StorageClass//fast",
	}
	for via, key := range checks {
		if got[via] != key {
			t.Errorf("%s: %q want %q", via, got[via], key)
		}
	}
	if _, ok := got["field:spec.tlsSecret"]; ok {
		t.Error("empty name must not produce a ref")
	}
	if _, ok := got["field:status.lastSecretName"]; !ok {
		t.Error("shallow status fields are still scanned")
	}
	// the same object via two paths is kept once per via, and never through metadata
	for _, r := range refs {
		if strings.HasPrefix(r.Via, "field:metadata") {
			t.Errorf("metadata scanned: %+v", r)
		}
	}
	// ranking: owner < child < others < field
	if viaRank("owner") >= viaRank("child") || viaRank("child") >= viaRank("volume x") || viaRank("volume x") >= viaRank("field:spec.a") {
		t.Error("via rank order")
	}
}

func TestIsNamespacedKind(t *testing.T) {
	for _, k := range []string{"Node", "PersistentVolume", "StorageClass", "ClusterRoleBinding", "Namespace", "CustomResourceDefinition", "PriorityClass", "IngressClass", "CSIDriver", "CSINode", "ETCDSnapshotFile"} {
		if isNamespacedKind(k) {
			t.Errorf("%s is cluster-scoped", k)
		}
	}
	for _, k := range []string{"Pod", "Secret", "HelmChart", "Whatever"} {
		if !isNamespacedKind(k) {
			t.Errorf("%s is namespaced", k)
		}
	}
}

func TestSnapshotChildren(t *testing.T) {
	owner := []metav1.OwnerReference{{UID: types.UID("u-1"), Kind: "Deployment", Name: "x"}}
	other := []metav1.OwnerReference{{UID: types.UID("u-2")}}
	s := &Snapshot{
		Pods:         []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "p1", OwnerReferences: owner}}, {ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "p2", OwnerReferences: other}}},
		Deployments:  []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "d", OwnerReferences: owner}}},
		DaemonSets:   []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "ds", OwnerReferences: owner}}},
		StatefulSets: []appsv1.StatefulSet{{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "ss", OwnerReferences: owner}}},
		Jobs:         []batchv1.Job{{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "j", OwnerReferences: owner}}},
		PVCs:         []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "pvc", OwnerReferences: owner}}},
	}
	kids := s.Children("u-1")
	if len(kids) != 6 {
		t.Fatalf("children: %+v", kids)
	}
	kinds := map[string]string{}
	for _, k := range kids {
		if k.Via != "child" || k.Namespace != "a" {
			t.Errorf("child ref: %+v", k)
		}
		kinds[k.Kind] = k.APIVersion
	}
	if kinds["Pod"] != "v1" || kinds["Deployment"] != "apps/v1" || kinds["Job"] != "batch/v1" || kinds["PersistentVolumeClaim"] != "v1" {
		t.Errorf("kinds: %v", kinds)
	}
	if len(s.Children("nope")) != 0 {
		t.Error("unknown uid")
	}
}

func TestConditionSummary(t *testing.T) {
	if s, bad := ConditionSummary(map[string]any{}); s != "" || bad {
		t.Error("no conditions")
	}
	obj := map[string]any{"status": map[string]any{"conditions": []any{
		map[string]any{"type": "Ready", "status": "True"},
		map[string]any{"type": "Available", "status": "False"},
		map[string]any{"type": "Degraded", "status": "True"},
		map[string]any{"type": "Stalled", "status": "False"},
		map[string]any{"type": "Unknown", "status": "True"},
	}}}
	s, bad := ConditionSummary(obj)
	if s != "Ready,Available=false,Degraded" || !bad {
		t.Errorf("summary %q bad=%v", s, bad)
	}
	s, bad = ConditionSummary(map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Synced", "status": "True"}}}})
	if s != "Synced" || bad {
		t.Errorf("healthy: %q %v", s, bad)
	}
}

func TestHasVerb(t *testing.T) {
	if !hasVerb([]string{"get", "list"}, "list") || hasVerb([]string{"get"}, "list") || hasVerb(nil, "get") {
		t.Error("hasVerb")
	}
}
