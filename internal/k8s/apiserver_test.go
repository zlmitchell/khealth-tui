package k8s

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeAPI is an httptest API server: one JSON document per path, a Status
// error for everything else, and a per-path hit count so the tests can
// assert what the caches spared the server. Query strings are ignored;
// metadata-only lists (Accept: PartialObjectMetadataList) are served from
// a separate table so the same path can carry a typed list too.
type fakeAPI struct {
	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string]any
	meta map[string]any
	raw  map[string]rawResp
	deny map[string]int
	hits map[string]int
	// unknownCode answers paths nothing was set for (0 = 404)
	unknownCode int
}

type rawResp struct {
	status int
	body   string
}

// The discovery documents every fake serves: enough for the RESTMapper,
// ServerPreferredResources and ServerVersion.
var discoveryDocs = map[string]any{
	"/version": map[string]any{"major": "1", "minor": "30", "gitVersion": "v1.30.4+rke2r1"},
	"/api":     map[string]any{"kind": "APIVersions", "versions": []string{"v1"}, "serverAddressByClientCIDRs": []any{}},
	"/apis": map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{
		group("apps", "v1"), group("batch", "v1"), group("rbac.authorization.k8s.io", "v1"), group("networking.k8s.io", "v1"),
		group("storage.k8s.io", "v1"), group("helm.cattle.io", "v1"), group("k3s.cattle.io", "v1"), group("apiextensions.k8s.io", "v1"),
		group("management.cattle.io", "v3"), group("trident.netapp.io", "v1"),
	}},
	"/api/v1": resources("v1",
		res("pods", "Pod", true, "list", "get", "create"), res("nodes", "Node", false, "list", "get"), res("secrets", "Secret", true, "list", "get"),
		res("configmaps", "ConfigMap", true, "list", "get"), res("serviceaccounts", "ServiceAccount", true, "list", "get"), res("events", "Event", true, "list", "get"),
		res("namespaces", "Namespace", false, "list", "get"), res("persistentvolumes", "PersistentVolume", false, "list", "get"),
		res("persistentvolumeclaims", "PersistentVolumeClaim", true, "list", "get"), res("pods/log", "Pod", true, "get"), res("bindings", "Binding", true, "create")),
	"/apis/apps/v1":                      resources("apps/v1", res("deployments", "Deployment", true, "list", "get"), res("replicasets", "ReplicaSet", true, "list", "get"), res("daemonsets", "DaemonSet", true, "list", "get"), res("statefulsets", "StatefulSet", true, "list", "get")),
	"/apis/batch/v1":                     resources("batch/v1", res("jobs", "Job", true, "list", "get"), res("cronjobs", "CronJob", true, "list", "get")),
	"/apis/rbac.authorization.k8s.io/v1": resources("rbac.authorization.k8s.io/v1", res("clusterrolebindings", "ClusterRoleBinding", false, "list", "get")),
	"/apis/networking.k8s.io/v1":         resources("networking.k8s.io/v1", res("ingresses", "Ingress", true, "list", "get"), res("networkpolicies", "NetworkPolicy", true, "list", "get")),
	"/apis/storage.k8s.io/v1":            resources("storage.k8s.io/v1", res("storageclasses", "StorageClass", false, "list", "get"), res("csidrivers", "CSIDriver", false, "list", "get"), res("csinodes", "CSINode", false, "list", "get")),
	"/apis/helm.cattle.io/v1":            resources("helm.cattle.io/v1", res("helmcharts", "HelmChart", true, "list", "get"), res("helmchartconfigs", "HelmChartConfig", true, "list", "get")),
	"/apis/k3s.cattle.io/v1":             resources("k3s.cattle.io/v1", res("etcdsnapshotfiles", "ETCDSnapshotFile", false, "list", "get")),
	"/apis/apiextensions.k8s.io/v1":      resources("apiextensions.k8s.io/v1", res("customresourcedefinitions", "CustomResourceDefinition", false, "list", "get")),
	"/apis/management.cattle.io/v3":      resources("management.cattle.io/v3", res("users", "User", false, "list", "get"), res("authconfigs", "AuthConfig", false, "list", "get"), res("globalroles", "GlobalRole", false, "list", "get"), res("globalrolebindings", "GlobalRoleBinding", false, "list", "get")),
	"/apis/trident.netapp.io/v1":         resources("trident.netapp.io/v1", res("tridentbackends", "TridentBackend", true, "list", "get")),
}

func group(name, version string) map[string]any {
	gv := name + "/" + version
	return map[string]any{"name": name, "versions": []any{map[string]any{"groupVersion": gv, "version": version}}, "preferredVersion": map[string]any{"groupVersion": gv, "version": version}}
}

func resources(gv string, rs ...map[string]any) map[string]any {
	return map[string]any{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": gv, "resources": rs}
}

func res(name, kind string, namespaced bool, verbs ...string) map[string]any {
	return map[string]any{"name": name, "kind": kind, "namespaced": namespaced, "verbs": verbs}
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{objs: map[string]any{}, meta: map[string]any{}, raw: map[string]rawResp{}, deny: map[string]int{}, hits: map[string]int{}}
	for p, d := range discoveryDocs {
		f.objs[p] = d
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	isMeta := strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList")
	key := path
	if isMeta {
		key += "|meta"
	}
	f.mu.Lock()
	f.hits[key]++
	raw, hasRaw := f.raw[path]
	code, denied := f.deny[path]
	var obj any
	var ok bool
	if isMeta {
		obj, ok = f.meta[path]
	}
	if !ok {
		obj, ok = f.objs[path]
	}
	f.mu.Unlock()
	switch {
	case denied:
		writeStatus(w, code, path)
	case hasRaw:
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(raw.status)
		fmt.Fprint(w, raw.body)
	case ok:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(obj)
	case f.unknownCode != 0:
		writeStatus(w, f.unknownCode, path)
	default:
		writeStatus(w, http.StatusNotFound, path)
	}
}

func writeStatus(w http.ResponseWriter, code int, path string) {
	reason, msg := metav1.StatusReasonNotFound, "the server could not find the requested resource "+path
	if code == http.StatusForbidden {
		reason, msg = metav1.StatusReasonForbidden, path+` is forbidden: User "tester" cannot list resource`
	}
	if code == http.StatusInternalServerError {
		reason, msg = metav1.StatusReasonInternalError, "boom "+path
	}
	// details as the real apiserver sends them (client-go rewrites the
	// message of a Status without them)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	details := &metav1.StatusDetails{Kind: parts[len(parts)-1]}
	if len(parts) >= 2 {
		details.Kind, details.Name = parts[len(parts)-2], parts[len(parts)-1]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: metav1.StatusFailure, Message: msg, Reason: reason, Details: details, Code: int32(code)})
}

// set serves obj (marshalled as JSON) at path.
func (f *fakeAPI) set(path string, obj any) {
	f.mu.Lock()
	f.objs[path] = obj
	f.mu.Unlock()
}

// setMeta serves a PartialObjectMetadataList at path for metadata-only lists.
func (f *fakeAPI) setMeta(path string, items ...metav1.ObjectMeta) {
	l := map[string]any{"kind": "PartialObjectMetadataList", "apiVersion": "meta.k8s.io/v1", "metadata": map[string]any{"resourceVersion": "1"}, "items": []any{}}
	var its []any
	for _, m := range items {
		its = append(its, map[string]any{"metadata": m})
	}
	l["items"] = its
	f.mu.Lock()
	f.meta[path] = l
	f.mu.Unlock()
}

// setRaw serves a verbatim body with the given status (readyz, proxies).
func (f *fakeAPI) setRaw(path string, status int, body string) {
	f.mu.Lock()
	f.raw[path] = rawResp{status, body}
	f.mu.Unlock()
}

// denyWith makes path answer with a Status of the given code.
func (f *fakeAPI) denyWith(path string, code int) {
	f.mu.Lock()
	f.deny[path] = code
	f.mu.Unlock()
}

func (f *fakeAPI) hitCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[key]
}

// ulist builds an unstructured list document for the dynamic client.
func ulist(apiVersion, kind string, items ...map[string]any) map[string]any {
	its := make([]any, 0, len(items))
	for _, it := range items {
		it["apiVersion"], it["kind"] = apiVersion, kind
		its = append(its, it)
	}
	return map[string]any{"apiVersion": apiVersion, "kind": kind + "List", "metadata": map[string]any{"resourceVersion": "1"}, "items": its}
}

// uobj builds an unstructured object with metadata.
func uobj(ns, name string, body map[string]any) map[string]any {
	md := map[string]any{"name": name, "uid": "uid-" + name, "resourceVersion": "1"}
	if ns != "" {
		md["namespace"] = ns
	}
	body["metadata"] = md
	return body
}

// client builds a Client against the fake server through a kubeconfig file,
// so New / NewWithOptions are exercised too.
func (f *fakeAPI) client(t *testing.T, opts Options) *Client {
	t.Helper()
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	content := "apiVersion: v1\nkind: Config\nclusters:\n- name: fake\n  cluster:\n    server: " + f.srv.URL + "\ncontexts:\n- name: fake\n  context:\n    cluster: fake\n    user: tester\ncurrent-context: fake\nusers:\n- name: tester\n  user:\n    token: t0k3n\n"
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewWithOptions(kc, "", opts)
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	return c
}

// helmPayload encodes a helm v3 release the way the release secret stores
// it: base64(gzip(json)).
func helmPayload(js string) []byte {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(js))
	_ = w.Close()
	return []byte(base64.StdEncoding.EncodeToString(gz.Bytes()))
}
