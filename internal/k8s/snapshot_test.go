package k8s

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func tm(kind string) metav1.TypeMeta { return metav1.TypeMeta{Kind: kind, APIVersion: "v1"} }

// rke2Cluster populates the fake with a small two-node rke2 cluster.
func rke2Cluster(f *fakeAPI) {
	now := metav1.Now()
	earlier := metav1.NewTime(now.Add(-time.Hour))
	f.set("/api/v1/nodes", corev1.NodeList{TypeMeta: tm("NodeList"), Items: []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Annotations: map[string]string{"rke2.io/node-args": "[]"}, Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}}},
	}})
	f.set("/api/v1/pods", corev1.PodList{TypeMeta: tm("PodList"), Items: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "nginx-b"}, Spec: corev1.PodSpec{NodeName: "cp-1"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "etcd-cp-1", Labels: map[string]string{"component": "etcd"}}, Spec: corev1.PodSpec{NodeName: "cp-1"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "nginx-a"}, Spec: corev1.PodSpec{NodeName: "w-1"}},
	}})
	f.set("/api/v1/services", corev1.ServiceList{TypeMeta: tm("ServiceList"), Items: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.1"}}, {ObjectMeta: metav1.ObjectMeta{Name: "rke2-coredns-rke2-coredns", Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-dns"}}, Spec: corev1.ServiceSpec{ClusterIP: "10.43.0.10"}}}})
	f.set("/api/v1/namespaces", corev1.NamespaceList{TypeMeta: tm("NamespaceList"), Items: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "web"}}, {ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}}})
	f.set("/api/v1/events", corev1.EventList{TypeMeta: tm("EventList"), Items: []corev1.Event{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "old"}, Type: "Normal", LastTimestamp: earlier},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "new"}, Type: "Warning", Reason: "BackOff", LastTimestamp: now},
	}})
	f.set("/api/v1/persistentvolumeclaims", corev1.PersistentVolumeClaimList{TypeMeta: tm("PersistentVolumeClaimList"), Items: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "data"}}}})
	f.set("/api/v1/persistentvolumes", corev1.PersistentVolumeList{TypeMeta: tm("PersistentVolumeList")})
	f.set("/apis/storage.k8s.io/v1/storageclasses", storagev1.StorageClassList{TypeMeta: metav1.TypeMeta{Kind: "StorageClassList", APIVersion: "storage.k8s.io/v1"}})
	f.set("/apis/storage.k8s.io/v1/csidrivers", storagev1.CSIDriverList{TypeMeta: metav1.TypeMeta{Kind: "CSIDriverList", APIVersion: "storage.k8s.io/v1"}})
	f.set("/apis/storage.k8s.io/v1/csinodes", storagev1.CSINodeList{TypeMeta: metav1.TypeMeta{Kind: "CSINodeList", APIVersion: "storage.k8s.io/v1"}})
	f.set("/apis/apps/v1/daemonsets", appsv1.DaemonSetList{TypeMeta: metav1.TypeMeta{Kind: "DaemonSetList", APIVersion: "apps/v1"}})
	f.set("/apis/apps/v1/statefulsets", appsv1.StatefulSetList{TypeMeta: metav1.TypeMeta{Kind: "StatefulSetList", APIVersion: "apps/v1"}})
	f.set("/apis/batch/v1/jobs", batchv1.JobList{TypeMeta: metav1.TypeMeta{Kind: "JobList", APIVersion: "batch/v1"}})
	f.set("/apis/batch/v1/cronjobs", batchv1.CronJobList{TypeMeta: metav1.TypeMeta{Kind: "CronJobList", APIVersion: "batch/v1"}})
	f.set("/apis/networking.k8s.io/v1/ingresses", networkingv1.IngressList{TypeMeta: metav1.TypeMeta{Kind: "IngressList", APIVersion: "networking.k8s.io/v1"}})
	f.set("/apis/networking.k8s.io/v1/networkpolicies", networkingv1.NetworkPolicyList{TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicyList", APIVersion: "networking.k8s.io/v1"}})
	f.set("/apis/apps/v1/deployments", appsv1.DeploymentList{TypeMeta: metav1.TypeMeta{Kind: "DeploymentList", APIVersion: "apps/v1"}, Items: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "nginx"}}}})
	f.set("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", rbacv1.ClusterRoleBindingList{TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBindingList", APIVersion: "rbac.authorization.k8s.io/v1"}})

	// metadata-only lists; the helm release secret carries owner=helm
	f.setMeta("/api/v1/secrets", metav1.ObjectMeta{Namespace: "web", Name: "sh.helm.release.v1.nginx.v1", ResourceVersion: "10", Labels: map[string]string{"owner": "helm"}}, metav1.ObjectMeta{Namespace: "kube-system", Name: "rke2-etcd-s3-config"})
	f.setMeta("/api/v1/configmaps", metav1.ObjectMeta{Namespace: "kube-system", Name: "rke2-etcd-snapshots"})
	f.setMeta("/api/v1/serviceaccounts", metav1.ObjectMeta{Namespace: "web", Name: "default"})
	// the typed secret list (helm payloads) behind the same path
	rel := `{"name":"nginx","namespace":"web","version":1,"info":{"status":"deployed"},"chart":{"metadata":{"name":"nginx","version":"1.0.0"}}}`
	f.set("/api/v1/secrets", corev1.SecretList{TypeMeta: tm("SecretList"), Items: []corev1.Secret{{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "sh.helm.release.v1.nginx.v1"}, Type: "helm.sh/release.v1", Data: map[string][]byte{"release": helmPayload(rel)}}}})
	f.set("/api/v1/configmaps", corev1.ConfigMapList{TypeMeta: tm("ConfigMapList")})

	f.setRaw("/readyz", http.StatusInternalServerError, "[+]ping ok\n[+]etcd ok\n[-]poststarthook/x failed: reason withheld\nreadyz check failed\n")
	f.setRaw("/livez", http.StatusOK, "[+]ping ok\nlivez check passed\n")
	f.set("/apis/metrics.k8s.io/v1beta1/nodes", map[string]any{"kind": "NodeMetricsList", "items": []any{
		map[string]any{"metadata": map[string]any{"name": "cp-1"}, "usage": map[string]any{"cpu": "250m", "memory": "1Gi"}},
		map[string]any{"metadata": map[string]any{"name": "w-1"}, "usage": map[string]any{"cpu": "1", "memory": "512Mi"}},
	}})
	for _, n := range []string{"cp-1", "w-1"} {
		f.setRaw("/api/v1/nodes/"+n+"/proxy/configz", http.StatusOK, `{"kubeletconfig":{"authentication":{"anonymous":{"enabled":false}},"node":"`+n+`"}}`)
	}
	f.setRaw("/api/v1/nodes/cp-1/proxy/stats/summary", http.StatusOK, `{"pods":[{"podRef":{"name":"nginx-b","namespace":"web"},"volume":[{"name":"data","capacityBytes":1000,"usedBytes":250,"availableBytes":750,"inodes":10,"inodesUsed":1,"pvcRef":{"name":"data","namespace":"web"}},{"name":"tmp","capacityBytes":5,"usedBytes":1}]}]}`)
	f.setRaw("/api/v1/nodes/w-1/proxy/stats/summary", http.StatusOK, `{"pods":[]}`)

	// rke2 CRs: one snapshot from the CRD and one only in the configmap
	f.set("/apis/k3s.cattle.io/v1/etcdsnapshotfiles", ulist("k3s.cattle.io/v1", "ETCDSnapshotFile",
		uobj("", "etcd-snapshot-cp-1-1", map[string]any{"spec": map[string]any{"snapshotName": "etcd-snapshot-cp-1-1", "nodeName": "cp-1", "location": "file:///var/lib/rancher/rke2/server/db/snapshots/etcd-snapshot-cp-1-1"}, "status": map[string]any{"creationTime": "2026-09-18T10:00:00Z", "size": int64(2048), "readyToUse": true}}),
		uobj("", "etcd-snapshot-cp-1-0", map[string]any{"spec": map[string]any{"snapshotName": "etcd-snapshot-cp-1-0", "nodeName": "cp-1", "s3": map[string]any{"bucket": "b"}}, "status": map[string]any{"creationTime": "2026-09-17T10:00:00Z", "error": map[string]any{"message": "upload failed"}}}),
	))
	f.set("/api/v1/namespaces/kube-system/configmaps/rke2-etcd-snapshots", corev1.ConfigMap{TypeMeta: tm("ConfigMap"), ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "rke2-etcd-snapshots"}, Data: map[string]string{
		"etcd-snapshot-cp-1-1": `{"name":"etcd-snapshot-cp-1-1","nodeName":"cp-1","createdAt":"2026-09-18T10:00:00Z","status":"successful"}`,
		"old-cm-only":          `{"name":"old-cm-only","nodeName":"cp-1","location":"s3://bucket/old-cm-only","createdAt":"2026-09-16T10:00:00Z","size":100,"status":"successful"}`,
		"junk":                 `not json`,
	}})
	f.set("/apis/helm.cattle.io/v1/helmcharts", ulist("helm.cattle.io/v1", "HelmChart",
		uobj("kube-system", "rke2-canal", map[string]any{"spec": map[string]any{"chart": "rke2-canal", "version": "v3.28", "repo": "", "targetNamespace": "kube-system", "valuesContent": "a: 1\n"}, "status": map[string]any{"jobName": "helm-install-rke2-canal", "conditions": []any{map[string]any{"type": "Failed", "status": "True"}}}}),
		uobj("kube-system", "rke2-coredns", map[string]any{"spec": map[string]any{"chart": "rke2-coredns"}}),
	))
	f.set("/apis/helm.cattle.io/v1/helmchartconfigs", ulist("helm.cattle.io/v1", "HelmChartConfig",
		uobj("kube-system", "rke2-canal", map[string]any{"spec": map[string]any{"valuesContent": "calico:\n  vethuMTU: 1400\n"}}),
	))
	f.denyWith("/apis/trident.netapp.io/v1/tridentbackends", http.StatusForbidden)
	f.set("/api/v1/namespaces/kube-system/configmaps/vsphere-cloud-config", corev1.ConfigMap{TypeMeta: tm("ConfigMap"), Data: map[string]string{"vsphere.conf": "[Global]\nport = \"443\"\ninsecure-flag = \"1\"\n[VirtualCenter \"vc.example.com\"]\ndatacenters = \"dc1, dc2\"\n"}})
	f.set("/apis/apiextensions.k8s.io/v1/customresourcedefinitions", ulist("apiextensions.k8s.io/v1", "CustomResourceDefinition",
		uobj("", "helmcharts.helm.cattle.io", map[string]any{"spec": map[string]any{"group": "helm.cattle.io", "scope": "Namespaced", "names": map[string]any{"kind": "HelmChart", "plural": "helmcharts"}, "versions": []any{map[string]any{"name": "v1", "served": true, "storage": true}}}, "status": map[string]any{"conditions": []any{map[string]any{"type": "Established", "status": "True"}}}}),
	))
}

func TestFetchRKE2(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	f.denyWith("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", http.StatusForbidden)
	c := f.client(t, DefaultOptions())
	if c.Context != "fake" || c.Host != f.srv.URL {
		t.Fatalf("client: context %q host %q", c.Context, c.Host)
	}
	ctx := context.Background()
	s := c.Fetch(ctx)

	if s.Version != "v1.30.4+rke2r1" || s.Distribution != "rke2" {
		t.Errorf("version %q dist %q", s.Version, s.Distribution)
	}
	if len(s.Nodes) != 2 || s.Nodes[0].Name != "cp-1" || s.Nodes[1].Name != "w-1" {
		t.Errorf("nodes not sorted: %v", []string{s.Nodes[0].Name, s.Nodes[1].Name})
	}
	if len(s.Pods) != 3 || s.Pods[0].Name != "etcd-cp-1" || s.Pods[1].Name != "nginx-a" || s.Pods[2].Name != "nginx-b" {
		t.Errorf("pods not sorted by ns/name: %v", podNames(s.Pods))
	}
	if s.ClusterDNSIP() != "10.43.0.10" || s.APIServiceIP() != "10.43.0.1" {
		t.Errorf("service IPs: dns=%q api=%q", s.ClusterDNSIP(), s.APIServiceIP())
	}
	if len(s.Namespaces) != 2 || s.Namespaces[0].Name != "kube-system" {
		t.Errorf("namespaces: %+v", s.Namespaces)
	}
	if len(s.Events) != 2 || s.Events[0].Name != "new" || len(s.WarningEvents()) != 1 {
		t.Errorf("events: newest first expected, got %v warnings=%d", s.Events[0].Name, len(s.WarningEvents()))
	}
	if len(s.Deployments) != 1 || len(s.PVCs) != 1 {
		t.Errorf("typed lists: deployments=%d pvcs=%d", len(s.Deployments), len(s.PVCs))
	}
	// the refused list is reported, remembered and everything else still there
	if len(s.Errors) != 1 || !strings.HasPrefix(s.Errors[0], "clusterrolebindings: ") || !strings.Contains(s.Errors[0], "forbidden") {
		t.Errorf("errors: %v", s.Errors)
	}
	if _, ok := c.Denied("clusterrolebindings"); !ok {
		t.Error("403 on clusterrolebindings not remembered")
	}
	if _, ok := c.Denied("tridentbackends.trident.netapp.io"); !ok || s.TridentBackends != nil {
		t.Errorf("optional CR list: denied=%v backends=%v", ok, s.TridentBackends)
	}
	// metadata lists and reference lookups
	if ok, tracked := s.RefExists("Secret", "web", "sh.helm.release.v1.nginx.v1"); !ok || !tracked {
		t.Error("secret name from the metadata list missing")
	}
	if ok, tracked := s.RefExists("ConfigMap", "kube-system", "nope"); ok || !tracked {
		t.Error("missing configmap should be tracked but absent")
	}
	if ok, tracked := s.RefExists("ServiceAccount", "web", "default"); !ok || !tracked {
		t.Error("service account missing")
	}
	if ok, tracked := s.RefExists("PersistentVolumeClaim", "web", "data"); !ok || !tracked {
		t.Error("pvc from the typed list missing")
	}
	if _, tracked := s.RefExists("Service", "web", "x"); tracked {
		t.Error("Service is not a tracked kind")
	}
	// readyz / livez: a failing readyz still yields the per-check lines
	if len(s.Readyz) != 3 || s.Readyz[2].OK || s.Readyz[2].Name != "poststarthook/x" || s.Readyz[2].Detail != "failed: reason withheld" {
		t.Errorf("readyz: %+v", s.Readyz)
	}
	if len(s.Livez) != 1 || !s.Livez[0].OK {
		t.Errorf("livez: %+v", s.Livez)
	}
	// metrics
	if !s.MetricsAvailable || s.NodeMetrics["cp-1"].CPUMilli != 250 || s.NodeMetrics["cp-1"].MemBytes != 1<<30 || s.NodeMetrics["w-1"].CPUMilli != 1000 {
		t.Errorf("metrics: %+v", s.NodeMetrics)
	}
	// kubelet proxies
	if s.KubeletCfgErr != "" || len(s.KubeletConfigs) != 2 || s.KubeletConfigs["w-1"]["node"] != "w-1" {
		t.Errorf("configz: err=%q cfgs=%v", s.KubeletCfgErr, s.KubeletConfigs)
	}
	u, ok := s.PVCUsage["web/data"]
	if !ok || u.Node != "cp-1" || u.Pod != "web/nginx-b" || u.Used != 250 || u.UsedPct() != 25 || u.InodesUsed != 1 || s.PVCUsageErr != "" {
		t.Errorf("pvc usage: %+v err=%q", s.PVCUsage, s.PVCUsageErr)
	}
	// rke2 snapshot records: CRD + configmap merged, newest first
	if len(s.RKE2Snapshots) != 3 {
		t.Fatalf("snapshots: %+v", s.RKE2Snapshots)
	}
	if r := s.RKE2Snapshots[0]; r.Name != "etcd-snapshot-cp-1-1" || r.Source != "crd" || r.Status != "successful" || r.Size != 2048 || r.S3 {
		t.Errorf("crd record: %+v", r)
	}
	if r := s.RKE2Snapshots[1]; r.Name != "etcd-snapshot-cp-1-0" || r.Status != "failed" || r.Message != "upload failed" || !r.S3 {
		t.Errorf("failed s3 record: %+v", r)
	}
	if r := s.RKE2Snapshots[2]; r.Name != "old-cm-only" || r.Source != "configmap" || !r.S3 || r.Size != 100 {
		t.Errorf("configmap-only record: %+v", r)
	}
	// HelmChart CRs with their config overrides
	if len(s.HelmCharts) != 2 || s.HelmCharts[0].Name != "rke2-canal" || !s.HelmCharts[0].HasConfig || !s.HelmCharts[0].Failed || s.HelmCharts[0].JobName != "helm-install-rke2-canal" || !strings.Contains(s.HelmCharts[0].ConfigValues, "vethuMTU") || s.HelmCharts[1].HasConfig {
		t.Errorf("helm charts: %+v", s.HelmCharts)
	}
	// helm releases decoded from the secret
	if len(s.HelmReleases) != 1 || s.HelmReleases[0].Name != "nginx" || s.HelmReleases[0].Storage != "secret" || len(s.HelmReleases[0].History) != 1 {
		t.Errorf("helm releases: %+v", s.HelmReleases)
	}
	if s.VSphereConf == nil || len(s.VSphereConf.VCenters) != 1 || s.VSphereConf.VCenters[0] != "vc.example.com:443" || !s.VSphereConf.Insecure || len(s.VSphereConf.Datacenters) != 2 {
		t.Errorf("vsphere conf: %+v", s.VSphereConf)
	}
	if s.Kubeadm != nil {
		t.Errorf("kubeadm config on an rke2 cluster: %+v", s.Kubeadm)
	}
	if s.Rancher == nil || s.Rancher.Managed || s.Rancher.Management {
		t.Errorf("rancher: %+v", s.Rancher)
	}
	var custom int
	for _, r := range s.CRDs {
		if r.Custom {
			custom++
			if r.Name != "helmcharts.helm.cattle.io" || r.Storage != "v1" || !r.Established {
				t.Errorf("custom resource row: %+v", r)
			}
		}
	}
	if custom != 1 || len(s.CRDs) < 20 {
		t.Errorf("resources: custom=%d total=%d", custom, len(s.CRDs))
	}
	if s.FetchDuration <= 0 || s.Traffic.Requests < 30 || s.Traffic.BytesIn == 0 {
		t.Errorf("footprint: %s %+v", s.FetchDuration, s.Traffic)
	}

	// second cycle: caches spare the server the helm payloads, discovery
	// and configz; the refused list is not retried but still reported
	before := map[string]int{}
	for _, k := range []string{"/api/v1/secrets", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "/api/v1/nodes/cp-1/proxy/configz", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", "/api/v1/nodes"} {
		before[k] = f.hitCount(k)
	}
	s2 := c.Fetch(ctx)
	for _, k := range []string{"/api/v1/secrets", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "/api/v1/nodes/cp-1/proxy/configz", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"} {
		if f.hitCount(k) != before[k] {
			t.Errorf("%s fetched again (%d -> %d)", k, before[k], f.hitCount(k))
		}
	}
	if f.hitCount("/api/v1/nodes") != before["/api/v1/nodes"]+1 {
		t.Error("nodes must be listed every cycle")
	}
	if len(s2.HelmReleases) != 1 || len(s2.CRDs) != len(s.CRDs) || len(s2.KubeletConfigs) != 2 || len(s2.Errors) != 1 {
		t.Errorf("cached cycle: releases=%d crds=%d configz=%d errors=%v", len(s2.HelmReleases), len(s2.CRDs), len(s2.KubeletConfigs), s2.Errors)
	}
	if s2.Traffic.Requests >= s.Traffic.Requests {
		t.Errorf("cached cycle should cost fewer requests: %d vs %d", s2.Traffic.Requests, s.Traffic.Requests)
	}

	// a changed helm release secret invalidates the cache
	f.setMeta("/api/v1/secrets", metav1.ObjectMeta{Namespace: "web", Name: "sh.helm.release.v1.nginx.v2", ResourceVersion: "11", Labels: map[string]string{"owner": "helm"}})
	c.Fetch(ctx)
	if f.hitCount("/api/v1/secrets") != before["/api/v1/secrets"]+1 {
		t.Error("helm payloads not re-read after the release secret changed")
	}

	// R resets the denied gate and the list is tried again
	c.ResetDenied()
	c.Fetch(ctx)
	if f.hitCount("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings") != before["/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"]+1 {
		t.Error("denied list not retried after ResetDenied")
	}
}

func TestFetchNoCaches(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	c := f.client(t, Options{})
	ctx := context.Background()
	c.Fetch(ctx)
	c.Fetch(ctx)
	if n := f.hitCount("/api/v1/nodes/cp-1/proxy/configz"); n != 2 {
		t.Errorf("configz with ConfigzTTL 0: %d hits", n)
	}
	if n := f.hitCount("/apis/apiextensions.k8s.io/v1/customresourcedefinitions"); n != 2 {
		t.Errorf("discovery with DiscoveryTTL 0: %d hits", n)
	}
	// quorum reads: no resourceVersion=0
	if c.listOpts().ResourceVersion != "" {
		t.Error("WatchCache off must not set resourceVersion")
	}
	if DefaultOptions().WatchCache && f.client(t, DefaultOptions()).listOpts().ResourceVersion != "0" {
		t.Error("WatchCache on must list with resourceVersion=0")
	}
}

func TestFetchKubeletProxyDenied(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	for _, n := range []string{"cp-1", "w-1"} {
		f.denyWith("/api/v1/nodes/"+n+"/proxy/configz", http.StatusForbidden)
		f.denyWith("/api/v1/nodes/"+n+"/proxy/stats/summary", http.StatusForbidden)
	}
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	s := c.Fetch(ctx)
	// (client-go's Result.Raw() reports the generic "unknown (get nodes X)"
	// for a JSON Status; the reason is still Forbidden, which is what the
	// denied gate keys on)
	if s.KubeletCfgErr == "" || s.PVCUsageErr == "" || len(s.KubeletConfigs) != 0 || len(s.PVCUsage) != 0 {
		t.Errorf("denied proxies: cfg=%q usage=%q", s.KubeletCfgErr, s.PVCUsageErr)
	}
	got := c.DeniedList()
	if strings.Join(got, ",") != "clusters.provisioning.cattle.io,kubeadm-config,nodes/proxy configz,nodes/proxy stats,plans.upgrade.cattle.io,tridentbackends.trident.netapp.io,volumeattachments,volumes.longhorn.io" {
		t.Errorf("denied list: %v", got)
	}
	hits := f.hitCount("/api/v1/nodes/cp-1/proxy/configz") + f.hitCount("/api/v1/nodes/w-1/proxy/configz")
	kaHits := f.hitCount("/api/v1/namespaces/kube-system/configmaps/kubeadm-config")
	s = c.Fetch(ctx)
	if h := f.hitCount("/api/v1/namespaces/kube-system/configmaps/kubeadm-config"); h != kaHits {
		t.Errorf("kubeadm-config asked again while absent: %d -> %d", kaHits, h)
	}
	if h := f.hitCount("/api/v1/nodes/cp-1/proxy/configz") + f.hitCount("/api/v1/nodes/w-1/proxy/configz"); h != hits {
		t.Errorf("nodes/proxy asked again while denied: %d -> %d", hits, h)
	}
	if s.KubeletCfgErr == "" || s.PVCUsageErr == "" {
		t.Errorf("cached denial must still be reported: cfg=%q usage=%q", s.KubeletCfgErr, s.PVCUsageErr)
	}
}

func TestFetchTransportErrors(t *testing.T) {
	// a server that refuses everything: every required list is an error,
	// nothing is remembered as denied (transport/500 errors are retried)
	f := newFakeAPI(t)
	f.unknownCode = http.StatusInternalServerError
	for p := range discoveryDocs {
		f.denyWith(p, http.StatusInternalServerError)
	}
	c := f.client(t, DefaultOptions())
	s := c.Fetch(context.Background())
	if len(s.Errors) < 15 || s.Version != "" || s.Distribution != "unknown" {
		t.Errorf("errors=%d version=%q dist=%q", len(s.Errors), s.Version, s.Distribution)
	}
	for i := 1; i < len(s.Errors); i++ {
		if s.Errors[i-1] > s.Errors[i] {
			t.Errorf("errors not sorted: %q > %q", s.Errors[i-1], s.Errors[i])
		}
	}
	if len(c.DeniedList()) != 0 {
		t.Errorf("500s remembered as denied: %v", c.DeniedList())
	}
	if len(s.Readyz) != 0 || s.MetricsAvailable || len(s.CRDs) != 0 {
		t.Errorf("partial results on a dead server: %+v %v %d", s.Readyz, s.MetricsAvailable, len(s.CRDs))
	}
}

func TestHealthz(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	f.setRaw("/readyz", http.StatusOK, "[+]ping ok\n[+]log ok\nreadyz check passed\n")
	checks, err := c.healthz(ctx, "/readyz")
	if err != nil || len(checks) != 2 || !checks[0].OK || checks[0].Name != "ping" || checks[0].Detail != "ok" {
		t.Errorf("ok body: %v %+v", err, checks)
	}
	// a 503 with an empty body is an error; with lines it is data
	f.setRaw("/livez", http.StatusServiceUnavailable, "")
	if _, err := c.healthz(ctx, "/livez"); err == nil {
		t.Error("empty failing body must error")
	}
	f.setRaw("/livez", http.StatusServiceUnavailable, "[-]etcd failed: dial tcp: refused\n")
	checks, err = c.healthz(ctx, "/livez")
	if err != nil || len(checks) != 1 || checks[0].OK || checks[0].Detail != "failed: dial tcp: refused" {
		t.Errorf("failing lines: %v %+v", err, checks)
	}
	// a failing status with no parsable lines is an error
	f.setRaw("/livez", http.StatusServiceUnavailable, "no checks here\n")
	if _, err := c.healthz(ctx, "/livez"); err == nil {
		t.Error("unparsable failing body must error")
	}
}

func TestNodeMetricsAndKubeletParsing(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	if _, err := c.nodeMetrics(ctx); err == nil {
		t.Error("metrics-server missing must error")
	}
	f.setRaw("/apis/metrics.k8s.io/v1beta1/nodes", http.StatusOK, "not json")
	if _, err := c.nodeMetrics(ctx); err == nil {
		t.Error("bad json must error")
	}
	f.setRaw("/apis/metrics.k8s.io/v1beta1/nodes", http.StatusOK, `{"items":[{"metadata":{"name":"n"},"usage":{"cpu":"garbage","memory":"2Ki"}}]}`)
	m, err := c.nodeMetrics(ctx)
	if err != nil || m["n"].CPUMilli != 0 || m["n"].MemBytes != 2048 {
		t.Errorf("lenient quantities: %v %+v", err, m)
	}

	f.setRaw("/api/v1/nodes/n/proxy/configz", http.StatusOK, `{"other":1}`)
	if _, err := c.kubeletConfigz(ctx, "n"); err == nil || !strings.Contains(err.Error(), "no kubeletconfig") {
		t.Errorf("configz without kubeletconfig: %v", err)
	}
	f.setRaw("/api/v1/nodes/n/proxy/configz", http.StatusOK, `{`)
	if _, err := c.kubeletConfigz(ctx, "n"); err == nil {
		t.Error("configz bad json must error")
	}
	if _, err := c.kubeletConfigz(ctx, "missing"); err == nil {
		t.Error("configz 404 must error")
	}
	f.setRaw("/api/v1/nodes/n/proxy/stats/summary", http.StatusOK, `{"pods":`)
	if _, err := c.kubeletVolumeStats(ctx, "n"); err == nil {
		t.Error("stats bad json must error")
	}
	if _, err := c.kubeletVolumeStats(ctx, "missing"); err == nil {
		t.Error("stats 404 must error")
	}
	// cachedConfigz: a failed read is not cached, a good one is
	c.Opts.ConfigzTTL = time.Minute
	f.setRaw("/api/v1/nodes/n/proxy/configz", http.StatusOK, `{"kubeletconfig":{"a":1}}`)
	if _, err := c.cachedConfigz(ctx, "n"); err != nil {
		t.Fatal(err)
	}
	f.setRaw("/api/v1/nodes/n/proxy/configz", http.StatusOK, `{"kubeletconfig":{"a":2}}`)
	cfg, _ := c.cachedConfigz(ctx, "n")
	if cfg["a"] != float64(1) {
		t.Errorf("configz not served from cache: %v", cfg)
	}
	c.configz["n"] = configzEntry{cfg: cfg, at: time.Now().Add(-2 * time.Minute)}
	cfg, _ = c.cachedConfigz(ctx, "n")
	if cfg["a"] != float64(2) {
		t.Errorf("expired configz not refreshed: %v", cfg)
	}
}

func TestS3SecretAndKubeadmConfig(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t, DefaultOptions())
	ctx := context.Background()
	if info := c.S3Secret(ctx, "rke2-etcd-s3-config"); info.Found || info.Err == "" || info.Name != "rke2-etcd-s3-config" {
		t.Errorf("missing secret: %+v", info)
	}
	f.set("/api/v1/namespaces/kube-system/secrets/rke2-etcd-s3-config", corev1.Secret{TypeMeta: tm("Secret"), Data: map[string][]byte{
		"etcd-s3-endpoint": []byte("minio:9000"), "etcd-s3-bucket": []byte("etcd"), "etcd-s3-folder": []byte("prod"), "etcd-s3-region": []byte("us-east-1"),
		"etcd-s3-access-key": []byte("AK"), "etcd-s3-secret-key": []byte("SK"), "etcd-s3-endpoint-ca": []byte("-----BEGIN CERTIFICATE-----"), "etcd-s3-skip-ssl-verify": []byte("true"), "etcd-s3-insecure": []byte("false"),
	}})
	info := c.S3Secret(ctx, "rke2-etcd-s3-config")
	if !info.Found || info.Endpoint != "minio:9000" || info.Bucket != "etcd" || info.Folder != "prod" || info.Region != "us-east-1" || !info.HasCredentials || !info.SkipSSLVerify || info.Insecure || !strings.HasPrefix(info.EndpointCA, "-----BEGIN") || info.Err != "" {
		t.Errorf("s3 secret: %+v", info)
	}

	if kc, err := c.kubeadmConfig(ctx); kc != nil || err == nil {
		t.Errorf("no kubeadm-config: %+v %v", kc, err)
	}
	f.set("/api/v1/namespaces/kube-system/configmaps/kubeadm-config", corev1.ConfigMap{TypeMeta: tm("ConfigMap"), Data: map[string]string{"ClusterStatus": "x"}})
	if kc, _ := c.kubeadmConfig(ctx); kc != nil {
		t.Errorf("no ClusterConfiguration key: %+v", kc)
	}
	f.set("/api/v1/namespaces/kube-system/configmaps/kubeadm-config", corev1.ConfigMap{TypeMeta: tm("ConfigMap"), Data: map[string]string{"ClusterConfiguration": ": : not yaml ["}})
	if kc, _ := c.kubeadmConfig(ctx); kc != nil {
		t.Errorf("bad yaml: %+v", kc)
	}
	f.set("/api/v1/namespaces/kube-system/configmaps/kubeadm-config", corev1.ConfigMap{TypeMeta: tm("ConfigMap"), Data: map[string]string{"ClusterConfiguration": "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\nclusterName: prod\ncontrolPlaneEndpoint: k8s.example.com:6443\nkubernetesVersion: v1.30.4\napiServer:\n  certSANs:\n  - k8s.example.com\n  - 10.0.0.100\nnetworking:\n  serviceSubnet: 10.96.0.0/12\n"}})
	kc, _ := c.kubeadmConfig(ctx)
	if kc == nil || kc.ClusterName != "prod" || kc.ControlPlaneEndpoint != "k8s.example.com:6443" || kc.KubernetesVersion != "v1.30.4" || len(kc.CertSANs) != 2 || kc.ServiceSubnet != "10.96.0.0/12" {
		t.Errorf("kubeadm config: %+v", kc)
	}
}

func TestRKE2SnapshotsAbsent(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t, DefaultOptions())
	if recs := c.rke2Snapshots(context.Background()); len(recs) != 0 {
		t.Errorf("no CRD, no configmap: %+v", recs)
	}
	// the missing CRD type is remembered so it is not asked again
	if _, ok := c.Denied("etcdsnapshotfiles.k3s.cattle.io"); !ok {
		t.Error("404 on the CRD list not remembered")
	}
	if charts := c.helmCharts(context.Background()); charts != nil {
		t.Errorf("no HelmChart CRD: %+v", charts)
	}
}

func TestCheckKubeconfig(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client(t, DefaultOptions())
	if err := CheckKubeconfig(c.Config.Host, ""); err == nil {
		t.Error("a URL is not a kubeconfig path")
	}
	if _, err := New("/nonexistent/kubeconfig", "nope"); err == nil {
		t.Error("missing kubeconfig must fail")
	}
	if _, err := NewWithOptions("", "no-such-context", DefaultOptions()); err == nil {
		t.Error("unknown context must fail")
	}
}

func podNames(pods []corev1.Pod) []string {
	var out []string
	for _, p := range pods {
		out = append(out, p.Name)
	}
	return out
}
