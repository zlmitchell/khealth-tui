package checks

import (
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stig"
)

// The same node / etcd probe output the UI tests use: an rke2 server with a
// 95% full root, an expired admin cert, a fatal journal line, an etcd member
// with a NOSPACE alarm and a second member that no node object matches.
const evalNodeSample = `
===TIME
1
===HOST
cp-1
5.15
x86_64
===UPTIME
1000 0
===LOAD
9.5 0.4 0.3 1/1 1
===NPROC
2
===STAT1
cpu 10 0 10 100 0 0 0 0 0 0
===STAT2
cpu 20 0 20 190 0 0 0 0 0 0
===MEM
MemTotal: 1000 kB
MemAvailable: 50 kB
===DF
Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/sda1 ext4 100 95 5 95% /
/dev/sdb1 ext4 100 85 15 85% /var/lib/rancher
===SVC
rke2-server loaded inactive dead
rancher-system-agent loaded inactive dead
===DIST
/var/lib/rancher/rke2/server
===CERTS
/var/lib/rancher/rke2/server/tls/client-admin.crt|Jan 1 00:00:00 2020 GMT
===RKE2CFG
--- /etc/rancher/rke2/config.yaml
profile: cis
cni: canal
===REGISTRIES
--- /etc/rancher/rke2/registries.yaml
mirrors:
  docker.io:
    endpoint:
      - https://mirror
===CRICTL
crictl=/x
===IMAGES
{"images":[{"id":"sha256:a","repoTags":["nginx:1"],"size":"10"},{"id":"sha256:b","repoTags":["old:1"],"size":"6000000000"}]}
===CONTAINERS
{"containers":[{"id":"c","metadata":{"name":"c"},"image":{"image":"sha256:a"},"imageRef":"sha256:a","labels":{"io.kubernetes.pod.namespace":"default","io.kubernetes.pod.name":"app-1"}}]}
===TARBALLS
--- /var/lib/rancher/rke2/agent/images/x.tar|10|1
[{"RepoTags":["nginx:1","other:2"]}]
===JOURNAL
2024-09-18T10:00:00+00:00 cp-1 rke2[1]: level=fatal msg="token does not match"
2024-09-18T10:00:01+00:00 cp-1 rke2[1]: msg="Waiting for API server to become available"
===END
`

const evalEtcdSample = `
===DIST
rke2
===PATHS
endpoint=https://127.0.0.1:2379
datadir=/var/lib/rancher/rke2/server/db/etcd
===SOURCE
static-pod /x/etcd.yaml
===RKE2CONFIG
/etc/rancher/rke2/config.yaml: etcd-s3: true
/etc/rancher/rke2/config.yaml: etcd-s3-config-secret: rke2-s3
===CONFIGDUMP
--- /var/lib/rancher/rke2/server/db/etcd/config
client-cert-auth: true
===HEALTH
{"health":"true"}
===METRICS
etcd_server_has_leader 1
etcd_mvcc_db_total_size_in_bytes 2.0e+09
etcd_mvcc_db_total_size_in_use_in_bytes 5.0e+08
etcd_server_quota_backend_bytes 2.147483648e+09
etcd_disk_wal_fsync_duration_seconds_sum 50
etcd_disk_wal_fsync_duration_seconds_count 1000
===ETCDCTL
via=crictl x
---MEMBERS
{"members":[{"ID":1,"name":"cp-1","peerURLs":["https://10.0.0.1:2380"]},{"ID":2,"name":"cp-2","peerURLs":["https://10.0.0.2:2380"]}]}
---STATUS
[{"Endpoint":"a","Status":{"header":{"member_id":1},"version":"3.5.16","dbSize":1,"leader":1}}]
---ALARMS
{"alarms":[{"memberID":1,"alarm":1}]}
===DATADIR
/var/lib/rancher/rke2/server/db/etcd
100
/dev/sda1 100 95 5 95% /
===SNAPSHOTS
--- /var/lib/rancher/rke2/server/db/snapshots
100|1|/var/lib/rancher/rke2/server/db/snapshots/old
===END
`

func evalInput(t *testing.T) Input {
	t.Helper()
	now := time.Now()
	mnow := metav1.NewTime(now)
	old := metav1.NewTime(now.Add(-2 * time.Hour))
	one, three := int32(1), int32(3)
	suspend := true
	fleetDown := false
	alloc := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("4Gi"), corev1.ResourcePods: resource.MustParse("10")}
	req := corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1900m"), corev1.ResourceMemory: resource.MustParse("3900Mi")}}
	snap := &k8s.Snapshot{
		Taken: now, Version: "v1.30.4+rke2r1", Distribution: "rke2", MetricsAvailable: true,
		Errors: []string{"jobs.batch (forbidden)"},
		Readyz: []k8s.APICheck{{Name: "etcd", OK: true}, {Name: "poststarthook/x", OK: false, Detail: "failed: reason withheld"}},
		Livez:  []k8s.APICheck{{Name: "log", OK: false, Detail: "failed"}},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}, CreationTimestamp: old},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}, {Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue, Message: "kubelet has memory pressure"}},
					Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}}, NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.30.4+rke2r1"}, Allocatable: alloc}},
			{ObjectMeta: metav1.ObjectMeta{Name: "w-1", CreationTimestamp: old}, Spec: corev1.NodeSpec{Unschedulable: true},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Message: "kubelet stopped"}, {Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionTrue, Message: "no CNI"}},
					NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.29.0+rke2r1"}, Allocatable: alloc}},
			{ObjectMeta: metav1.ObjectMeta{Name: "w-2", CreationTimestamp: old},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}, NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.30.4+rke2r1"}, Allocatable: alloc}},
		},
		NodeMetrics: map[string]k8s.NodeMetric{"w-2": {CPUMilli: 1950, MemBytes: 4 << 30}},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "default", CreationTimestamp: old}, Spec: corev1.PodSpec{NodeName: "w-1", ServiceAccountName: "missing-sa", Containers: []corev1.Container{{Name: "c", Image: "nginx:1", Resources: req}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "c", RestartCount: 7, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: mnow}}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pull", Namespace: "default", CreationTimestamp: old}, Spec: corev1.PodSpec{NodeName: "w-2", Containers: []corev1.Container{{Name: "c", Image: "nope:1"}}},
				Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "c", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "default", CreationTimestamp: old}, Spec: corev1.PodSpec{NodeName: "w-2", Containers: []corev1.Container{{Name: "c", Image: "x", Env: []corev1.EnvVar{{Name: "K", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "gone-secret"}, Key: "k"}}}, {Name: "C", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "gone-cm"}, Key: "k"}}}}}},
				Volumes: []corev1.Volume{{Name: "s", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "gone-secret"}}}, {Name: "c", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "gone-cm"}}}}, {Name: "p", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "gone-pvc"}}}}},
				Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "c", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CreateContainerConfigError"}}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "evicted", Namespace: "default", CreationTimestamp: old}, Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "default", CreationTimestamp: old}, Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Error"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "unknown", Namespace: "default", CreationTimestamp: old}, Status: corev1.PodStatus{Phase: corev1.PodUnknown}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "default", CreationTimestamp: old}, Status: corev1.PodStatus{Phase: corev1.PodPending}},
			{ObjectMeta: metav1.ObjectMeta{Name: "term", Namespace: "default", CreationTimestamp: old, DeletionTimestamp: &old}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Name: "notready", Namespace: "default", CreationTimestamp: old}, Spec: corev1.PodSpec{NodeName: "w-2", Containers: []corev1.Container{{Name: "a"}, {Name: "b"}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "a", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}, {Name: "b", Ready: false, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}}, Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"--anonymous-auth=false"}, Image: "registry.example.com/rancher/hardened-kubernetes:v1.30.4"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{ObjectMeta: metav1.ObjectMeta{Name: "user-on-cp", Namespace: "team-a", CreationTimestamp: old}, Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "c", Image: "x", Resources: req}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		},
		Namespaces:     []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, {ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}, {ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}},
		Events:         []corev1.Event{{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "default"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "app-1"}, Reason: "BackOff", Message: "Back-off restarting failed container", Count: 12, LastTimestamp: mnow, Type: "Warning"}},
		PVCs:           []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default", CreationTimestamp: old}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}, {ObjectMeta: metav1.ObjectMeta{Name: "lost", Namespace: "default", CreationTimestamp: old}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimLost}}},
		PVs:            []corev1.PersistentVolume{{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}, Spec: corev1.PersistentVolumeSpec{StorageClassName: "longhorn"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased}}, {ObjectMeta: metav1.ObjectMeta{Name: "pv-2"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeFailed, Message: "backend gone"}}},
		StorageClasses: []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "longhorn", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}}, Provisioner: "driver.longhorn.io"}, {ObjectMeta: metav1.ObjectMeta{Name: "nfs", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}}, Provisioner: "nfs.csi.k8s.io"}},
		CSIDrivers:     []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "driver.longhorn.io"}}},
		Deployments:    []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}, Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{UnavailableReplicas: 1}}},
		DaemonSets:     []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "rke2-canal", Namespace: "kube-system"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 2}}},
		StatefulSets:   []appsv1.StatefulSet{{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default"}, Spec: appsv1.StatefulSetSpec{Replicas: &three}, Status: appsv1.StatefulSetStatus{ReadyReplicas: 1}}},
		Jobs:           []batchv1.Job{{ObjectMeta: metav1.ObjectMeta{Name: "migrate", Namespace: "default"}, Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", LastTransitionTime: mnow}}}}},
		CronJobs:       []batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "default"}, Spec: batchv1.CronJobSpec{Suspend: &suspend}}},
		Ingresses:      []networkingv1.Ingress{{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}, Spec: networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{Hosts: []string{"web.example.com"}, SecretName: "gone-tls"}}}}},
		HelmReleases: []k8s.HelmRelease{
			{Namespace: "default", Name: "web", Chart: "nginx", Version: "15.0.0", AppVersion: "1.25", Revision: 2, Status: "deployed", Updated: now},
			{Namespace: "default", Name: "broken", Chart: "x", Version: "1.0.0", Revision: 1, Status: "failed", Updated: now},
		},
		HelmCharts:     []k8s.HelmChartCR{{Namespace: "kube-system", Name: "rke2-canal", Chart: "https://rke2-charts/rke2-canal.tgz", Version: "v3.28", Failed: true, JobName: "helm-install-rke2-canal"}},
		RKE2Snapshots:  []k8s.EtcdSnapshotRecord{{Name: "etcd-snapshot-cp-1-1", Node: "cp-1", Created: now.Add(-2 * time.Hour), Size: 5e6, Status: "successful", Source: "crd"}},
		Rancher:        &k8s.RancherInfo{Managed: true, Server: "https://rancher.example.com", ClusterAgent: "0/1 ready", ClusterAgentOK: false, FleetAgentOK: &fleetDown},
		KubeletConfigs: map[string]map[string]any{"cp-1": {"authentication": map[string]any{"anonymous": map[string]any{"enabled": true}}}},
	}
	nodes := map[string]*nodeinfo.Info{
		"cp-1": nodeinfo.Parse("cp-1", "10.0.0.1", evalNodeSample, now),
		"w-1":  {Node: "w-1", Err: errors.New("dial tcp: connection refused")},
	}
	// a second reachable node presenting cp-1's host key: a clone
	w2 := nodeinfo.Parse("w-2", "10.0.0.3", evalNodeSample, now)
	w2.Node = "w-2"
	nodes["cp-1"].HostKey, w2.HostKey = "SHA256:same", "SHA256:same"
	nodes["w-2"] = w2
	return Input{
		Snap: snap, Nodes: nodes,
		Etcd:       map[string]*etcd.Probe{"cp-1": etcd.Parse("cp-1", evalEtcdSample)},
		S3:         &k8s.S3SecretInfo{Name: "rke2-s3", Found: true, Endpoint: "s3.example.com", Bucket: "b", HasCredentials: true},
		S3Reach:    map[string]etcd.S3Check{"cp-1": {Node: "cp-1", URL: "https://s3.example.com", OK: false, Detail: "dial tcp: i/o timeout", Checked: now}},
		Logs:       map[string]*logs.Summary{"cp-1": logs.Classify(errorLines(30, now), now)},
		Stig:       []stig.Result{{ID: "V-1", Title: "one", Cat: "I", Status: stig.Fail}, {ID: "V-2", Title: "two", Cat: "II", Status: stig.Pass}},
		APIServer:  "https://10.0.0.1:6443",
		HelmLatest: map[string]helmcheck.Latest{"default/web": {Version: "99.0.0", Source: "repo"}},
		SSHEnabled: true,
		Cfg:        config.Default(),
		Now:        now,
	}
}

func errorLines(n int, now time.Time) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, now.Add(-time.Duration(i)*time.Minute).Format(time.RFC3339)+` cp-1 rke2[1]: level=error msg="failed to sync"`)
	}
	return out
}

func TestEvaluateRichCluster(t *testing.T) {
	in := evalInput(t)
	f := Evaluate(in)
	if len(f) == 0 {
		t.Fatal("no findings")
	}
	for i := 1; i < len(f); i++ {
		if f[i-1].Severity < f[i].Severity {
			t.Fatalf("findings not sorted by severity: %v before %v", f[i-1], f[i])
		}
	}
	has := func(area, obj, msg string) bool {
		for _, x := range f {
			if x.Area == area && strings.Contains(x.Object, obj) && strings.Contains(x.Message, msg) {
				return true
			}
		}
		return false
	}
	want := []struct{ area, obj, msg string }{
		{"cluster", "api", "could not list jobs.batch"},
		{"cluster", "readyz", "poststarthook/x failed"},
		{"cluster", "livez", "log failed"},
		{"node", "w-1", "not Ready: kubelet stopped"},
		{"node", "cp-1", "MemoryPressure"},
		{"node", "w-1", "NetworkUnavailable"},
		{"node", "w-1", "cordoned"},
		{"node", "w-1", "kubelet version v1.29.0+rke2r1 differs"},
		{"node", "w-2", "SSH host key is shared with cp-1"},
		{"node", "cp-1", "/"},
		{"node", "cp-1", "rke2-server"},
		{"node", "cp-1", "client-admin.crt"},
		{"ssh", "w-1", "collection failed"},
		{"etcd", "cluster", "quorum lost"},
		{"etcd", "cp-2", "stale member"},
		{"etcd", "cp-1", "S3 endpoint"},
		{"cluster", "endpoint", "single server node"},
		{"logs", "cp-1", "30 error log lines"},
		{"images", "cp-1", "unused images"},
		{"workload", "default/app-1", "CrashLoopBackOff"},
		{"workload", "default/app-1", "OOMKilled"},
		{"workload", "default/pull", "ImagePullBackOff"},
		{"workload", "default/cfg", "CreateContainerConfigError"},
		{"workload", "default/evicted", "Evicted"},
		{"workload", "default/failed", "Failed"},
		{"workload", "default/unknown", "Unknown phase"},
		{"workload", "default/pending", "Pending for"},
		{"workload", "default/term", "Terminating for"},
		{"workload", "default/notready", "1/2 containers ready"},
		{"workload", "default/deploy/web", "0/1 replicas available"},
		{"workload", "kube-system/ds/rke2-canal", "2/3 ready"},
		{"workload", "default/sts/db", "1/3 ready"},
		{"workload", "default/job/migrate", "failed: BackoffLimitExceeded"},
		{"workload", "default/cronjob/nightly", "suspended"},
		{"storage", "default/pvc/data", "Pending"},
		{"storage", "default/pvc/lost", "Lost"},
		{"storage", "pv/pv-1", "Released"},
		{"storage", "pv/pv-2", "Failed: backend gone"},
		{"storage", "storageclass", "2 default StorageClasses"},
		{"addons", "rancher", "cattle-cluster-agent not ready"},
		{"addons", "rancher", "fleet-agent not ready"},
		{"helm", "kube-system/rke2-canal", "HelmChart install job failed"},
		{"helm", "default/broken", "release status failed"},
		{"helm", "default/web", "15.0.0 -> 99.0.0"},
		{"security", "stig", "V-1"},
		{"etcd", "cp-1", "NOSPACE"},
	}
	for _, w := range want {
		if !has(w.area, w.obj, w.msg) {
			t.Errorf("missing finding %s %s %q", w.area, w.obj, w.msg)
		}
	}
	if t.Failed() {
		for _, x := range f {
			t.Logf("%-5s %-9s %-40s %s", x.Severity, x.Area, x.Object, x.Message)
		}
	}
}

func TestHelmReleaseFix(t *testing.T) {
	failed := k8s.HelmRelease{Namespace: "default", Name: "web", Revision: 3, Status: "failed", History: []k8s.HelmRevision{{Revision: 3, Status: "failed"}, {Revision: 2, Status: "deployed"}}}
	if fix := helmReleaseFix(failed); !strings.Contains(fix, "helm rollback web 2 -n default") || !strings.Contains(fix, "B on the Helm tab") {
		t.Errorf("failed upgrade fix = %q", fix)
	}
	first := k8s.HelmRelease{Namespace: "default", Name: "web", Revision: 1, Status: "failed", History: []k8s.HelmRevision{{Revision: 1, Status: "failed"}}}
	if fix := helmReleaseFix(first); !strings.Contains(fix, "no revision ever deployed") || !strings.Contains(fix, "helm history web -n default") {
		t.Errorf("failed install fix = %q", fix)
	}
}

func TestEvaluateEmptyAndQuiet(t *testing.T) {
	if f := Evaluate(Input{}); f != nil {
		t.Errorf("no snapshot -> nil findings, got %v", f)
	}
	// a healthy single node, no SSH: only the informational metrics note
	now := time.Now()
	in := Input{Cfg: config.Default(), Now: now, Snap: &k8s.Snapshot{Taken: now, Distribution: "kubeadm",
		Nodes:          []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "n1"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}, NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.8"}}}},
		StorageClasses: []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "std"}}},
	}, SSHErr: "no key"}
	f := Evaluate(in)
	var areas []string
	for _, x := range f {
		areas = append(areas, x.Area+"/"+x.Object)
		if x.Severity == SevCrit {
			t.Errorf("healthy cluster should have no CRIT: %v", x)
		}
	}
	joined := strings.Join(areas, " ")
	for _, w := range []string{"ssh/config", "cluster/metrics", "storage/storageclass"} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing %s in %s", w, joined)
		}
	}
}

func TestMergePVCUsage(t *testing.T) {
	snap := &k8s.Snapshot{
		PVCs: []corev1.PersistentVolumeClaim{
			{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-1"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
			{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "default"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-2"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		},
		PVs: []corev1.PersistentVolume{
			{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: "pvc-1"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "pv-2"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: "default", Name: "local"}, PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data/local"}}}},
		},
	}
	snap.PVCs[1].Spec.Resources.Requests = corev1.ResourceList{"storage": resource.MustParse("1Gi")}
	nodes := map[string]*nodeinfo.Info{
		"w-1": {Node: "w-1",
			PVMounts: []nodeinfo.PVMount{{PV: "pv-1", Mountpoint: "/var/lib/kubelet/pods/x/volumes/kubernetes.io~csi/pv-1/mount", SizeKB: 1000, UsedKB: 950, AvailKB: 50, UsePct: 95}},
			PVDirs:   map[string]int64{"/data/local": 512 * 1024}},
		"w-2": {Node: "w-2", Err: errors.New("unreachable")},
	}
	u := MergePVCUsage(snap, nodes)
	got, ok := u["default/data"]
	if !ok {
		t.Fatalf("default/data missing: %v", u)
	}
	if got.Node != "w-1" || got.UsedPct() < 90 || got.Pod != "(ssh df)" {
		t.Errorf("df usage %+v", got)
	}
	local, ok := u["default/local"]
	if !ok || local.Used != 512*1024*1024 || local.Capacity != 1<<30 || local.Available != (1<<30)-512*1024*1024 {
		t.Errorf("du usage %+v (found %v)", local, ok)
	}
	// what the API already knows wins; without node info only that remains
	snap.PVCUsage = map[string]k8s.VolumeUsage{"default/data": {Capacity: 10, Used: 1, Node: "api"}}
	if got := MergePVCUsage(snap, nodes)["default/data"]; got.Node != "api" {
		t.Errorf("API usage should win: %+v", got)
	}
	if got := MergePVCUsage(snap, nil); len(got) != 1 {
		t.Errorf("no node info -> only the API usage, got %v", got)
	}
}
