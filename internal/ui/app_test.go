package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/helmcheck"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/logs"
	"k8s-health-tui/internal/nodeinfo"
)

func testApp() *App {
	cfg := config.Default()
	a := &App{
		cfg:        cfg,
		client:     &k8s.Client{Context: "test", Host: "https://10.0.0.1:6443"},
		nodes:      map[string]*nodeinfo.Info{},
		pending:    map[string]bool{},
		etcd:       map[string]*etcd.Probe{},
		etcdPend:   map[string]bool{},
		logSum:     map[string]*logs.Summary{},
		helmLatest: map[string]helmcheck.Latest{"nginx": {Version: "99.0.0", Source: "repo"}},
		sshEnabled: true,
		width:      140,
		height:     40,
	}
	now := metav1.Now()
	one := int32(1)
	a.snap = &k8s.Snapshot{
		Taken: time.Now(), Version: "v1.30.4+rke2r1", Distribution: "rke2",
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}, CreationTimestamp: now},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}, Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}}, NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.30.4+rke2r1"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "w-1", CreationTimestamp: now}, Spec: corev1.NodeSpec{Unschedulable: true},
				Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Message: "kubelet stopped"}}, NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.30.4+rke2r1"}}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "default", CreationTimestamp: now}, Spec: corev1.PodSpec{NodeName: "w-1", Containers: []corev1.Container{{Name: "c", Image: "nginx:1"}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "c", RestartCount: 7, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: now}}}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-cp-1", Namespace: "kube-system", Labels: map[string]string{"component": "kube-apiserver"}}, Spec: corev1.PodSpec{NodeName: "cp-1", Containers: []corev1.Container{{Name: "kube-apiserver", Args: []string{"--anonymous-auth=false"}, Image: "registry.example.com/rancher/hardened-kubernetes:v1.30.4"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		},
		Namespaces:     []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, {ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}, {ObjectMeta: metav1.ObjectMeta{Name: "team-a"}}},
		Events:         []corev1.Event{{ObjectMeta: metav1.ObjectMeta{Name: "e1", Namespace: "default"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "app-1"}, Reason: "BackOff", Message: "Back-off restarting failed container", Count: 12, LastTimestamp: now, Type: "Warning"}},
		PVCs:           []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default", CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour))}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}},
		PVs:            []corev1.PersistentVolume{{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}, Spec: corev1.PersistentVolumeSpec{StorageClassName: "longhorn"}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased}}},
		StorageClasses: []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: "longhorn", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}}, Provisioner: "driver.longhorn.io"}},
		CSIDrivers:     []storagev1.CSIDriver{{ObjectMeta: metav1.ObjectMeta{Name: "driver.longhorn.io"}}},
		Deployments:    []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}, Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{UnavailableReplicas: 1}}},
		DaemonSets:     []appsv1.DaemonSet{{ObjectMeta: metav1.ObjectMeta{Name: "rke2-canal", Namespace: "kube-system"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, NumberReady: 2}}},
		Readyz:         []k8s.APICheck{{Name: "etcd", OK: true}, {Name: "poststarthook/x", OK: false, Detail: "failed: reason withheld"}},
		HelmReleases:   []k8s.HelmRelease{{Namespace: "default", Name: "web", Chart: "nginx", Version: "15.0.0", AppVersion: "1.25", Revision: 2, Status: "deployed", Updated: time.Now(), ValuesYAML: "replicaCount: 2\n"}},
		HelmCharts:     []k8s.HelmChartCR{{Namespace: "kube-system", Name: "rke2-canal", Chart: "https://rke2-charts/rke2-canal.tgz", Version: "v3.28", HasConfig: true, ConfigValues: "calico:\n  vethuMTU: 1400\n"}},
		RKE2Snapshots:  []k8s.EtcdSnapshotRecord{{Name: "etcd-snapshot-cp-1-1", Node: "cp-1", Created: time.Now().Add(-2 * time.Hour), Size: 5e6, Status: "successful", Source: "crd"}},
		Rancher:        &k8s.RancherInfo{Managed: true, Server: "https://rancher.example.com", ClusterAgent: "1/1 ready", ClusterAgentOK: true, Env: map[string]string{"CATTLE_SERVER": "https://rancher.example.com", "CATTLE_TOKEN": "<masked>"}},
		NodeMetrics:    map[string]k8s.NodeMetric{},
		KubeletConfigs: map[string]map[string]any{"cp-1": {"authentication": map[string]any{"anonymous": map[string]any{"enabled": false}}}},
	}
	a.nodes["cp-1"] = nodeinfo.Parse("cp-1", "10.0.0.1", nodeSample, time.Now())
	a.nodes["w-1"] = &nodeinfo.Info{Node: "w-1", Err: fmt.Errorf("dial tcp: connection refused")}
	a.etcd["cp-1"] = etcd.Parse("cp-1", etcdSample)
	a.s3 = &k8s.S3SecretInfo{Name: "rke2-s3", Found: true, Endpoint: "s3.example.com", Bucket: "b", HasCredentials: true}
	a.recompute()
	return a
}

func TestRenderAllTabsAndDetails(t *testing.T) {
	a := testApp()
	if len(a.findings) == 0 {
		t.Fatalf("expected findings")
	}
	for tb := tab(0); tb < tabCount; tb++ {
		a.tab = tb
		a.cursor[tb] = 0
		v := a.View()
		if !strings.Contains(v, tabNames[tb]) {
			t.Errorf("tab %s not rendered", tabNames[tb])
		}
		if n := len(strings.Split(v, "\n")); n != a.height {
			t.Errorf("tab %s rendered %d lines, want %d", tabNames[tb], n, a.height)
		}
		// exercise movement and detail on every tab
		a.move(1)
		a.move(-1)
		a.openDetail()
		if a.overlay == ovDetail {
			_ = a.View()
			a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyPgDown})
			_ = a.View()
			a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEsc})
		}
		a.problemOnly = true
		_ = a.View()
		a.problemOnly = false
	}
	// filter + namespace overlay + help
	a.tab = tabWorkloads
	a.filters[tabWorkloads] = "app-1"
	if c := a.currentContent(); len(a.filteredRows(c)) != 1 {
		t.Errorf("filter should leave 1 row")
	}
	a.overlay = ovNamespace
	a.nsInput.SetValue("team")
	if opts := a.nsOptions(); len(opts) != 2 || opts[1] != "team-a" {
		t.Errorf("ns options: %v", opts)
	}
	_ = a.View()
	a.nsCursor = 1
	a.handleOverlayKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.namespace != "team-a" {
		t.Errorf("namespace not applied: %q", a.namespace)
	}
	a.overlay = ovHelp
	_ = a.View()
	// tiny terminal must not panic
	a.width, a.height = 20, 6
	for tb := tab(0); tb < tabCount; tb++ {
		a.tab = tb
		_ = a.View()
	}
}

func TestKeyHandling(t *testing.T) {
	a := testApp()
	a.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if a.tab != tabNodes {
		t.Errorf("tab key")
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'-'}})
	if a.tab != tabLogs {
		t.Errorf("'-' should jump to Logs, got %v", a.tab)
	}
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if !a.problemOnly {
		t.Errorf("problems toggle")
	}
	_, cmd := a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Errorf("q should quit")
	}
}

const nodeSample = `
===TIME
1
===HOST
cp-1
5.15
x86_64
===UPTIME
1000 0
===LOAD
0.5 0.4 0.3 1/1 1
===NPROC
2
===STAT1
cpu 10 0 10 100 0 0 0 0 0 0
===STAT2
cpu 20 0 20 190 0 0 0 0 0 0
===MEM
MemTotal: 1000 kB
MemAvailable: 500 kB
===DF
Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/sda1 ext4 100 95 5 95% /
===SVC
rke2-server loaded active running
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

const etcdSample = `
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
