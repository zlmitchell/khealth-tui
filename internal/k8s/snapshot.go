package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Snapshot is everything we read from the API server in one refresh.
type Snapshot struct {
	Taken        time.Time
	Version      string
	Distribution string // rke2, k3s, kubeadm, unknown

	Nodes          []corev1.Node
	Pods           []corev1.Pod
	Namespaces     []corev1.Namespace
	Events         []corev1.Event
	PVs            []corev1.PersistentVolume
	PVCs           []corev1.PersistentVolumeClaim
	StorageClasses []storagev1.StorageClass
	CSIDrivers     []storagev1.CSIDriver
	CSINodes       []storagev1.CSINode
	Deployments    []appsv1.Deployment
	DaemonSets     []appsv1.DaemonSet
	StatefulSets   []appsv1.StatefulSet
	Jobs           []batchv1.Job
	CronJobs       []batchv1.CronJob
	CRBs           []rbacv1.ClusterRoleBinding
	NetPols        []networkingv1.NetworkPolicy
	Ingresses      []networkingv1.Ingress

	// Names of secrets / configmaps / service accounts (ns/name) from
	// metadata-only lists, used to spot dangling references.
	SecretNames    map[string]bool
	ConfigMapNames map[string]bool
	SANames        map[string]bool

	Readyz []APICheck
	Livez  []APICheck

	NodeMetrics      map[string]NodeMetric
	MetricsAvailable bool

	// KubeletConfigs holds the running kubelet configuration per node read
	// from /api/v1/nodes/<name>/proxy/configz (needs nodes/proxy RBAC).
	KubeletConfigs map[string]map[string]any
	KubeletCfgErr  string

	// PVCUsage is filesystem usage of mounted PVCs from kubelet stats/summary,
	// keyed by "namespace/claim".
	PVCUsage    map[string]VolumeUsage
	PVCUsageErr string // first error from stats/summary (RBAC etc.)

	CRDs []CRDInfo

	RKE2Snapshots []EtcdSnapshotRecord
	HelmCharts    []HelmChartCR
	Kubeadm       *KubeadmConfig // upstream clusters: kube-system/kubeadm-config ClusterConfiguration
	// Cloud provider / CSI extras (cloud.go): Trident backends and the
	// vSphere CPI config; everything else is derived by Snapshot.Cloud.
	TridentBackends []TridentBackend
	VSphereConf     *VSphereConf
	HelmReleases    []HelmRelease
	Rancher         *RancherInfo

	Errors []string

	// FetchDuration / Traffic are what this refresh cost: wall time and the
	// API server requests/bytes it took (docs/PERFORMANCE.md).
	FetchDuration time.Duration
	Traffic       Stats
}

// APICheck is one line of /readyz?verbose or /livez?verbose.
type APICheck struct {
	Name   string
	OK     bool
	Detail string
}

// VolumeUsage is the kubelet-reported usage of a mounted PVC.
type VolumeUsage struct {
	Capacity, Used, Available int64
	Inodes, InodesUsed        int64
	Node, Pod                 string
}

// UsedPct returns used/capacity in percent, or -1.
func (v VolumeUsage) UsedPct() float64 {
	if v.Capacity <= 0 {
		return -1
	}
	return float64(v.Used) * 100 / float64(v.Capacity)
}

// NodeMetric is the metrics.k8s.io usage for a node.
type NodeMetric struct {
	CPUMilli int64
	MemBytes int64
}

// EtcdSnapshotRecord is a cluster-level etcd snapshot record (rke2/k3s).
type EtcdSnapshotRecord struct {
	Name     string
	Node     string
	Location string
	Created  time.Time
	Size     int64
	S3       bool
	Status   string // successful, failed, ...
	Message  string
	Source   string // crd | configmap
}

// S3SecretInfo summarises the rke2 etcd-s3-config-secret without exposing keys.
type S3SecretInfo struct {
	Name           string
	Found          bool
	Endpoint       string
	Bucket         string
	Folder         string
	Region         string
	HasCredentials bool
	EndpointCA     string // PEM content of etcd-s3-endpoint-ca, if set
	SkipSSLVerify  bool
	Insecure       bool // plain http
	Err            string
}

// HelmChartCR is an rke2/k3s helm.cattle.io HelmChart (bundled add-ons).
type HelmChartCR struct {
	Namespace     string
	Name          string
	Chart         string
	Version       string
	Repo          string
	TargetNS      string
	HasConfig     bool // a HelmChartConfig override exists
	JobName       string
	Failed        bool
	ValuesContent string
	ConfigValues  string
}

// RancherInfo describes the Rancher management relationship, if any.
type RancherInfo struct {
	Managed         bool
	Server          string
	ClusterAgent    string // deployment status text
	ClusterAgentOK  bool
	FleetAgentOK    *bool
	FleetNamespace  string
	Env             map[string]string // CATTLE_* env (tokens masked)
	SystemUpgradeOK *bool
	Provisioning    string // "rancher (v2prov)", "imported", ...

	// Management-cluster facts, filled only when this cluster runs Rancher
	// itself (Rancher MCM STIG). See rancher.go.
	Management    bool
	IngressFound  bool
	IngressPorts  []int32         // backend service ports of ingress cattle-system/rancher
	IngressTLS    []string        // TLS secret names on that ingress
	AuthProviders []string        // enabled authconfigs other than local
	GlobalRoles   map[string]bool // global role name -> newUserDefault
	Users         []RancherUser
	MgmtErr       string // first collection error (RBAC / CRDs missing)
}

var checkRe = regexp.MustCompile(`^\[([+-])\](\S+)\s*(.*)$`)

// Fetch gathers the snapshot. Individual failures (RBAC etc.) are recorded in
// Errors rather than aborting.
func (c *Client) Fetch(ctx context.Context) *Snapshot {
	s := &Snapshot{
		Taken:          time.Now(),
		NodeMetrics:    map[string]NodeMetric{},
		KubeletConfigs: map[string]map[string]any{},
		PVCUsage:       map[string]VolumeUsage{},
		SecretNames:    map[string]bool{},
		ConfigMapNames: map[string]bool{},
		SANames:        map[string]bool{},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var helmFPs []string
	fail := func(what string, err error) {
		mu.Lock()
		s.Errors = append(s.Errors, what+": "+err.Error())
		mu.Unlock()
	}
	// run skips calls the token was refused (403) last time within DeniedTTL
	// - the cached error is still reported so the RBAC findings persist -
	// and remembers new refusals.
	run := func(what string, f func() error) {
		if err, ok := c.Denied(what); ok {
			fail(what, err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				c.NoteDenied(what, err, false)
				fail(what, err)
			}
		}()
	}
	// optional is run for calls whose absence is not an error (metrics-server,
	// rke2 CRs, Rancher): skipped while denied or not installed, never reported
	optional := func(what string, f func() error) {
		if _, ok := c.Denied(what); ok {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				c.NoteDenied(what, err, true)
			}
		}()
	}
	all := c.listOpts()
	cs := c.CS
	fetchStart := time.Now()
	statsStart := c.Stats()

	run("version", func() error {
		v, err := cs.Discovery().ServerVersion()
		if err != nil {
			return err
		}
		mu.Lock()
		s.Version = v.GitVersion
		mu.Unlock()
		return nil
	})
	run("nodes", func() error {
		l, err := cs.CoreV1().Nodes().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Nodes = l.Items
		mu.Unlock()
		return nil
	})
	run("pods", func() error {
		l, err := cs.CoreV1().Pods("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Pods = l.Items
		mu.Unlock()
		return nil
	})
	run("namespaces", func() error {
		l, err := cs.CoreV1().Namespaces().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Namespaces = l.Items
		mu.Unlock()
		return nil
	})
	run("events", func() error {
		l, err := cs.CoreV1().Events("").List(ctx, all) // all types; events expire after the apiserver's event-ttl
		if err != nil {
			return err
		}
		mu.Lock()
		s.Events = l.Items
		mu.Unlock()
		return nil
	})
	run("persistentvolumes", func() error {
		l, err := cs.CoreV1().PersistentVolumes().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.PVs = l.Items
		mu.Unlock()
		return nil
	})
	run("persistentvolumeclaims", func() error {
		l, err := cs.CoreV1().PersistentVolumeClaims("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.PVCs = l.Items
		mu.Unlock()
		return nil
	})
	run("storageclasses", func() error {
		l, err := cs.StorageV1().StorageClasses().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.StorageClasses = l.Items
		mu.Unlock()
		return nil
	})
	run("csidrivers", func() error {
		l, err := cs.StorageV1().CSIDrivers().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.CSIDrivers = l.Items
		mu.Unlock()
		return nil
	})
	run("csinodes", func() error {
		l, err := cs.StorageV1().CSINodes().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.CSINodes = l.Items
		mu.Unlock()
		return nil
	})
	run("deployments", func() error {
		l, err := cs.AppsV1().Deployments("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Deployments = l.Items
		mu.Unlock()
		return nil
	})
	run("daemonsets", func() error {
		l, err := cs.AppsV1().DaemonSets("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.DaemonSets = l.Items
		mu.Unlock()
		return nil
	})
	run("statefulsets", func() error {
		l, err := cs.AppsV1().StatefulSets("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.StatefulSets = l.Items
		mu.Unlock()
		return nil
	})
	run("jobs", func() error {
		l, err := cs.BatchV1().Jobs("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Jobs = l.Items
		mu.Unlock()
		return nil
	})
	run("cronjobs", func() error {
		l, err := cs.BatchV1().CronJobs("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.CronJobs = l.Items
		mu.Unlock()
		return nil
	})
	run("clusterrolebindings", func() error {
		l, err := cs.RbacV1().ClusterRoleBindings().List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.CRBs = l.Items
		mu.Unlock()
		return nil
	})
	run("ingresses", func() error {
		l, err := cs.NetworkingV1().Ingresses("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.Ingresses = l.Items
		mu.Unlock()
		return nil
	})
	for _, spec := range []struct {
		res  string
		dest *map[string]bool
	}{{"secrets", &s.SecretNames}, {"configmaps", &s.ConfigMapNames}, {"serviceaccounts", &s.SANames}} {
		spec := spec
		optional(spec.res+"-metadata", func() error { // metadata-only, so cheap even with large secrets
			gvr := schema.GroupVersionResource{Version: "v1", Resource: spec.res}
			l, err := c.Meta.Resource(gvr).List(ctx, all)
			if err != nil {
				return err
			}
			names := make(map[string]bool, len(l.Items))
			var helm []string
			for _, it := range l.Items {
				names[it.Namespace+"/"+it.Name] = true
				if it.Labels["owner"] == "helm" {
					// helm release storage: the fingerprint decides whether the
					// (large) release payloads need to be re-read below
					helm = append(helm, it.Namespace+"/"+it.Name+"@"+it.ResourceVersion)
				}
			}
			sort.Strings(helm)
			mu.Lock()
			*spec.dest = names
			if spec.res != "serviceaccounts" {
				helmFPs = append(helmFPs, spec.res+":"+strings.Join(helm, ","))
			}
			mu.Unlock()
			return nil
		})
	}
	run("networkpolicies", func() error {
		l, err := cs.NetworkingV1().NetworkPolicies("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.NetPols = l.Items
		mu.Unlock()
		return nil
	})
	run("readyz", func() error {
		checks, err := c.healthz(ctx, "/readyz")
		if err != nil {
			return err
		}
		mu.Lock()
		s.Readyz = checks
		mu.Unlock()
		return nil
	})
	run("livez", func() error {
		checks, err := c.healthz(ctx, "/livez")
		if err != nil {
			return err
		}
		mu.Lock()
		s.Livez = checks
		mu.Unlock()
		return nil
	})
	optional("metrics.k8s.io", func() error { // metrics-server is optional: absence is not an error
		m, err := c.nodeMetrics(ctx)
		if err != nil {
			return err
		}
		mu.Lock()
		s.NodeMetrics = m
		s.MetricsAvailable = true
		mu.Unlock()
		return nil
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		recs := c.rke2Snapshots(ctx)
		mu.Lock()
		s.RKE2Snapshots = recs
		mu.Unlock()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		charts := c.helmCharts(ctx)
		mu.Lock()
		s.HelmCharts = charts
		mu.Unlock()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		tb := c.tridentBackends(ctx)
		mu.Lock()
		s.TridentBackends = tb
		mu.Unlock()
	}()
	optional("kubeadm-config", func() error {
		kc := c.kubeadmConfig(ctx)
		mu.Lock()
		s.Kubeadm = kc
		mu.Unlock()
		return nil
	})
	optional("vsphere-cloud-config", func() error {
		vc := c.vsphereConf(ctx)
		mu.Lock()
		s.VSphereConf = vc
		mu.Unlock()
		return nil
	})
	if _, denied := c.Denied("rancher"); !denied {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := c.rancherInfo(ctx)
			mu.Lock()
			s.Rancher = r
			mu.Unlock()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := c.cachedResources(ctx)
		mu.Lock()
		if err == nil {
			s.CRDs = res
		}
		mu.Unlock()
	}()
	wg.Wait()

	// Helm release payloads (every revision of every release, gzipped and
	// base64'd) are the largest secrets in most clusters. Re-read them only
	// when the metadata list shows a release secret/configmap changed.
	sort.Strings(helmFPs)
	fp := strings.Join(helmFPs, ";")
	c.cacheMu.Lock()
	cached, fpOK := c.helmCache, fp != "" && fp == c.helmFP
	c.cacheMu.Unlock()
	if fpOK {
		s.HelmReleases = cached
	} else if err, denied := c.Denied("helm-releases"); denied {
		fail("helm-releases", err)
	} else if rels, err := c.helmReleases(ctx); err != nil {
		c.NoteDenied("helm-releases", err, false)
		fail("helm-releases", err)
	} else {
		s.HelmReleases = rels
		c.cacheMu.Lock()
		c.helmFP, c.helmCache = fp, rels
		c.cacheMu.Unlock()
	}

	// kubelet configz needs the node list first. nodes/proxy is one RBAC
	// rule for every node: once refused, no node is asked again until the
	// DeniedTTL passes (the cached error is still shown).
	var kwg sync.WaitGroup
	sem := make(chan struct{}, 6)
	cfgDenied, cfgOK := c.Denied("nodes/proxy configz")
	statsDenied, statsOK := c.Denied("nodes/proxy stats")
	if cfgOK {
		s.KubeletCfgErr = cfgDenied.Error()
	}
	if statsOK {
		s.PVCUsageErr = statsDenied.Error()
	}
	for _, n := range s.Nodes {
		if cfgOK && statsOK {
			break
		}
		kwg.Add(1)
		go func(name string) {
			defer kwg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var cfg map[string]any
			var usage map[string]VolumeUsage
			err, uerr := cfgDenied, statsDenied
			if !cfgOK {
				if cfg, err = c.cachedConfigz(ctx, name); err != nil {
					c.NoteDenied("nodes/proxy configz", err, false)
				}
			}
			if !statsOK {
				if usage, uerr = c.kubeletVolumeStats(ctx, name); uerr != nil {
					c.NoteDenied("nodes/proxy stats", uerr, false)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			for k, v := range usage {
				s.PVCUsage[k] = v
			}
			if uerr != nil && s.PVCUsageErr == "" {
				s.PVCUsageErr = uerr.Error()
			}
			if err != nil {
				if s.KubeletCfgErr == "" {
					s.KubeletCfgErr = err.Error()
				}
				return
			}
			s.KubeletConfigs[name] = cfg
		}(n.Name)
	}
	kwg.Wait()

	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Name < s.Nodes[j].Name })
	sort.Slice(s.Pods, func(i, j int) bool {
		if s.Pods[i].Namespace != s.Pods[j].Namespace {
			return s.Pods[i].Namespace < s.Pods[j].Namespace
		}
		return s.Pods[i].Name < s.Pods[j].Name
	})
	sort.Slice(s.Namespaces, func(i, j int) bool { return s.Namespaces[i].Name < s.Namespaces[j].Name })
	sort.Slice(s.Events, func(i, j int) bool { return EventTime(&s.Events[i]).After(EventTime(&s.Events[j])) })
	sort.Slice(s.RKE2Snapshots, func(i, j int) bool { return s.RKE2Snapshots[i].Created.After(s.RKE2Snapshots[j].Created) })
	sort.Slice(s.HelmReleases, func(i, j int) bool {
		if s.HelmReleases[i].Namespace != s.HelmReleases[j].Namespace {
			return s.HelmReleases[i].Namespace < s.HelmReleases[j].Namespace
		}
		return s.HelmReleases[i].Name < s.HelmReleases[j].Name
	})
	sort.Strings(s.Errors)
	s.Distribution = detectDistribution(s)
	s.FetchDuration = time.Since(fetchStart)
	s.Traffic = c.Stats().Sub(statsStart)
	return s
}

// cachedResources serves ListResources (discovery + every CRD definition,
// which carries its whole OpenAPI schema) from a TTL cache.
func (c *Client) cachedResources(ctx context.Context) ([]CRDInfo, error) {
	c.cacheMu.Lock()
	if c.discovery != nil && c.Opts.DiscoveryTTL > 0 && time.Since(c.discoveryAt) < c.Opts.DiscoveryTTL {
		res := c.discovery
		c.cacheMu.Unlock()
		return res, nil
	}
	c.cacheMu.Unlock()
	res, err := c.ListResources(ctx)
	if err == nil {
		c.cacheMu.Lock()
		c.discovery, c.discoveryAt = res, time.Now()
		c.cacheMu.Unlock()
	}
	return res, err
}

// cachedConfigz serves the kubelet configz (static for the life of the
// kubelet process) from a TTL cache; kubelet restarts show up within the TTL.
func (c *Client) cachedConfigz(ctx context.Context, node string) (map[string]any, error) {
	c.cacheMu.Lock()
	if e, ok := c.configz[node]; ok && c.Opts.ConfigzTTL > 0 && time.Since(e.at) < c.Opts.ConfigzTTL {
		c.cacheMu.Unlock()
		return e.cfg, nil
	}
	c.cacheMu.Unlock()
	cfg, err := c.kubeletConfigz(ctx, node)
	if err == nil {
		c.cacheMu.Lock()
		c.configz[node] = configzEntry{cfg: cfg, at: time.Now()}
		c.cacheMu.Unlock()
	}
	return cfg, err
}

func (c *Client) healthz(ctx context.Context, path string) ([]APICheck, error) {
	raw, err := c.CS.Discovery().RESTClient().Get().AbsPath(path).Param("verbose", "true").Do(ctx).Raw()
	if len(raw) == 0 && err != nil {
		return nil, err
	}
	var out []APICheck
	for _, line := range strings.Split(string(raw), "\n") {
		m := checkRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		out = append(out, APICheck{Name: m[2], OK: m[1] == "+", Detail: strings.TrimSpace(m[3])})
	}
	if len(out) == 0 && err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) nodeMetrics(ctx context.Context) (map[string]NodeMetric, error) {
	raw, err := c.CS.Discovery().RESTClient().Get().AbsPath("/apis/metrics.k8s.io/v1beta1/nodes").SetHeader("Accept", "application/json").Do(ctx).Raw()
	if err != nil {
		return nil, err
	}
	var ml struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Usage map[string]string `json:"usage"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &ml); err != nil {
		return nil, err
	}
	out := map[string]NodeMetric{}
	for _, it := range ml.Items {
		var m NodeMetric
		if q, err := resource.ParseQuantity(it.Usage["cpu"]); err == nil {
			m.CPUMilli = q.MilliValue()
		}
		if q, err := resource.ParseQuantity(it.Usage["memory"]); err == nil {
			m.MemBytes = q.Value()
		}
		out[it.Metadata.Name] = m
	}
	return out, nil
}

func (c *Client) kubeletConfigz(ctx context.Context, node string) (map[string]any, error) {
	raw, err := c.CS.CoreV1().RESTClient().Get().Resource("nodes").Name(node).SubResource("proxy").Suffix("configz").SetHeader("Accept", "application/json").Do(ctx).Raw()
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		KubeletConfig map[string]any `json:"kubeletconfig"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.KubeletConfig == nil {
		return nil, fmt.Errorf("configz: no kubeletconfig in response")
	}
	return wrapper.KubeletConfig, nil
}

// kubeletVolumeStats reads /stats/summary through the API proxy and returns
// usage for every volume backed by a PVC.
func (c *Client) kubeletVolumeStats(ctx context.Context, node string) (map[string]VolumeUsage, error) {
	raw, err := c.CS.CoreV1().RESTClient().Get().Resource("nodes").Name(node).SubResource("proxy").Suffix("stats/summary").SetHeader("Accept", "application/json").Do(ctx).Raw()
	if err != nil {
		return nil, err
	}
	var doc struct {
		Pods []struct {
			PodRef struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"podRef"`
			Volume []struct {
				Name           string `json:"name"`
				CapacityBytes  int64  `json:"capacityBytes"`
				UsedBytes      int64  `json:"usedBytes"`
				AvailableBytes int64  `json:"availableBytes"`
				Inodes         int64  `json:"inodes"`
				InodesUsed     int64  `json:"inodesUsed"`
				PVCRef         *struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"pvcRef"`
			} `json:"volume"`
		} `json:"pods"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]VolumeUsage{}
	for _, p := range doc.Pods {
		for _, v := range p.Volume {
			if v.PVCRef == nil {
				continue
			}
			key := v.PVCRef.Namespace + "/" + v.PVCRef.Name
			out[key] = VolumeUsage{Capacity: v.CapacityBytes, Used: v.UsedBytes, Available: v.AvailableBytes, Inodes: v.Inodes, InodesUsed: v.InodesUsed, Node: node, Pod: p.PodRef.Namespace + "/" + p.PodRef.Name}
		}
	}
	return out, nil
}

var etcdSnapshotGVR = schema.GroupVersionResource{Group: "k3s.cattle.io", Version: "v1", Resource: "etcdsnapshotfiles"}
var helmChartGVR = schema.GroupVersionResource{Group: "helm.cattle.io", Version: "v1", Resource: "helmcharts"}
var helmChartConfigGVR = schema.GroupVersionResource{Group: "helm.cattle.io", Version: "v1", Resource: "helmchartconfigs"}

func (c *Client) rke2Snapshots(ctx context.Context) []EtcdSnapshotRecord {
	seen := map[string]bool{}
	var out []EtcdSnapshotRecord

	if l, err := c.dynList(ctx, "etcdsnapshotfiles.k3s.cattle.io", etcdSnapshotGVR); err == nil {
		for _, it := range l.Items {
			r := EtcdSnapshotRecord{Source: "crd"}
			r.Name, _, _ = unstructured.NestedString(it.Object, "spec", "snapshotName")
			if r.Name == "" {
				r.Name = it.GetName()
			}
			r.Node, _, _ = unstructured.NestedString(it.Object, "spec", "nodeName")
			r.Location, _, _ = unstructured.NestedString(it.Object, "spec", "location")
			if s3, ok, _ := unstructured.NestedMap(it.Object, "spec", "s3"); ok && len(s3) > 0 {
				r.S3 = true
			}
			if ts, ok, _ := unstructured.NestedString(it.Object, "status", "creationTime"); ok {
				r.Created, _ = time.Parse(time.RFC3339, ts)
			}
			if sz, ok, _ := unstructured.NestedInt64(it.Object, "status", "size"); ok {
				r.Size = sz
			}
			ready, _, _ := unstructured.NestedBool(it.Object, "status", "readyToUse")
			if errMap, ok, _ := unstructured.NestedMap(it.Object, "status", "error"); ok && len(errMap) > 0 {
				r.Status = "failed"
				if msg, ok := errMap["message"].(string); ok {
					r.Message = msg
				}
			} else if ready {
				r.Status = "successful"
			} else {
				r.Status = "pending"
			}
			seen[r.Name] = true
			out = append(out, r)
		}
	}

	for _, cmName := range []string{"rke2-etcd-snapshots", "k3s-etcd-snapshots"} {
		cm, err := c.CS.CoreV1().ConfigMaps("kube-system").Get(ctx, cmName, metav1.GetOptions{})
		if err != nil {
			continue
		}
		for key, val := range cm.Data {
			var rec struct {
				Name      string          `json:"name"`
				Location  string          `json:"location"`
				NodeName  string          `json:"nodeName"`
				CreatedAt string          `json:"createdAt"`
				Size      int64           `json:"size"`
				Status    string          `json:"status"`
				Message   string          `json:"message"`
				S3        json.RawMessage `json:"s3"`
				S3Config  json.RawMessage `json:"s3Config"`
			}
			if err := json.Unmarshal([]byte(val), &rec); err != nil {
				continue
			}
			name := rec.Name
			if name == "" {
				name = key
			}
			if seen[name] {
				continue
			}
			r := EtcdSnapshotRecord{Name: name, Node: rec.NodeName, Location: rec.Location, Size: rec.Size, Status: rec.Status, Message: rec.Message, Source: "configmap"}
			r.Created, _ = time.Parse(time.RFC3339, rec.CreatedAt)
			r.S3 = (len(rec.S3) > 0 && string(rec.S3) != "null") || (len(rec.S3Config) > 0 && string(rec.S3Config) != "null") || strings.HasPrefix(rec.Location, "s3://")
			seen[name] = true
			out = append(out, r)
		}
	}
	return out
}

// S3Secret reads the rke2 etcd S3 config secret from kube-system.
func (c *Client) S3Secret(ctx context.Context, name string) *S3SecretInfo {
	info := &S3SecretInfo{Name: name}
	sec, err := c.CS.CoreV1().Secrets("kube-system").Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		info.Err = err.Error()
		return info
	}
	get := func(k string) string { return string(sec.Data[k]) }
	info.Found = true
	info.Endpoint = get("etcd-s3-endpoint")
	info.Bucket = get("etcd-s3-bucket")
	info.Folder = get("etcd-s3-folder")
	info.Region = get("etcd-s3-region")
	info.HasCredentials = len(sec.Data["etcd-s3-access-key"]) > 0 && len(sec.Data["etcd-s3-secret-key"]) > 0
	info.EndpointCA = get("etcd-s3-endpoint-ca")
	info.SkipSSLVerify = get("etcd-s3-skip-ssl-verify") == "true"
	info.Insecure = get("etcd-s3-insecure") == "true"
	return info
}

func (c *Client) helmCharts(ctx context.Context) []HelmChartCR {
	l, err := c.dynList(ctx, "helmcharts.helm.cattle.io", helmChartGVR)
	if err != nil {
		return nil
	}
	configs := map[string]string{}
	if cl, err := c.dynList(ctx, "helmchartconfigs.helm.cattle.io", helmChartConfigGVR); err == nil {
		for _, it := range cl.Items {
			v, _, _ := unstructured.NestedString(it.Object, "spec", "valuesContent")
			configs[it.GetNamespace()+"/"+it.GetName()] = v
		}
	}
	var out []HelmChartCR
	for _, it := range l.Items {
		h := HelmChartCR{Namespace: it.GetNamespace(), Name: it.GetName()}
		h.Chart, _, _ = unstructured.NestedString(it.Object, "spec", "chart")
		h.Version, _, _ = unstructured.NestedString(it.Object, "spec", "version")
		h.Repo, _, _ = unstructured.NestedString(it.Object, "spec", "repo")
		h.TargetNS, _, _ = unstructured.NestedString(it.Object, "spec", "targetNamespace")
		h.ValuesContent, _, _ = unstructured.NestedString(it.Object, "spec", "valuesContent")
		h.JobName, _, _ = unstructured.NestedString(it.Object, "status", "jobName")
		if conds, ok, _ := unstructured.NestedSlice(it.Object, "status", "conditions"); ok {
			for _, cd := range conds {
				m, _ := cd.(map[string]any)
				if m["type"] == "Failed" && m["status"] == "True" {
					h.Failed = true
				}
			}
		}
		if v, ok := configs[h.Namespace+"/"+h.Name]; ok {
			h.HasConfig = true
			h.ConfigValues = v
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c *Client) rancherInfo(ctx context.Context) *RancherInfo {
	info := &RancherInfo{Env: map[string]string{}}
	dep, err := c.CS.AppsV1().Deployments("cattle-system").Get(ctx, "cattle-cluster-agent", metav1.GetOptions{})
	if err != nil {
		if c.NoteDenied("rancher", err, false) {
			return nil
		}
		if !apierrors.IsNotFound(err) {
			return nil
		}
		// not managed by Rancher (or no access) - check for rancher itself (this could be the management cluster)
		if _, err := c.CS.AppsV1().Deployments("cattle-system").Get(ctx, "rancher", metav1.GetOptions{}); err == nil {
			info.Provisioning = "this cluster runs Rancher (management/local cluster)"
			info.Managed = false
			c.rancherManagement(ctx, info)
			return info
		}
		return info
	}
	info.Managed = true
	for _, ctr := range dep.Spec.Template.Spec.Containers {
		for _, e := range ctr.Env {
			if !strings.HasPrefix(e.Name, "CATTLE_") {
				continue
			}
			v := e.Value
			if e.ValueFrom != nil {
				v = "<from " + describeValueFrom(e.ValueFrom) + ">"
			}
			if strings.Contains(e.Name, "TOKEN") || strings.Contains(e.Name, "SECRET") || strings.Contains(e.Name, "PASSWORD") {
				v = "<masked>"
			}
			info.Env[e.Name] = v
		}
	}
	info.Server = info.Env["CATTLE_SERVER"]
	info.ClusterAgent = fmt.Sprintf("%d/%d ready", dep.Status.ReadyReplicas, dep.Status.Replicas)
	info.ClusterAgentOK = dep.Status.Replicas > 0 && dep.Status.ReadyReplicas == dep.Status.Replicas
	if fdep, err := c.CS.AppsV1().Deployments("cattle-fleet-system").Get(ctx, "fleet-agent", metav1.GetOptions{}); err == nil {
		ok := fdep.Status.Replicas > 0 && fdep.Status.ReadyReplicas == fdep.Status.Replicas
		info.FleetAgentOK = &ok
		info.FleetNamespace = "cattle-fleet-system"
	} else if fss, err := c.CS.AppsV1().StatefulSets("cattle-fleet-system").Get(ctx, "fleet-agent", metav1.GetOptions{}); err == nil {
		ok := fss.Status.Replicas > 0 && fss.Status.ReadyReplicas == fss.Status.Replicas
		info.FleetAgentOK = &ok
		info.FleetNamespace = "cattle-fleet-system"
	}
	if sdep, err := c.CS.AppsV1().Deployments("cattle-system").Get(ctx, "system-upgrade-controller", metav1.GetOptions{}); err == nil {
		ok := sdep.Status.ReadyReplicas == sdep.Status.Replicas
		info.SystemUpgradeOK = &ok
	}
	return info
}

func describeValueFrom(v *corev1.EnvVarSource) string {
	switch {
	case v.SecretKeyRef != nil:
		return "secret " + v.SecretKeyRef.Name
	case v.ConfigMapKeyRef != nil:
		return "configmap " + v.ConfigMapKeyRef.Name
	case v.FieldRef != nil:
		return "field " + v.FieldRef.FieldPath
	}
	return "ref"
}

// detectDistribution names the Kubernetes distribution from node
// annotations/labels and the kubelet version suffix, then from what kubeadm
// leaves behind (the kubeadm-config ConfigMap, kube-apiserver-<node> static
// pods): recent kubeadm no longer annotates nodes with cri-socket.
func detectDistribution(s *Snapshot) string {
	for _, n := range s.Nodes {
		if _, ok := n.Annotations["rke2.io/node-args"]; ok {
			return "rke2"
		}
		if _, ok := n.Annotations["k3s.io/node-args"]; ok {
			return "k3s"
		}
		v := n.Status.NodeInfo.KubeletVersion
		switch {
		case strings.Contains(v, "+rke2"):
			return "rke2"
		case strings.Contains(v, "+k3s"):
			return "k3s"
		case strings.Contains(v, "+k0s"):
			return "k0s"
		case strings.Contains(v, "-eks-"):
			return "eks"
		case strings.Contains(v, "-gke."):
			return "gke"
		}
		if _, ok := n.Annotations["kubeadm.alpha.kubernetes.io/cri-socket"]; ok {
			return "kubeadm"
		}
		if _, ok := n.Annotations["rke.cattle.io/internal-ip"]; ok {
			return "rke1"
		}
		if _, ok := n.Annotations["machineconfiguration.openshift.io/currentConfig"]; ok {
			return "openshift"
		}
		if _, ok := n.Labels["kubernetes.azure.com/agentpool"]; ok {
			return "aks"
		}
		if _, ok := n.Labels["microk8s.io/cluster"]; ok {
			return "microk8s"
		}
		if strings.Contains(n.Status.NodeInfo.OSImage, "Talos") {
			return "talos"
		}
	}
	if s.ConfigMapNames["kube-system/kubeadm-config"] {
		return "kubeadm"
	}
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Namespace == "kube-system" && strings.HasPrefix(p.Name, "kube-apiserver-") && p.Annotations["kubernetes.io/config.source"] == "file" {
			return "kubeadm"
		}
	}
	return "unknown"
}

// RefExists reports whether a Secret/ConfigMap/ServiceAccount/PVC reference
// resolves; ok=false when the kind is not tracked.
func (s *Snapshot) RefExists(kind, ns, name string) (exists bool, tracked bool) {
	key := ns + "/" + name
	switch kind {
	case "Secret":
		if len(s.SecretNames) == 0 {
			return false, false
		}
		return s.SecretNames[key], true
	case "ConfigMap":
		if len(s.ConfigMapNames) == 0 {
			return false, false
		}
		return s.ConfigMapNames[key], true
	case "ServiceAccount":
		if len(s.SANames) == 0 {
			return false, false
		}
		return s.SANames[key], true
	case "PersistentVolumeClaim":
		for i := range s.PVCs {
			if s.PVCs[i].Namespace == ns && s.PVCs[i].Name == name {
				return true, true
			}
		}
		return false, true
	}
	return false, false
}

// WarningEvents returns only Warning-type events.
func (s *Snapshot) WarningEvents() []corev1.Event {
	var out []corev1.Event
	for i := range s.Events {
		if s.Events[i].Type == "Warning" {
			out = append(out, s.Events[i])
		}
	}
	return out
}

// EventTime returns the best timestamp for an event.
func EventTime(e *corev1.Event) time.Time {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if e.Series != nil && !e.Series.LastObservedTime.IsZero() {
		return e.Series.LastObservedTime.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	if !e.FirstTimestamp.IsZero() {
		return e.FirstTimestamp.Time
	}
	return e.CreationTimestamp.Time
}

// EventCount returns the occurrence count of an event.
func EventCount(e *corev1.Event) int32 {
	if e.Series != nil && e.Series.Count > 0 {
		return e.Series.Count
	}
	if e.Count > 0 {
		return e.Count
	}
	return 1
}
