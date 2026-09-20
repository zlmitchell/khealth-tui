package k8s

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Cloud provider integration (CPI / cloud-controller-manager) and CSI
// drivers: which ones are installed, whether they run, whether the nodes
// were initialized by them and whether volumes attach. Everything here is
// derived from the snapshot except TridentBackends and VSphereConf, which
// Fetch reads (one CR list, one ConfigMap).

// CloudInfo is the cluster-wide picture.
type CloudInfo struct {
	Provider string // vsphere, aws, azure, openstack, harvester, hetzner, digitalocean, rke2 (embedded stub only), none
	Source   string // how Provider was decided
	CCMs     []Component
	CSI      []CSIStatus
	Nodes    []CloudNode
}

// Component is a cloud-controller-manager or CSI controller/node workload.
type Component struct {
	Label     string // e.g. "vSphere CPI", "Trident controller"
	Provider  string // vsphere, aws, trident, longhorn, ...
	Role      string // ccm, csi-controller, csi-node, operator
	Namespace string
	Name      string
	Kind      string // DaemonSet, Deployment, StaticPod
	Desired   int32
	Ready     int32
	Restarts  int32  // sum over pods in the last snapshot
	Problem   string // CrashLoopBackOff / ImagePullBackOff / last termination message of a bad pod
	Image     string
}

// OK reports whether the component runs everywhere it should.
func (c Component) OK() bool { return c.Desired > 0 && c.Ready == c.Desired && c.Problem == "" }

// CSIStatus is one CSI driver with its nodes, workloads and recent failures.
type CSIStatus struct {
	Driver     string // CSIDriver name
	Provider   string // vsphere, trident, aws-ebs, ...
	Registered int    // nodes whose CSINode lists the driver
	Missing    []string
	Controller *Component
	NodePlugin *Component
	StorageCls []string
	PVs        int
	Failures   []VolumeFailure // last hour
	Trident    []TridentBackend
	TridentX   *TridentInfo  // orchestrator, backend configs, nodes, publications
	Longhorn   *LonghornInfo // volumes, replicas, nodes, disks, backup target
	Ceph       *CephInfo     // Rook-Ceph cluster health, pools, filesystems, object stores
	VSphere    *VSphereConf
}

// VolumeFailure is an attach/mount/provision event attributed to a driver.
type VolumeFailure struct {
	Reason, Object, Message string
	Last                    time.Time
	Count                   int32
}

// CloudNode is what the cloud controller did to a node.
type CloudNode struct {
	Name          string
	ProviderID    string
	Uninitialized bool // node.cloudprovider.kubernetes.io/uninitialized taint still present
	Zone, Region  string
	InstanceType  string
	ExternalIP    bool
}

// TridentBackend is a trident.netapp.io/v1 TridentBackend.
type TridentBackend struct {
	Namespace, Name, BackendName string
	UUID                         string // backendUUID: what a PV's volumeAttributes.backendUUID points at
	State                        string // online, offline, failed, deleting, unknown
	Online                       bool
	Driver                       string // config.storageDriverName: ontap-nas, ontap-san, ...
	Version                      string
	UserState                    string // "" or suspended
	StateReason                  string
	ConfigRef                    string // TridentBackendConfig uid
	// from config (non-secret parts only): labels and policy defaults the
	// StorageClass selectors and provisioned volumes see
	Labels       map[string]string
	Region, Zone string
	Pools        []TridentPool
}

// TridentInfo is the rest of the Trident control plane: the operator's
// TridentOrchestrator, the TridentBackendConfigs the backends come from,
// the node registrations and which node each volume is published to.
type TridentInfo struct {
	Orchestrator   *TridentOrchestrator
	BackendConfigs []TridentBackendConfig
	Nodes          []TridentNode
	Publications   []TridentPublication
	// StorageClasses are the classes Trident accepted (TridentStorageClass
	// CRs); StorageClassesListed says the list itself worked.
	StorageClasses       []TridentStorageClass
	StorageClassesListed bool
}

// TridentOrchestrator is the trident-operator's install state.
type TridentOrchestrator struct {
	Name, Status, Message, Version, Namespace string // Status: Installed, Installing, Failed, Error, Uninstalled, Updating
	SilenceAutosupport, ForceDetach           bool
}

// TridentBackendConfig is a TridentBackendConfig (the declarative backend).
type TridentBackendConfig struct {
	Namespace, Name, BackendName, Driver string
	Phase                                string // Bound, Unbound, Failed, Deleting, Deleted, Lost
	LastOperation                        string // Success, Failed
	Message                              string
	Credentials                          string // spec.credentials.name
}

// TridentNode is a node registered with the Trident controller.
type TridentNode struct {
	Name             string
	Registered       bool // status.registered (newer Trident) or present at all (older)
	IQN, NQN         string
	PublicationState string // clean, cleanable, dirty
	Deleted          bool
	Services         []string // hostInfo.services: what the node plugin found usable (NFS, iSCSI, NVMe, SMB)
	OS               string   // hostInfo.os.distro + release
}

// HasService reports whether Trident found the protocol usable on the node.
func (n TridentNode) HasService(name string) bool {
	for _, s := range n.Services {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// TridentPublication is a TridentVolumePublication: volume -> node.
type TridentPublication struct {
	Volume, Node string
	ReadOnly     bool
	AccessMode   int32 // CSI access mode: 1 single-node-writer, 5 multi-node-multi-writer, ...
}

// SingleWriter reports whether the access mode allows one writer node only.
func (p TridentPublication) SingleWriter() bool {
	return p.AccessMode == 1 || p.AccessMode == 6 || p.AccessMode == 7
}

// VSphereConf is the vSphere CPI configuration (kube-system
// vsphere-cloud-config / cloud-config ConfigMap, key vsphere.conf).
type VSphereConf struct {
	VCenters    []string // host or host:port per [VirtualCenter "..."] section
	Datacenters []string
	Insecure    bool
	SecretRef   string // ns/name of the credentials secret
	SecretFound bool
}

var (
	tridentBackendGVR       = schema.GroupVersionResource{Group: "trident.netapp.io", Version: "v1", Resource: "tridentbackends"}
	tridentOrchestratorGVR  = schema.GroupVersionResource{Group: "trident.netapp.io", Version: "v1", Resource: "tridentorchestrators"}
	tridentBackendConfigGVR = schema.GroupVersionResource{Group: "trident.netapp.io", Version: "v1", Resource: "tridentbackendconfigs"}
	tridentNodeGVR          = schema.GroupVersionResource{Group: "trident.netapp.io", Version: "v1", Resource: "tridentnodes"}
	tridentPublicationGVR   = schema.GroupVersionResource{Group: "trident.netapp.io", Version: "v1", Resource: "tridentvolumepublications"}

	// cloudWorkloads classifies DaemonSets/Deployments by name. Order
	// matters: the first match wins.
	cloudWorkloads = []struct {
		re                    *regexp.Regexp
		label, provider, role string
	}{
		{regexp.MustCompile(`vsphere-cpi|vsphere-cloud-controller-manager`), "vSphere CPI", "vsphere", "ccm"},
		{regexp.MustCompile(`^aws-cloud-controller-manager`), "AWS CCM", "aws", "ccm"},
		{regexp.MustCompile(`azure.*cloud-controller-manager|^cloud-controller-manager$`), "Azure CCM", "azure", "ccm"},
		{regexp.MustCompile(`^cloud-node-manager`), "Azure cloud-node-manager", "azure", "ccm"},
		{regexp.MustCompile(`^openstack-cloud-controller-manager`), "OpenStack CCM", "openstack", "ccm"},
		{regexp.MustCompile(`^harvester-cloud-provider`), "Harvester cloud provider", "harvester", "ccm"},
		{regexp.MustCompile(`^hcloud-cloud-controller-manager`), "Hetzner CCM", "hetzner", "ccm"},
		{regexp.MustCompile(`^digitalocean-cloud-controller-manager`), "DigitalOcean CCM", "digitalocean", "ccm"},
		{regexp.MustCompile(`^vsphere-csi-controller`), "vSphere CSI controller", "vsphere", "csi-controller"},
		{regexp.MustCompile(`^vsphere-csi-node`), "vSphere CSI node", "vsphere", "csi-node"},
		{regexp.MustCompile(`^trident-operator`), "Trident operator", "trident", "operator"},
		{regexp.MustCompile(`^trident-controller|^trident-csi$`), "Trident controller", "trident", "csi-controller"},
		{regexp.MustCompile(`^trident-node`), "Trident node", "trident", "csi-node"},
		{regexp.MustCompile(`^ebs-csi-controller`), "AWS EBS CSI controller", "aws-ebs", "csi-controller"},
		{regexp.MustCompile(`^ebs-csi-node`), "AWS EBS CSI node", "aws-ebs", "csi-node"},
		{regexp.MustCompile(`^efs-csi-controller`), "AWS EFS CSI controller", "aws-efs", "csi-controller"},
		{regexp.MustCompile(`^efs-csi-node`), "AWS EFS CSI node", "aws-efs", "csi-node"},
		{regexp.MustCompile(`^csi-azuredisk-controller`), "Azure Disk CSI controller", "azure-disk", "csi-controller"},
		{regexp.MustCompile(`^csi-azuredisk-node`), "Azure Disk CSI node", "azure-disk", "csi-node"},
		{regexp.MustCompile(`^csi-azurefile-controller`), "Azure File CSI controller", "azure-file", "csi-controller"},
		{regexp.MustCompile(`^csi-azurefile-node`), "Azure File CSI node", "azure-file", "csi-node"},
		{regexp.MustCompile(`^csi-cinder-controllerplugin`), "Cinder CSI controller", "cinder", "csi-controller"},
		{regexp.MustCompile(`^csi-cinder-nodeplugin`), "Cinder CSI node", "cinder", "csi-node"},
		{regexp.MustCompile(`^longhorn-csi-plugin`), "Longhorn CSI plugin", "longhorn", "csi-node"},
		{regexp.MustCompile(`^longhorn-manager`), "Longhorn manager", "longhorn", "csi-controller"},
		{regexp.MustCompile(`^csi-nfs-controller`), "NFS CSI controller", "nfs", "csi-controller"},
		{regexp.MustCompile(`^csi-nfs-node`), "NFS CSI node", "nfs", "csi-node"},
		{regexp.MustCompile(`^csi-smb-controller`), "SMB CSI controller", "smb", "csi-controller"},
		{regexp.MustCompile(`^csi-smb-node`), "SMB CSI node", "smb", "csi-node"},
		{regexp.MustCompile(`^harvester-csi-driver-controllers`), "Harvester CSI controller", "harvester", "csi-controller"},
		{regexp.MustCompile(`^harvester-csi-driver$`), "Harvester CSI node", "harvester", "csi-node"},
		{regexp.MustCompile(`^csi-rbdplugin-provisioner|^csi-cephfsplugin-provisioner`), "Ceph CSI provisioner", "ceph", "csi-controller"},
		{regexp.MustCompile(`^csi-rbdplugin$|^csi-cephfsplugin$`), "Ceph CSI plugin", "ceph", "csi-node"},
	}

	// csiDriverProvider maps CSIDriver names to the provider keys above.
	csiDriverProvider = map[string]string{
		"csi.vsphere.vmware.com": "vsphere", "csi.trident.netapp.io": "trident", "ebs.csi.aws.com": "aws-ebs", "efs.csi.aws.com": "aws-efs",
		"disk.csi.azure.com": "azure-disk", "file.csi.azure.com": "azure-file", "cinder.csi.openstack.org": "cinder", "driver.longhorn.io": "longhorn",
		"nfs.csi.k8s.io": "nfs", "smb.csi.k8s.io": "smb", "driver.harvesterhci.io": "harvester", "rbd.csi.ceph.com": "ceph", "cephfs.csi.ceph.com": "ceph",
	}

	// providerIDPrefix maps node providerID schemes to providers.
	providerIDPrefix = map[string]string{"vsphere": "vsphere", "aws": "aws", "azure": "azure", "openstack": "openstack", "harvester": "harvester", "hcloud": "hetzner", "digitalocean": "digitalocean", "gce": "gce", "rke2": "rke2", "k3s": "k3s"}

	pvcInMessage = regexp.MustCompile(`"(pvc-[0-9a-f-]{36})"`)
)

const uninitializedTaint = "node.cloudprovider.kubernetes.io/uninitialized"

// Cloud derives the cloud provider and CSI picture from the snapshot.
func (s *Snapshot) Cloud() CloudInfo {
	var ci CloudInfo
	podsByPrefix := func(ns, name string) []*corev1.Pod {
		var out []*corev1.Pod
		for i := range s.Pods {
			p := &s.Pods[i]
			if p.Namespace == ns && strings.HasPrefix(p.Name, name+"-") {
				out = append(out, p)
			}
		}
		return out
	}
	// FailedCreate on the DaemonSet/ReplicaSet: the pods were never
	// created (PodSecurity admission, quota, missing ServiceAccount), so no
	// pod carries the reason
	failedCreate := map[string]string{}
	for i := range s.Events {
		e := &s.Events[i]
		if e.Reason != "FailedCreate" || e.Type != corev1.EventTypeWarning {
			continue
		}
		name := e.InvolvedObject.Name
		if e.InvolvedObject.Kind == "ReplicaSet" {
			if i := strings.LastIndex(name, "-"); i > 0 {
				name = name[:i]
			}
		}
		key := e.InvolvedObject.Namespace + "/" + name
		if _, ok := failedCreate[key]; !ok {
			msg := e.Message
			if i := strings.Index(msg, "Error creating: "); i >= 0 {
				msg = msg[i+len("Error creating: "):]
			}
			failedCreate[key] = firstLineOf(msg)
		}
	}
	fill := func(c *Component, pods []*corev1.Pod) {
		if len(pods) == 0 && c.Desired > c.Ready {
			if m, ok := failedCreate[c.Namespace+"/"+c.Name]; ok {
				c.Problem = "FailedCreate: " + m
			}
		}
		for _, p := range pods {
			for _, cs := range p.Status.ContainerStatuses {
				c.Restarts += cs.RestartCount
				if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" && c.Problem == "" {
					c.Problem = p.Name + ": " + w.Reason
					if lt := cs.LastTerminationState.Terminated; lt != nil && lt.Message != "" {
						c.Problem += " (" + firstLineOf(lt.Message) + ")"
					}
				}
			}
			if p.Status.Phase == corev1.PodPending && c.Problem == "" {
				for _, cond := range p.Status.Conditions {
					if cond.Type == corev1.PodScheduled && cond.Status != corev1.ConditionTrue {
						c.Problem = p.Name + ": " + firstLineOf(cond.Message)
					}
				}
			}
		}
	}
	classify := func(name string) (label, provider, role string, ok bool) {
		for _, w := range cloudWorkloads {
			if w.re.MatchString(name) {
				return w.label, w.provider, w.role, true
			}
		}
		return "", "", "", false
	}
	var comps []Component
	for i := range s.DaemonSets {
		d := &s.DaemonSets[i]
		if label, prov, role, ok := classify(d.Name); ok {
			c := Component{Label: label, Provider: prov, Role: role, Namespace: d.Namespace, Name: d.Name, Kind: "DaemonSet", Desired: d.Status.DesiredNumberScheduled, Ready: d.Status.NumberReady}
			c.Image = mainImage(d.Spec.Template.Spec.Containers)
			fill(&c, podsByPrefix(d.Namespace, d.Name))
			comps = append(comps, c)
		}
	}
	for i := range s.Deployments {
		d := &s.Deployments[i]
		if label, prov, role, ok := classify(d.Name); ok {
			c := Component{Label: label, Provider: prov, Role: role, Namespace: d.Namespace, Name: d.Name, Kind: "Deployment", Desired: d.Status.Replicas, Ready: d.Status.ReadyReplicas}
			if d.Spec.Replicas != nil {
				c.Desired = *d.Spec.Replicas
			}
			c.Image = mainImage(d.Spec.Template.Spec.Containers)
			fill(&c, podsByPrefix(d.Namespace, d.Name))
			comps = append(comps, c)
		}
	}
	// rke2's embedded cloud controller: static pods cloud-controller-manager-<node>
	var stub Component
	var stubPods []*corev1.Pod
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Namespace == "kube-system" && strings.HasPrefix(p.Name, "cloud-controller-manager-") && p.Annotations["kubernetes.io/config.source"] == "file" {
			stubPods = append(stubPods, p)
		}
	}
	if len(stubPods) > 0 {
		stub = Component{Label: "rke2 embedded cloud-controller", Provider: "rke2", Role: "ccm", Namespace: "kube-system", Name: "cloud-controller-manager", Kind: "StaticPod", Desired: int32(len(stubPods))}
		for _, p := range stubPods {
			if p.Status.Phase == corev1.PodRunning {
				stub.Ready++
			}
			if len(p.Spec.Containers) > 0 {
				stub.Image = p.Spec.Containers[0].Image
			}
		}
		fill(&stub, stubPods)
		comps = append(comps, stub)
	}
	sort.SliceStable(comps, func(i, j int) bool {
		if comps[i].Role != comps[j].Role {
			return comps[i].Role < comps[j].Role
		}
		return comps[i].Name < comps[j].Name
	})
	byProvRole := map[string]*Component{}
	for i := range comps {
		c := &comps[i]
		if c.Role == "ccm" {
			ci.CCMs = append(ci.CCMs, *c)
		}
		byProvRole[c.Provider+"/"+c.Role] = c
	}

	// nodes
	idProviders := map[string]int{}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		cn := CloudNode{Name: n.Name, ProviderID: n.Spec.ProviderID}
		if scheme, _, ok := strings.Cut(n.Spec.ProviderID, "://"); ok {
			if p, ok := providerIDPrefix[scheme]; ok {
				idProviders[p]++
			} else {
				idProviders[scheme]++
			}
		}
		for _, t := range n.Spec.Taints {
			if t.Key == uninitializedTaint {
				cn.Uninitialized = true
			}
		}
		l := n.Labels
		cn.Zone = firstNonEmpty(l["topology.kubernetes.io/zone"], l["failure-domain.beta.kubernetes.io/zone"])
		cn.Region = firstNonEmpty(l["topology.kubernetes.io/region"], l["failure-domain.beta.kubernetes.io/region"])
		cn.InstanceType = firstNonEmpty(l["node.kubernetes.io/instance-type"], l["beta.kubernetes.io/instance-type"])
		for _, ad := range n.Status.Addresses {
			if ad.Type == corev1.NodeExternalIP {
				cn.ExternalIP = true
			}
		}
		ci.Nodes = append(ci.Nodes, cn)
	}

	// provider: the external CCM installed wins, then providerIDs, then the stub
	for _, c := range ci.CCMs {
		if c.Provider != "rke2" {
			ci.Provider, ci.Source = c.Provider, c.Label+" ("+c.Kind+" "+c.Namespace+"/"+c.Name+")"
			break
		}
	}
	if ci.Provider == "" {
		best, bestN := "", 0
		for p, n := range idProviders {
			if n > bestN && p != "rke2" && p != "k3s" {
				best, bestN = p, n
			}
		}
		if best != "" {
			ci.Provider, ci.Source = best, "node providerID"
		}
	}
	if ci.Provider == "" {
		if len(stubPods) > 0 {
			ci.Provider, ci.Source = "rke2", "embedded cloud-controller (node lifecycle only)"
		} else {
			ci.Provider, ci.Source = "none", "no cloud-controller-manager found"
		}
	}

	// CSI drivers
	perNode := map[string]map[string]bool{} // driver -> node -> registered
	for i := range s.CSINodes {
		for _, d := range s.CSINodes[i].Spec.Drivers {
			if perNode[d.Name] == nil {
				perNode[d.Name] = map[string]bool{}
			}
			perNode[d.Name][s.CSINodes[i].Name] = true
		}
	}
	pvDriver := map[string]string{}
	pvsPer := map[string]int{}
	for i := range s.PVs {
		if c := s.PVs[i].Spec.CSI; c != nil {
			pvDriver[s.PVs[i].Name] = c.Driver
			pvsPer[c.Driver]++
		}
	}
	failures := map[string][]VolumeFailure{}
	cutoff := s.Taken.Add(-time.Hour)
	if s.Taken.IsZero() {
		cutoff = time.Now().Add(-time.Hour)
	}
	for i := range s.Events {
		e := &s.Events[i]
		switch e.Reason {
		case "FailedAttachVolume", "FailedMount", "FailedMapVolume", "ProvisioningFailed", "VolumeResizeFailed", "FailedDetachVolume", "VolumeFailedDelete":
		default:
			continue
		}
		last := e.LastTimestamp.Time
		if last.IsZero() {
			last = e.EventTime.Time
		}
		if last.Before(cutoff) {
			continue
		}
		driver := ""
		if m := pvcInMessage.FindStringSubmatch(e.Message); m != nil {
			driver = pvDriver[m[1]]
		}
		if driver == "" {
			for name := range csiDriverProvider {
				if strings.Contains(e.Message, name) {
					driver = name
				}
			}
		}
		if driver == "" {
			continue
		}
		failures[driver] = append(failures[driver], VolumeFailure{Reason: e.Reason, Object: e.InvolvedObject.Namespace + "/" + e.InvolvedObject.Name, Message: firstLineOf(e.Message), Last: last, Count: e.Count})
	}
	for i := range s.CSIDrivers {
		name := s.CSIDrivers[i].Name
		st := CSIStatus{Driver: name, Provider: csiDriverProvider[name], Registered: len(perNode[name]), PVs: pvsPer[name], Failures: failures[name]}
		if st.Provider == "" {
			st.Provider = name
		}
		for j := range s.Nodes {
			if !perNode[name][s.Nodes[j].Name] {
				st.Missing = append(st.Missing, s.Nodes[j].Name)
			}
		}
		for j := range s.StorageClasses {
			if s.StorageClasses[j].Provisioner == name {
				st.StorageCls = append(st.StorageCls, s.StorageClasses[j].Name)
			}
		}
		st.Controller = byProvRole[st.Provider+"/csi-controller"]
		st.NodePlugin = byProvRole[st.Provider+"/csi-node"]
		if st.Provider == "trident" {
			st.Trident = s.TridentBackends
			st.TridentX = s.Trident
		}
		if st.Provider == "longhorn" {
			st.Longhorn = s.Longhorn
		}
		if st.Provider == "ceph" {
			st.Ceph = s.Ceph
		}
		if st.Provider == "vsphere" && s.VSphereConf != nil {
			vc := *s.VSphereConf
			vc.SecretFound = vc.SecretRef == "" || s.SecretNames[vc.SecretRef]
			st.VSphere = &vc
		}
		sort.Slice(st.Failures, func(a, b int) bool { return st.Failures[a].Last.After(st.Failures[b].Last) })
		ci.CSI = append(ci.CSI, st)
	}
	sort.Slice(ci.CSI, func(i, j int) bool { return ci.CSI[i].Driver < ci.CSI[j].Driver })
	return ci
}

// Component returns the CCM or CSI workload for a provider and role, if any.
func (ci CloudInfo) Component(provider, role string) *Component {
	for i := range ci.CCMs {
		if ci.CCMs[i].Provider == provider && ci.CCMs[i].Role == role {
			return &ci.CCMs[i]
		}
	}
	for i := range ci.CSI {
		for _, c := range []*Component{ci.CSI[i].Controller, ci.CSI[i].NodePlugin} {
			if c != nil && c.Provider == provider && c.Role == role {
				return c
			}
		}
	}
	return nil
}

// mainImage is the driver/controller image of a pod template, skipping the
// CSI sidecars.
func mainImage(cs []corev1.Container) string {
	for _, c := range cs {
		if !sidecar.MatchString(c.Name) {
			return c.Image
		}
	}
	if len(cs) > 0 {
		return cs[0].Image
	}
	return ""
}

var sidecar = regexp.MustCompile(`^(csi-)?(provisioner|attacher|resizer|snapshotter|node-driver-registrar|liveness-?probe|external-.*|driver-registrar)$|^livenessprobe$`)

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// tridentBackends lists trident.netapp.io TridentBackend CRs (nil when the
// CRD is absent or the token cannot list it).
func (c *Client) tridentBackends(ctx context.Context) []TridentBackend {
	l, err := c.dynList(ctx, "tridentbackends.trident.netapp.io", tridentBackendGVR)
	if err != nil {
		return nil
	}
	var out []TridentBackend
	for _, it := range l.Items {
		b := TridentBackend{Namespace: it.GetNamespace(), Name: it.GetName()}
		b.BackendName, _, _ = unstructured.NestedString(it.Object, "backendName")
		b.UUID, _, _ = unstructured.NestedString(it.Object, "backendUUID")
		b.State, _, _ = unstructured.NestedString(it.Object, "state")
		b.Online, _, _ = unstructured.NestedBool(it.Object, "online")
		b.Driver, _, _ = unstructured.NestedString(it.Object, "config", "storageDriverName")
		b.Version, _, _ = unstructured.NestedString(it.Object, "version")
		b.UserState, _, _ = unstructured.NestedString(it.Object, "userState")
		b.StateReason, _, _ = unstructured.NestedString(it.Object, "stateReason")
		b.ConfigRef, _, _ = unstructured.NestedString(it.Object, "configRef")
		b.Labels, b.Region, b.Zone, b.Pools = parseTridentBackendConfig(it.Object)
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BackendName < out[j].BackendName })
	return out
}

// vsphereConf reads the vSphere CPI configuration from kube-system
// (vsphere-cloud-config from the rancher-vsphere-cpi chart, or cloud-config
// upstream). Only the vCenter hosts, datacenters, TLS flag and the secret
// reference are kept.
// The last error is returned so Fetch can remember a 403/404 (no vSphere
// CPI on this cluster) instead of two GETs every cycle.
func (c *Client) vsphereConf(ctx context.Context) (*VSphereConf, error) {
	var last error
	for _, name := range []string{"vsphere-cloud-config", "cloud-config"} {
		cm, err := c.CS.CoreV1().ConfigMaps("kube-system").Get(ctx, name, c.getOpts())
		if err != nil {
			last = err
			continue
		}
		text, ok := cm.Data["vsphere.conf"]
		if !ok {
			continue
		}
		return parseVSphereConf(text), nil
	}
	return nil, last
}

var vcSection = regexp.MustCompile(`^\[VirtualCenter\s+"([^"]+)"\]`)

func parseVSphereConf(text string) *VSphereConf {
	v := &VSphereConf{}
	section, secretName, secretNS := "", "", "kube-system"
	var globalPort string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if m := vcSection.FindStringSubmatch(l); m != nil {
			section = "vc"
			v.VCenters = append(v.VCenters, m[1])
			continue
		}
		if strings.HasPrefix(l, "[") {
			section = strings.Trim(l, "[]")
			continue
		}
		k, val, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, val = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(val), `"`)
		switch k {
		case "datacenters":
			for _, d := range strings.Split(val, ",") {
				if d = strings.TrimSpace(d); d != "" {
					v.Datacenters = append(v.Datacenters, d)
				}
			}
		case "insecure-flag":
			v.Insecure = val == "true" || val == "1"
		case "secret-name":
			secretName = val
		case "secret-namespace":
			secretNS = val
		case "port":
			if section == "vc" && len(v.VCenters) > 0 {
				v.VCenters[len(v.VCenters)-1] += ":" + val
			} else {
				globalPort = val
			}
		}
	}
	if globalPort != "" {
		for i, vc := range v.VCenters {
			if !strings.Contains(vc, ":") {
				v.VCenters[i] = vc + ":" + globalPort
			}
		}
	}
	if secretName != "" {
		v.SecretRef = secretNS + "/" + secretName
	}
	return v
}

// tridentInfo lists the other Trident CRs (best effort, each list skipped
// while denied or absent). nil when none of them could be read.
func (c *Client) tridentInfo(ctx context.Context) *TridentInfo {
	var ti TridentInfo
	found := false
	if l, err := c.dynList(ctx, "tridentorchestrators.trident.netapp.io", tridentOrchestratorGVR); err == nil {
		found = true
		for _, it := range l.Items {
			o := &TridentOrchestrator{Name: it.GetName()}
			o.Status, _, _ = unstructured.NestedString(it.Object, "status", "status")
			o.Message, _, _ = unstructured.NestedString(it.Object, "status", "message")
			o.Version, _, _ = unstructured.NestedString(it.Object, "status", "version")
			o.Namespace, _, _ = unstructured.NestedString(it.Object, "status", "namespace")
			o.SilenceAutosupport, _, _ = unstructured.NestedBool(it.Object, "spec", "silenceAutosupport")
			o.ForceDetach, _, _ = unstructured.NestedBool(it.Object, "spec", "enableForceDetach")
			ti.Orchestrator = o
			break
		}
	}
	if l, err := c.dynList(ctx, "tridentbackendconfigs.trident.netapp.io", tridentBackendConfigGVR); err == nil {
		found = true
		for _, it := range l.Items {
			b := TridentBackendConfig{Namespace: it.GetNamespace(), Name: it.GetName()}
			b.BackendName, _, _ = unstructured.NestedString(it.Object, "status", "backendInfo", "backendName")
			if b.BackendName == "" {
				b.BackendName, _, _ = unstructured.NestedString(it.Object, "spec", "backendName")
			}
			b.Driver, _, _ = unstructured.NestedString(it.Object, "spec", "storageDriverName")
			b.Phase, _, _ = unstructured.NestedString(it.Object, "status", "phase")
			b.LastOperation, _, _ = unstructured.NestedString(it.Object, "status", "lastOperationStatus")
			b.Message, _, _ = unstructured.NestedString(it.Object, "status", "message")
			b.Credentials, _, _ = unstructured.NestedString(it.Object, "spec", "credentials", "name")
			ti.BackendConfigs = append(ti.BackendConfigs, b)
		}
		sort.Slice(ti.BackendConfigs, func(i, j int) bool { return ti.BackendConfigs[i].Name < ti.BackendConfigs[j].Name })
	}
	if l, err := c.dynList(ctx, "tridentnodes.trident.netapp.io", tridentNodeGVR); err == nil {
		found = true
		for _, it := range l.Items {
			n := TridentNode{Name: it.GetName(), Registered: true}
			// Trident 25.x moved the fields under spec/status; older releases keep them top-level
			if name, _, _ := unstructured.NestedString(it.Object, "spec", "nodeName"); name != "" {
				n.Name = name
			} else if name, _, _ := unstructured.NestedString(it.Object, "name"); name != "" {
				n.Name = name
			}
			if _, ok, _ := unstructured.NestedFieldNoCopy(it.Object, "status", "registered"); ok {
				n.Registered, _, _ = unstructured.NestedBool(it.Object, "status", "registered")
			}
			n.IQN, _, _ = unstructured.NestedString(it.Object, "spec", "iqn")
			if n.IQN == "" {
				n.IQN, _, _ = unstructured.NestedString(it.Object, "iqn")
			}
			n.NQN, _, _ = unstructured.NestedString(it.Object, "spec", "nqn")
			if n.NQN == "" {
				n.NQN, _, _ = unstructured.NestedString(it.Object, "nqn")
			}
			n.PublicationState, _, _ = unstructured.NestedString(it.Object, "status", "publicationState")
			if n.PublicationState == "" {
				n.PublicationState, _, _ = unstructured.NestedString(it.Object, "publicationState")
			}
			n.Deleted, _, _ = unstructured.NestedBool(it.Object, "status", "deleted")
			if !n.Deleted {
				n.Deleted, _, _ = unstructured.NestedBool(it.Object, "deleted")
			}
			for _, path := range [][]string{{"spec", "hostInfo"}, {"hostInfo"}} {
				if hi, _, _ := unstructured.NestedMap(it.Object, path...); hi != nil {
					n.Services, _, _ = unstructured.NestedStringSlice(hi, "services")
					distro, _, _ := unstructured.NestedString(hi, "os", "distro")
					rel, _, _ := unstructured.NestedString(hi, "os", "release")
					n.OS = strings.TrimSpace(distro + " " + rel)
					break
				}
			}
			ti.Nodes = append(ti.Nodes, n)
		}
		sort.Slice(ti.Nodes, func(i, j int) bool { return ti.Nodes[i].Name < ti.Nodes[j].Name })
	}
	if scs, ok := c.tridentStorageClasses(ctx); ok {
		found = true
		ti.StorageClasses, ti.StorageClassesListed = scs, true
	}
	if l, err := c.dynList(ctx, "tridentvolumepublications.trident.netapp.io", tridentPublicationGVR); err == nil {
		found = true
		for _, it := range l.Items {
			p := TridentPublication{}
			p.Volume, _, _ = unstructured.NestedString(it.Object, "volumeID")
			p.Node, _, _ = unstructured.NestedString(it.Object, "nodeID")
			p.ReadOnly, _, _ = unstructured.NestedBool(it.Object, "readOnly")
			if m, _, _ := unstructured.NestedInt64(it.Object, "accessMode"); m > 0 {
				p.AccessMode = int32(m)
			}
			ti.Publications = append(ti.Publications, p)
		}
		sort.Slice(ti.Publications, func(i, j int) bool {
			return ti.Publications[i].Volume+ti.Publications[i].Node < ti.Publications[j].Volume+ti.Publications[j].Node
		})
	}
	if !found {
		return nil
	}
	return &ti
}

// TridentNode returns the registration for a Kubernetes node, if any.
func (ti *TridentInfo) TridentNode(name string) *TridentNode {
	if ti == nil {
		return nil
	}
	for i := range ti.Nodes {
		if ti.Nodes[i].Name == name {
			return &ti.Nodes[i]
		}
	}
	return nil
}

// MultiPublished lists single-writer volumes published to more than one
// node: the controller granted a second ControllerPublish before the first
// node released the volume, so two hosts can write the same LUN/export.
func (ti *TridentInfo) MultiPublished() map[string][]string {
	if ti == nil {
		return nil
	}
	nodes := map[string][]string{}
	for _, p := range ti.Publications {
		if p.SingleWriter() && !p.ReadOnly {
			nodes[p.Volume] = append(nodes[p.Volume], p.Node)
		}
	}
	for v, ns := range nodes {
		if len(ns) < 2 {
			delete(nodes, v)
		}
	}
	return nodes
}
