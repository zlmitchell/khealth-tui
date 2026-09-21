package checks

import (
	"fmt"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalCloud raises the cloud provider (CPI / cloud-controller-manager) and
// CSI findings from the API snapshot: is the controller running, did it
// initialize every node, do volumes attach, are the Trident backends online,
// is the vSphere CPI config complete. Node-side facts (kubelet
// --cloud-provider, IMDS, disk.EnableUUID, vCenter reachability) are
// cross-checked in evalCloudNode.
func evalCloud(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	ci := s.Cloud()
	external := ci.Provider != "none" && ci.Provider != "rke2"
	cv := distro.For(s.Distribution)

	// ---- cloud-controller-managers ----
	var stub *k8s.Component
	for i := range ci.CCMs {
		c := &ci.CCMs[i]
		if c.Provider == "rke2" {
			stub = c
			continue
		}
		if !c.OK() {
			add(SevCrit, "cloud", c.Namespace+"/"+c.Name, fmt.Sprintf("%s not healthy: %d/%d ready%s - nodes are not initialized and cloud resources (node lifecycle, zones, load balancers) are not reconciled", c.Label, c.Ready, c.Desired, problemSuffix(c.Problem)), "kubectl -n "+c.Namespace+" logs "+c.Kind+"/"+c.Name+"; check the cloud credentials secret and API reachability from the nodes")
		}
	}
	if stub != nil && external {
		add(SevWarn, "cloud", "kube-system/cloud-controller-manager", "rke2's embedded cloud-controller runs alongside the "+ci.Provider+" cloud controller: both initialize nodes, and a node the stub reaches first gets an rke2:// providerID the "+ci.Provider+" CPI/CSI cannot use", "config.yaml on every server: disable-cloud-controller: true (Rancher sets it when the cloud provider is selected); restart rke2-server")
	}

	// ---- nodes ----
	for _, n := range ci.Nodes {
		scheme, _, _ := strings.Cut(n.ProviderID, "://")
		switch {
		case n.Uninitialized:
			hint := "the cloud controller could not match the node to an instance: "
			switch ci.Provider {
			case "vsphere":
				hint += "VM not under the datacenters in vsphere.conf, VM UUID/name mismatch, vCenter credentials or reachability; kubectl -n kube-system logs ds/<vsphere-cpi>"
			case "aws":
				hint += "instance missing the kubernetes.io/cluster/<name> tag, node name not the private DNS name, IAM role or IMDS; kubectl -n kube-system logs ds/aws-cloud-controller-manager"
			case "none":
				hint = "kubelet runs with --cloud-provider=external but no cloud-controller-manager is installed: deploy the CPI or drop cloud-provider-name from config.yaml"
			default:
				hint += "check the " + ci.Provider + " cloud controller logs"
			}
			add(SevCrit, "cloud", n.Name, "node still carries the node.cloudprovider.kubernetes.io/uninitialized taint: the cloud controller ("+ci.Provider+") has not initialized it, so no workload pods schedule there", hint)
		case external && n.ProviderID == "":
			add(SevWarn, "cloud", n.Name, "node has no providerID although the "+ci.Provider+" cloud controller is installed: the kubelet did not start with --cloud-provider=external, so the CPI never adopted it (no zone labels, CSI cannot map it to an instance)", cv.CloudProvider(ci.Provider)+"; providerID is set once at registration")
		case external && (scheme == "rke2" || scheme == "k3s"):
			add(SevCrit, "cloud", n.Name, fmt.Sprintf("node was initialized by the embedded %s cloud-controller (providerID %s) instead of the %s CPI: the %s CSI cannot map it to its instance, so volumes never attach on this node", scheme, n.ProviderID, ci.Provider, ci.Provider), "providerID is immutable: set disable-cloud-controller: true and cloud-provider-name in config.yaml, then delete the Node object and restart rke2 on it to re-register")
		case external && scheme != "" && scheme != providerScheme(ci.Provider) && providerScheme(ci.Provider) != "":
			add(SevWarn, "cloud", n.Name, fmt.Sprintf("providerID %s does not belong to the %s cloud controller", n.ProviderID, ci.Provider), "")
		}
	}

	// ---- CSI drivers ----
	cephSeen := map[string]bool{} // rbd and cephfs share one CephCluster
	for _, d := range ci.CSI {
		obj := d.Driver
		if d.Controller != nil && !d.Controller.OK() {
			add(SevCrit, "storage", obj, fmt.Sprintf("%s not healthy: %d/%d ready%s - provisioning, attach and resize stop for %s volumes", d.Controller.Label, d.Controller.Ready, d.Controller.Desired, problemSuffix(d.Controller.Problem), d.Driver), "kubectl -n "+d.Controller.Namespace+" logs "+d.Controller.Kind+"/"+d.Controller.Name+" -c "+csiMainContainer(d.Provider))
		}
		if d.NodePlugin != nil && !d.NodePlugin.OK() {
			add(SevWarn, "storage", obj, fmt.Sprintf("%s not healthy: %d/%d ready%s - mounts fail on the nodes without it", d.NodePlugin.Label, d.NodePlugin.Ready, d.NodePlugin.Desired, problemSuffix(d.NodePlugin.Problem)), "kubectl -n "+d.NodePlugin.Namespace+" describe ds/"+d.NodePlugin.Name)
		}
		if len(d.Missing) > 0 && d.NodePlugin != nil && int(d.NodePlugin.Desired) > d.Registered {
			add(SevWarn, "storage", obj, fmt.Sprintf("driver not registered on %s: the node plugin is scheduled there but the kubelet has no CSINode entry, pods with %s volumes cannot start on them", strutil.TruncList(d.Missing, 4), d.Driver), "kubectl -n "+d.NodePlugin.Namespace+" logs ds/"+d.NodePlugin.Name+" -c node-driver-registrar on that node; check /var/lib/kubelet/plugins_registry and fapolicyd")
		} else if len(d.Missing) > 0 && d.NodePlugin != nil && len(d.StorageCls) > 0 {
			add(SevInfo, "storage", obj, fmt.Sprintf("driver not on %s (node plugin not scheduled there: tolerations/nodeSelector)", strutil.TruncList(d.Missing, 4)), "")
		}
		if len(d.Failures) > 0 {
			f := d.Failures[0]
			var total int32
			for _, x := range d.Failures {
				total += max(x.Count, 1)
			}
			add(SevWarn, "storage", obj, fmt.Sprintf("%d volume failures in the last hour, latest %s on %s: %s", total, f.Reason, f.Object, strutil.TruncStr(f.Message, 160)), "kubectl get events -A --field-selector reason="+f.Reason+"; controller logs of "+d.Driver)
		}
		if d.Provider == "trident" {
			evalTridentExtra(in, d, add)
			if len(d.Trident) == 0 && len(s.TridentBackends) == 0 {
				add(SevWarn, "storage", obj, "Trident is installed but has no TridentBackend: no volume can be provisioned", "create a TridentBackendConfig (ONTAP SVM credentials) in the trident namespace")
			}
			for _, b := range d.Trident {
				if !b.Online || (b.State != "" && b.State != "online") {
					add(SevCrit, "storage", obj, fmt.Sprintf("Trident backend %s (%s) is %s%s: provisioning and attach on it fail", b.BackendName, b.Driver, strutil.FirstNonEmpty(b.State, "offline"), problemSuffix(b.StateReason)), "tridentctl -n trident get backend "+b.BackendName+"; check SVM credentials, management LIF reachability and the ONTAP aggregate")
				}
			}
		}
		if d.Provider == "longhorn" {
			evalLonghorn(in, d, add)
		}
		if d.Provider == "ceph" {
			evalCeph(in, d, cephSeen, add)
		}
		if d.Provider == "vsphere" {
			if ci.Provider != "vsphere" {
				add(SevCrit, "storage", obj, "vSphere CSI is installed but the vSphere CPI is not (provider: "+ci.Provider+"): the CSI needs the vsphere:// providerID the CPI sets to find each node's VM, so attach fails", "install the vSphere CPI (Rancher: cluster > Cloud Provider vSphere; upstream: cloud-provider-vsphere manifests) and "+cv.CloudProvider("vsphere"))
			}
			if v := d.VSphere; v != nil {
				if v.SecretRef != "" && !v.SecretFound {
					add(SevCrit, "cloud", "kube-system/vsphere-cloud-config", "vsphere.conf references credentials secret "+v.SecretRef+" which does not exist: the CPI cannot log in to vCenter", "recreate the secret (<vcenter>.username / <vcenter>.password keys) or fix secret-name/secret-namespace")
				}
				if len(v.VCenters) == 0 {
					add(SevCrit, "cloud", "kube-system/vsphere-cloud-config", "vsphere.conf has no [VirtualCenter] section", "")
				} else if len(v.Datacenters) == 0 {
					add(SevWarn, "cloud", "kube-system/vsphere-cloud-config", "vsphere.conf lists no datacenters: the CPI cannot find the node VMs", "datacenters = <DC> under each [VirtualCenter] section")
				}
			}
		}
	}

	evalVolumeAttachments(in, add)
	evalSnapshots(in, add)
	evalTridentProtect(in, add)

	// StorageClasses whose CSI provisioner has no driver
	have := map[string]bool{}
	for _, d := range ci.CSI {
		have[d.Driver] = true
	}
	for i := range s.StorageClasses {
		p := s.StorageClasses[i].Provisioner
		if strings.HasPrefix(p, "kubernetes.io/") || p == "rancher.io/local-path" || !strings.Contains(p, ".") || have[p] {
			continue
		}
		add(SevWarn, "storage", s.StorageClasses[i].Name, "StorageClass provisioner "+p+" has no CSIDriver object: PVCs using it stay Pending", "install the driver or delete the StorageClass")
	}
}

// evalCloudNode cross-checks a node's host facts with the cluster's cloud
// integration: kubelet --cloud-provider, AWS IMDS, vSphere disk.EnableUUID,
// vCenter reachability, Trident host prerequisites.
func evalCloudNode(name string, ni *nodeinfo.Info, in Input, ci k8s.CloudInfo, add func(Severity, string, string, string, string)) {
	p := &ni.Preflight
	external := ci.Provider != "none" && ci.Provider != "rke2"
	nv := distro.For(ni.Dist)
	if external && len(ni.KubeletFlags) > 0 {
		if v := ni.KubeletFlags["cloud-provider"]; v != "external" {
			add(SevCrit, "cloud", name, fmt.Sprintf("kubelet runs with --cloud-provider=%s while the %s cloud controller is installed: the node registers without the uninitialized taint and providerID, so the CPI ignores it and the CSI cannot map it", strutil.FirstNonEmpty(v, "<unset>"), ci.Provider), nv.CloudProvider(ci.Provider)+" (re-register the node if it already has an rke2:// providerID)")
		}
	}
	evalStorageNode(name, ni, in, add)
	if !p.Probed {
		return
	}
	if p.Virt.AWS() && p.Virt.IMDS != "" && p.Virt.IMDS != "200" {
		add(SevCrit, "cloud", name, "EC2 instance metadata (IMDSv2 token request) answered HTTP "+p.Virt.IMDS+": the AWS cloud controller and EBS CSI cannot read the instance identity from this node", "enable IMDS on the instance (HttpEndpoint=enabled, HttpTokens=required is fine) and set the hop limit to 2 for pods: aws ec2 modify-instance-metadata-options --http-put-response-hop-limit 2")
	}
	hasVSphereCSI := false
	for _, d := range ci.CSI {
		if d.Provider == "vsphere" {
			hasVSphereCSI = true
		}
	}
	if p.Virt.VMware() && hasVSphereCSI && p.Virt.WWNDisks == 0 {
		add(SevCrit, "storage", name, "no /dev/disk/by-id/wwn-* on this VMware VM: disk.EnableUUID is not TRUE, so the vSphere CSI cannot identify its disks and volumes fail to attach on this node", "power off the VM, set disk.EnableUUID = TRUE (VM options > Advanced > Configuration parameters), power on; bake it into the template")
	}
	for _, vc := range p.VCenters {
		if vc.Code == 0 {
			add(SevCrit, "cloud", name, fmt.Sprintf("vCenter %s unreachable from the node (curl exit %d): the vSphere CPI/CSI pods on this node cannot reach the SDK endpoint", vc.Host, vc.Exit), "allow TCP 443 from the nodes to vCenter; check DNS and NO_PROXY for the vCenter host")
		}
	}
	// Trident host prerequisites, by backend type
	if p.CSI.Has("trident") {
		san, nas := false, false
		for _, b := range in.Snap.TridentBackends {
			d := strings.ToLower(b.Driver)
			if strings.Contains(d, "san") || strings.Contains(d, "solidfire") || strings.Contains(d, "eseries") {
				san = true
			}
			if strings.Contains(d, "nas") || strings.Contains(d, "nfs") || strings.Contains(d, "azure") || strings.Contains(d, "gcp") {
				nas = true
			}
		}
		if san && !p.CSI.ISCSID {
			add(SevWarn, "storage", name, "Trident SAN backend in use but iscsid is not running on this node: iSCSI volumes cannot attach here", "install iscsi-initiator-utils / open-iscsi; systemctl enable --now iscsid")
		}
		if san && p.Units["multipathd.service"].Active && p.CSI.FindMultipaths != "no" {
			add(SevWarn, "storage", name, "multipath.conf find_multipaths is "+strutil.FirstNonEmpty(p.CSI.FindMultipaths, "unset")+": Trident requires find_multipaths no so multipath claims the iSCSI LUNs", "defaults { user_friendly_names yes; find_multipaths no } in /etc/multipath.conf; systemctl restart multipathd")
		}
		if san && !p.Units["multipathd.service"].Active {
			add(SevInfo, "storage", name, "multipathd is not running: Trident SAN volumes attach single-path", "systemctl enable --now multipathd (with find_multipaths no)")
		}
		if nas && !p.CSI.MountNFS {
			add(SevWarn, "storage", name, "Trident NAS backend in use but mount.nfs is missing on this node: NFS volumes cannot mount here", "install nfs-utils / nfs-common")
		}
	}
}

func problemSuffix(p string) string {
	if p == "" {
		return ""
	}
	return " (" + strutil.TruncStr(p, 120) + ")"
}

func providerScheme(p string) string {
	switch p {
	case "vsphere", "aws", "azure", "openstack", "harvester":
		return p
	case "hetzner":
		return "hcloud"
	}
	return ""
}

func csiMainContainer(provider string) string {
	switch provider {
	case "vsphere":
		return "vsphere-csi-controller"
	case "trident":
		return "trident-main"
	case "aws-ebs":
		return "ebs-plugin"
	}
	return "<driver>"
}
