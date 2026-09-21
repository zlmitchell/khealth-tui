# Support matrix

*Tested* = exercised against a live cluster in the lab (what those clusters are is under each table). *Supported* = the code paths and unit tests exist, built from the API/CRD schemas or the vendor's documented layout, but no live cluster of that kind has run through it yet - expect rough edges and report them. Nothing else is claimed.

The lab: rke2 v1.34 single node (Rocky Linux 9.7, Rancher v2.13 management cluster, Harbor registry, csi-driver-nfs, local-path), rke2 v1.35 three-server control plane (RHEL 9.6, DISA STIG + FIPS, fapolicyd, `profile: cis`, Longhorn), kubeadm v1.35 three-node stacked-etcd control plane (Ubuntu 24.04 LTS, DISA STIG); Canal on all three. The operator host is Windows; Linux binaries are built the same way but exercised less.

## Kubernetes distributions

| Distribution | Status | Notes |
|---|---|---|
| RKE2 | tested | v1.34-v1.35, single node and 3-server, `profile: cis` |
| kubeadm / upstream | tested | v1.35, 3-node stacked etcd (containerd); the Config tab and kubeadm cert/SAN checks |
| k3s | supported | same code paths as rke2 (data-dir, `k3s.yaml`, `k3s crictl`, embedded etcd); no k3s cluster in the lab |
| Rancher management cluster | tested | Rancher v2.13 on rke2: MCM STIG rules, local users/auth providers, provisioned-cluster listing |
| Rancher-managed (imported) cluster | supported | cattle-cluster-agent, fleet-agent, system-upgrade-controller plans; the Rancher-side views were exercised on the management cluster only |
| Rancher-provisioned (v2prov) cluster | supported | machine plans / RKEControlPlane conditions are read from the management cluster; built from the planner's secret layout, unit-tested, no downstream cluster in the lab |

## Node operating systems

| OS | Status | Notes |
|---|---|---|
| RHEL 9 (and Rocky / Alma / CentOS Stream / Oracle 9) | tested | preflight, hardening table, DISA RHEL 9 STIG V2R9 (445 rules), FIPS, fapolicyd, SELinux enforcing |
| Ubuntu 24.04 LTS | tested | preflight, hardening table, DISA Ubuntu 24.04 STIG, ufw, AppArmor, unattended-upgrades |
| RHEL 8, RHEL 10 | supported | DISA STIG tables generated the same way as RHEL 9; not run on a node |
| Ubuntu 22.04 LTS | supported | DISA STIG table present; not run on a node |
| SLES / SLE Micro, Flatcar, others | supported | the generic checks (preflight, hardening, `OS-*` rules); no DISA table, so the OS STIG sub-tab is empty |

## CNI

| CNI | Status | Notes |
|---|---|---|
| Canal | tested | overlay/underlay MTU, node-side pod / DNS / service probes |
| Calico, Cilium, Flannel, Multus | supported | detection, interface MTU and the node-side probes are CNI-agnostic; not run with these in the lab |

## Storage / CSI

| Driver | Status | Notes |
|---|---|---|
| Longhorn | tested | volumes, replicas, engines, nodes/disks, instance managers, backups, orphans, settings, node-side devices; chaos-tested (node partitions, replica and instance-manager loss, hung RWX exports, backup failures) |
| local-path-provisioner / hostPath | tested | PV `du` on the nodes, hung mounts |
| csi-driver-nfs / SMB | tested (nfs) | csi-driver-nfs 4.13.0 against an Unraid export: the generic controller / node-plugin / attachment checks, a claim without snapshot support inside a Trident Protect application; hung-mount detection was exercised with Longhorn RWX exports |
| NetApp Trident | tested (no provisioning) | Trident 26.06.1 in the lab: operator state, TridentNode registrations and host inventories, a backend config failing against an unreachable LIF, class registration and resolution; provisioning, publications and the backend pools need an ONTAP that the lab lacks (unit-tested from the CRD schemas) |
| NetApp Trident Protect | tested | 26.06.0 in the lab: vaults (MinIO and an unreachable S3), applications, snapshots/backups (completed and failed), schedules, runs stuck deleting, the application-lock Lease and its stale-holder case |
| CSI VolumeSnapshots | tested | snapshot.storage.k8s.io classes/snapshots/contents with Longhorn: ready, missing source, no default class for the driver, class for an absent driver |
| Rook-Ceph | tested | Rook v1.20.7 / Ceph 20.2 in the lab on loop devices (3 OSDs, ceph-csi-operator drivers `rook-ceph.rbd.csi.ceph.com`): cluster health with the check details ranked by what they mean for the data, pools, capacity, an OSD taken down (OSD_DOWN / PG_DEGRADED), an RBD claim end to end; CephFS and object stores from the schema only |
| vSphere CNS, AWS EBS/EFS, Azure Disk/File, OpenStack Cinder, Harvester, Portworx | supported | generic controller / node-plugin / CSINode / VolumeAttachment checks and the cloud-provider checks; not run in the lab (KVM) |

## Cloud providers

| Provider | Status | Notes |
|---|---|---|
| none / rke2 embedded stub | tested | providerID scheme, `uninitialized` taint |
| vSphere CPI, AWS, Azure, OpenStack, Harvester | supported | which CCM runs, node initialization, `vsphere.conf`, IMDS/vCenter reachability from the nodes; no such cluster in the lab |

## Major features

| Feature | Status | Notes |
|---|---|---|
| Health findings, node preflight, log classification | tested | all three lab clusters, continuously |
| Bootstrap a kubeconfig over SSH (`khealth user@node`) | tested | rke2 and kubeadm servers, VIP/SAN ranking |
| etcd triage (quorum, leader, latency, member vs node reconciliation) | tested | rke2 and kubeadm; exec-based member view and the SSH fallbacks |
| etcd rescue - rejoin one broken server | tested | rke2 3-server (RHEL 9 STIG) and kubeadm 3-node (Ubuntu STIG): stop, move data aside, member remove/add, rejoin, CNI restart, endpoint check |
| etcd rescue - restore a snapshot, single node | tested | rke2 single server and kubeadm single node |
| etcd rescue - restore a snapshot, whole control plane | tested | rke2 3-server (`cluster-reset`, VIP + shared token pre-flight) and kubeadm 3-node, restored from any of the servers |
| etcd rescue on k3s | supported | same steps as rke2 with the k3s paths; not run |
| etcd S3 snapshot configuration and endpoint reachability | supported | rke2 `etcd-s3` settings, secret, endpoint probe from the etcd nodes; unit-tested, no S3 target in the lab |
| Security scan: Kubernetes STIG, RKE2 STIG, CIS | tested | rke2 and kubeadm clusters |
| Security scan: Rancher MCM STIG | tested | Rancher v2.13 management cluster |
| Security scan: OS STIG collection over SSH | tested | RHEL 9 (STIG/FIPS/fapolicyd) and Ubuntu 24.04, four stages per node |
| Registry probes (`registries.yaml` curl + `crictl pull` dry run) | tested | Harbor (token auth, `insecure_skip_verify`), hand-rendered `hosts.toml` failure paths on containerd 2.x |
| Upgrade readiness: system-upgrade-controller plans | tested | SUC v0.20 on rke2: unpullable image, missing version, skipped minor, unresolvable channel, completed plan |
| Upgrade readiness: Rancher provisioned-cluster machine plans | supported | unit-tested against the planner's secret layout |
| Helm actions (`u` upgrade, `b` rollback, `B` rollback to the last deployed revision) | supported | run the `helm` CLI after a confirmation; the overlays, the last-good revision choice and the command lines are unit-tested, a live upgrade/rollback has not been run from khealth in the lab |
| Export (`e`, `--export`, JSON + XLSX) | tested | the RHEL 9 cluster with the full STIG scan (five benchmarks, 445 OS rules with per-node columns), the Rancher cluster with `--no-ssh` |
| Footprint measurement (`P`, `--perf-log`, `tools/perfbench`) | tested | baseline in [PERFORMANCE.md](PERFORMANCE.md) |
