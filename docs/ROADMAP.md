# Ideas / roadmap

Done (2026-09):

* tab-driven collection - the journal, image inventories, PV `du`, config tier and etcd exec view follow the visible tab, fire on tab entry when stale, show their age, and carry forward otherwise; `collect.always` pins tiers, the journal has an hourly floor for the findings ([ARCHITECTURE.md](ARCHITECTURE.md) §7). Steady state on the Overview is the light + etcd probes alone (9 KB / 0.4 s CPU per node on the lab against 373 KB / 3.9 s every sixth cycle before)
* rke2 upgrade readiness - kubelet/API skew, `system-upgrade-controller` plans, `rancher-system-agent` plan state and Rancher provisioned-cluster machine plans
* registry reachability - every `registries.yaml` endpoint and its token realm probed with `curl`, plus a `crictl pull` dry run per registry through containerd (images tier)
* CSI backend health - Longhorn (volumes, replicas, nodes, disks, backups, orphans, settings; live-tested with node partitions, instance-manager and replica loss, hung RWX exports, backup failures), Trident (backends with their pools and policies, StorageClass resolution, backend configs, orchestrator, nodes, publications) and Rook-Ceph (cluster health, pools) via their CRDs, VolumeAttachments for every driver, node-side stale devices and hung mounts, a per-volume detail on the Storage tab

Partly done:

* CSI backend health - Trident is live-tested up to the backend (no ONTAP for provisioning); Trident Protect, CSI VolumeSnapshots and the NFS CSI driver are live-tested; Rook-Ceph is built from the CRD schemas and unit-tested only; Portworx and vSphere CNS still only get the generic controller/node-plugin/attachment checks; Longhorn v2 data engine, backing images and system backups are not read
* tab-driven collection - `checks.Evaluate` still reruns for every message burst (only the STIG evaluation has a dirty flag); needs are per tab, not per sub-tab; `tools/perfbench` drives its own probe options rather than the app's tab logic, so the tab-driven savings are measured with `scandrive --perf-log`, not with the bench

Open:

* certificate expiry from the API server endpoint itself (TLS dial), kubelet serving certs via CSR state (today: on-disk certificates from the config tier)
* CNI: `NetworkUnavailable` history beyond the last transition (event timeline), probes from inside a pod namespace (NetworkPolicy effects) - the node-side probes cover the overlay, DNS and service paths
* image signature/SBOM presence
* Helm: drift between HelmChartConfig and rendered values, charts pinned to deprecated APIs
* Prometheus metrics for alerting (the JSON/XLSX export exists: `e`, `tools/findings -json -xlsx`)
