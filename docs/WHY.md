# Why I built this

- I run rke2 and kubeadm clusters on hardened hosts: DISA STIG, FIPS, fapolicyd, SELinux enforcing, often airgapped, often behind a Rancher management cluster
- when one misbehaves the question is rarely "which pod is red" - k9s shows that in seconds; it is:
  - why is the third etcd member stale
  - did containerd actually apply the mirror in `registries.yaml`
  - which node's kubelet cert expires this weekend
  - is that Longhorn volume degraded even though the PVC says `Bound`
  - does the cluster still pass the RKE2 STIG after the last upgrade
- answering those meant an SSH session per node, `etcdctl` with the right certs, `crictl`, `journalctl`, and a pile of scripts I kept rewriting
- `khealth` is those scripts turned into one screen that keeps its findings ranked and the evidence one keypress away

## What already exists

Surveyed September 2026, CLI tools only; each covers one slice:

- **Popeye** - API-side sanitizer: dead resources, missing limits/probes, RBAC, a health score. No nodes, no etcd.
- **Kubeowler** - API-side checks of nodes, pods, storage, certs and control plane; scored Markdown/JSON/HTML reports. No SSH, no etcd.
- **K8sGPT** - workload analyzers with LLM explanations. API only.
- **kdebug** - batch SSH to kube-discovered nodes: disk, DNS/HTTP, load, OOM, restarts. The only one that paired the API with SSH; archived 2026-09-15.
- **WatchSSH** - agentless host checks over SSH: inodes, NIC errors, fd pressure, NTP, TLS. Not Kubernetes-aware.
- **kube-bench** - CIS Kubernetes Benchmark, run on the node (Rancher's compliance scans wrap it). CIS only, no STIG.
- **Kubescape** - CIS / NSA-CISA posture of manifests and RBAC. API only.
- **InSpec + k8s-node-stig-baseline** - the Kubernetes node STIG as an InSpec profile, run per host. No RKE2 or Rancher STIG.
- **OpenSCAP** (`oscap`) - the OS STIG, run on the host.
- **etcd-defrag** - member health plus smart defragmentation, against the etcd endpoints directly. Single purpose.
- **etcd-tui** - a key/value browser for etcd. Data, not health.
- **Troubleshoot** (`kubectl support-bundle` / `kubectl preflight`) - YAML collectors and analyzers, host collectors run locally, archive output. A framework you write specs for.
- **rancher2_logs_collector.sh** - the official rke2/k3s log and config collector, run as root on each node. Collects, does not judge.
- **`rke2 etcd-snapshot`** - create / list / prune snapshots. Snapshots only.

## The gap

Every one of them is API-only, host-only, or a collector that hands the analysis back to me. None of them:

- reads the **kubeconfig and the nodes over SSH in the same view** and reconciles the two (etcd members vs Node objects, `registries.yaml` vs containerd's `certs.d`, airgap tarballs vs running images, CSI registrations vs the node-side devices); kdebug was the only tool that combined the API with SSH, and it is archived
- **triages etcd** into a named case with numbered steps, or drives the repair (rejoin one server, restore a snapshot onto a whole control plane) with the pre-flight checks that make it safe
- knows the **rke2 / Rancher layer**: `config.yaml(.d)` drift between servers, bundled `HelmChart` and `HelmChartConfig` overrides, `ETCDSnapshotFile` records, system-upgrade-controller plans, `rancher-system-agent` and provisioned-cluster machine plans
- evaluates the **Kubernetes, RKE2, Rancher MCM and OS STIGs together with CIS**, from the operator's machine, with the evidence per rule and per node, and exports it per benchmark
- joins the **storage backend's own health** (Longhorn replicas and engines, Trident backends and publications, Ceph pools) to the claim, the PV, the VolumeAttachment and the measured usage - the PVC stays `Bound` while the volume underneath is degraded
- does any of it **interactively**: the health tools above are batch report generators, the TUIs are resource browsers

## Why client-side

Not an operator, not an in-cluster scanner, not synthetic-check pods:

- an etcd restore happens on a live cluster: quorum is lost, the apiserver is refusing connections or answering from stale data
- I am about to stop `rke2-server` on every control-plane node, move data directories aside and run `cluster-reset`
- anything running inside the cluster - K8sGPT's operator, Kuberhealthy, kube-bench as a Job, a Prometheus stack - is exactly what is unavailable at that moment
- so the tool lives on my machine, reaches the nodes over SSH when the API cannot help, and keeps working while the control plane is torn down and brought back
- hence: nothing installed in the cluster, `khealth user@node` bootstraps its own kubeconfig, and the etcd tab's SSH probes are fallbacks to the `kubectl exec` path rather than the other way round

## Ten tools for one

- a full check used to mean reaching for ten of the above: a sanitizer for the API, `kube-bench` and `oscap` on each node, `etcdctl` and `rke2 etcd-snapshot` on the servers, the log collector, the Longhorn CLI, InSpec for the STIG, plus my own SSH loops
- most of them ran rarely enough that I re-learned their flags every time
- `khealth` is one binary I open every day: the tabs I use to glance at a healthy cluster in the morning are the same ones I use to triage etcd or run the STIG scan when something breaks
- a tool used daily is familiar exactly when it needs to be

- deliberately narrow: two distributions, Linux nodes, read-only by default
- the [support matrix](SUPPORT.md) says exactly what has been run against a real cluster and what is only built from schemas
