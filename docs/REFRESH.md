# Refresh cadence: what talks to the cluster and nodes, and how often

One timer drives everything: `refresh` (default 30 s, floor 5 s; `--refresh`,
`refresh:` in the config). Each tick fetches an API snapshot; when that lands,
the SSH collections and the other follow-up commands are started for the
same cycle. Nothing else polls on its own timer - the pod log viewer is a
server-side stream and the spinner is UI-only.

| Work | Target | When | Cost / bound |
|---|---|---|---|
| **API snapshot** (`k8s.Client.Fetch`) | kube-apiserver | every `refresh` tick | 20 parallel list calls (version, nodes, pods, namespaces, events, PV/PVC, storage classes, CSI drivers/nodes, deployments, daemonsets, statefulsets, jobs, cronjobs, clusterrolebindings, networkpolicies, ingresses) + metadata-only secrets/configmaps/serviceaccounts + `/readyz` + `/livez` + metrics API + rke2 `etcdsnapshotfile` CRs + Rancher deployments (and the `management.cattle.io` objects on a Rancher management cluster); lists use `resourceVersion=0` (apiserver watch cache, no etcd quorum read) and protobuf; 90 s overall timeout. Measured: ~2.3 MB / 37 requests / 0.3 s on a 72-pod cluster |
| **API discovery + CRD definitions** | kube-apiserver | every `perf.discovery_ttl` (5 min) | aggregated discovery + one CRD list (each CRD carries its OpenAPI schema; the largest payload on a Rancher cluster) |
| **Helm release payloads** | kube-apiserver | only when the metadata list shows an `owner=helm` secret/configmap changed | secrets list with `type=helm.sh/release.v1` (every revision of every release) |
| **Per-node API proxy** (part of the snapshot) | kubelet via apiserver proxy | `/stats/summary` every tick, `/configz` every `perf.configz_ttl` (10 min) | 6 in parallel |
| **kubeadm-config / kubelet-config / vSphere CPI ConfigMaps** | kube-apiserver | every tick where they exist (served from the watch cache); a 404/403 is remembered for `perf.denied_ttl` so rke2/k3s/managed clusters do not ask again | 1-4 GETs |
| **Refused / missing calls** | kube-apiserver | not retried for `perf.denied_ttl` (10 min) or until `R` | any list/get/exec the token gets a 403 for, and lists of API types that return 404 (not installed); the cached error is still reported so the RBAC findings persist |
| **CRD instance counts** | kube-apiserver | on each snapshot, only while the Workloads / Resources sub-tab is open | one list (limit 1, count from metadata) per resource type |
| **Light SSH probe** (`nodeinfo.Script`, base) | every node (or `ssh.nodes`) | every `refresh` tick when SSH is on, unless the node's previous probe is still running or it is in backoff (`ssh.backoff`: last probe took > `refresh`/2) | one `sh` session per node under `renice 19` / `ionice -c2 -n7` (`ssh.nice`), `ssh.concurrency` (8) in parallel, timeout 3 x `ssh.timeout` (60 s); ~0.2 s wall / 0.2 s CPU per node, nothing sleeps or waits on D-Bus: /proc (CPU% is the delta against the previous probe's counters), df, one `systemctl show` for all units, `chronyc`/timesyncd for NTP state, kubelet cmdline (pid reused from the previous probe), cheap hardening facts. Ends with a `PERF` section (`times`, loadavg) that feeds `P` / `--perf-log` |
| **Config tier** (`Options.Config`, inside the base script) | every node | every `heavy_every` ticks, first contact, `R`; carried forward by `Info.MergeConfig` in between | certificates (`openssl` per file), sysctl subset, file modes, slow hardening commands (`needs-restarting`, `fips-mode-setup`, `mokutil`, `auditctl`, `ufw`, `pro`), rke2/k3s config.yaml(.d), audit/PSS files, server manifests, static pods, CNI confs, registries.yaml, containerd certs.d/config; ~1 s CPU |
| **Preflight** (`scripts/preflight.sh`, appended to every probe) | every node | `SWAPS` and `PFUNITS` (unit state from `/run/systemd`, no D-Bus) every tick; the rest with the config tier (fstab swap, kubelet failSwapOn, mount options, modprobe.d, DMI/cloud-init, fapolicyd rules, CSI host dirs, auditd.conf, shadow ages + faillock, proxy env, iptables version, SELinux packages, NetworkManager conf, cloud-init result/log errors, AWS IMDS, vSphere wwn disks, vCenter SDK reachability (hosts from the kube-system vsphere-cloud-config ConfigMap), Trident host prerequisites, cloud-init users + sudo/keys, registries.yaml probe: parallel `curl` to each endpoint and its token realm, 6 s cap) and `FAPDENY` (`ausearch -m FANOTIFY`, `timeout 20`) with the heavy tier | ~0.1 s CPU; the registry probe is the only network I/O |
| **Cloud / CSI** (part of the snapshot) | kube-apiserver | every tick | `tridentbackends.trident.netapp.io` list (skipped for `perf.denied_ttl` when the CRD is absent) and one GET of `kube-system/vsphere-cloud-config`; the rest (`Snapshot.Cloud`) is derived from lists already taken |
| **Heavy SSH probe** (`Options.Heavy`) | every node | every `heavy_every` ticks (default 6 = every 3 min) or on `R` / when SSH is (re)enabled | adds journal (`logs.lines` / `logs.since`), `crictl images`, container list, tarball manifests (cached by path/size/mtime), `du` of hostPath/local PVs; timeout 6 x `ssh.timeout` (120 s) |
| **OS STIG SSH probe** (`Options.OSStig`) | every node | **only on request**: `S` on the Security / OS STIG sub-tab; never on launch, refresh or `R`. Results are carried across later cycles by `Info.MergeSTIG` until the next `S` | adds `sysctl -a`, package list, unit files/states, `findmnt`, `fstab`, `sshd -T`, `auditctl -l` + rules.d, modprobe.d, `lsmod`, grub args, `stat` of the STIG-named files, `find` violation scans (de-duplicated across rule sets: 39 scans, 20 s cap each, 20 hits max) and dumps of the config files the templates read (64 KB cap each, secrets masked); ~1.2 s CPU on a stock image |
| **etcd SSH probe** (`etcd.Script`) | etcd nodes (all known hosts when the API is down) | every `refresh` tick when SSH is on (same skip/backoff rules as the light probe) | every cycle: `/health` + `/metrics` from `--listen-metrics-urls` (plain HTTP) or the TLS client port, raft files, data-dir size (~0.1 s wall / 0.1 s CPU). Heavy cycles / unhealthy member: config sources and dumps, snapshot dir listings, backup hints, leader-election scan of the etcd container log. etcdctl member/endpoint/alarm via crictl only while the API-side exec probe is not answering (API down or first cycle). `Probe.Merge` carries every skipped section forward; same timeout as the light probe |
| **etcd via `kubectl exec`** | etcd pods | every `refresh` tick | `etcdctl member list`, `endpoint health/status`, `alarm list` inside the pod (4 exec round trips); the encryption-at-rest sample (one Secret key + value, 2 more execs) only until it is known and on `R` |
| **S3 snapshot checks** | rke2 S3 secret / one etcd node | on demand (when an etcd probe reports an S3 config) | one secret read; one SSH connectivity test |
| **Helm latest-version lookup** (`helmcheck`) | chart repos / Artifact Hub (outbound HTTP) | on each snapshot, but served from cache | repo indexes and Artifact Hub answers cached 1 h; helm's own `<repo>-index.yaml` cache is the offline fallback |
| **Pod log viewer** | apiserver log stream | while the overlay is open (`L`) | one streaming `GET .../log?follow=true` per selected container; nothing when closed |
| **STIG / CIS evaluation** (`stig.Evaluate`) | local | after every snapshot, and once 250 ms after the last node/etcd/helm/S3 message of a burst (coalesced `recompute`) | CPU only, no remote calls; ~450 OS rules per node evaluate in milliseconds |
| **Findings / history** | local | after every snapshot / node message | 90-sample in-memory series per metric |

## Why the OS STIG probe only runs on request

The light probe is designed to be cheap enough for every tick. The OS STIG
facts are not: `rpm -qa`, `sysctl -a`, a `find` sweep over the local
filesystems, `auditctl -l`, `sshd -T` and ~60 file dumps add a few seconds
of CPU and 50-100 KB of output per node, and none of it changes minute to
minute. So the scheduler (`App.collectCmds`) sets `Options.OSStig` only for
the cycle after the user presses `S` on the Security / OS STIG sub-tab; the
key does nothing anywhere else, and neither launch, `r`, `R` nor re-enabling
SSH trigger it.

Until a node has been collected its OS STIG rules are not emitted at all -
the sub-tab is empty with the hint to press `S`, and the Node hardening
column reads "not collected". After a collection `Info.MergeSTIG` copies the
facts forward on every later cycle, so the results stay populated, and the
header shows how old they are; press `S` again to re-collect.

## Footprint

`P` shows what the last cycles cost the API server, each node (remote CPU
seconds per probe, from the `PERF` section every script ends with) and this
host; `--perf-log` writes it per cycle and `tools/perfbench` measures it
headlessly with baseline-vs-during CPU sampling on the nodes.
[PERFORMANCE.md](PERFORMANCE.md) has the numbers and the rules.

## Tuning

```yaml
refresh: 30s        # API snapshot + light SSH + etcd probes (min 5s)
heavy_every: 6      # heavy SSH probe every N refreshes (journal, images, tarballs, PV du)
ssh:
  timeout: 20s      # per-command SSH timeout; light probe gets 3x, heavy 6x
  concurrency: 8    # parallel SSH sessions
  nodes: [...]      # restrict SSH collection to these nodes
  nice: true        # renice/ionice the probes on the nodes
  backoff: true     # skip a cycle for nodes whose probe is slow or still running
perf:
  watch_cache: true # lists from the apiserver watch cache (resourceVersion=0)
  protobuf: true
  discovery_ttl: 5m
  configz_ttl: 10m
  denied_ttl: 10m   # API calls the token is refused (403) / types that do not exist are skipped for this long
logs:
  lines: 400        # journal lines per unit in the heavy probe
  since: -24h
```

`s` turns SSH collection off entirely (API-only mode); `r` forces an
immediate light cycle; `R` forces a heavy cycle; `S` (OS STIG sub-tab only)
collects the OS STIG facts.
