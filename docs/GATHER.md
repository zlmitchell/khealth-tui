# Log bundles (`--gather`)

`khealth --gather DIR` collects what a root-cause analysis needs into one `.tar.gz`, without the TUI. It does
what the rke2 log collector does on one node, but for every node of an rke2, k3s or kubeadm cluster at once. It
also adds the API's view and khealth's own probes and findings.

```sh
khealth --gather ./bundles                                   # the cluster, last 24h
khealth --gather ./bundles --gather-since 6h                 # a shorter window
khealth --gather incident.tar.gz --gather-workload shop/deploy/web   # one workload
khealth --gather ./bundles --ssh-nodes cp-1,cp-2             # only these nodes over SSH
```

## Scope

**Cluster** (the default) collects:

- every object type below, in all namespaces
- the logs of every pod in a system namespace
- the logs of any pod elsewhere that is pending, failed, not ready, waiting (CrashLoopBackOff, ImagePullBackOff), being deleted, or restarted within the window
- every node over SSH

**Workload** (`--gather-workload namespace/kind/name`; kind is `deploy`, `sts`, `ds`, `rs`, `job`, `cronjob` or `pod`) exists because a deployment problem is often invisible from pod health: a rollout stuck with every pod Running, a probe that passes on a bad config. It collects:

- every pod the workload owns, healthy or not: all revisions through its selector, and for a CronJob the pods of the Jobs it created
- current and previous logs of each of those pods
- the objects and events of the workload's namespace, plus the cluster-scoped types (nodes, webhooks, APIServices, storage classes, ...)
- over SSH, the nodes its pods run on plus the control-plane and etcd nodes, where a stuck rollout usually ends up (scheduler, controllers, webhooks). `--ssh-nodes` overrides this.

**API down.** When the API server lists no nodes, the nodes come from `ssh.hosts`, and every one of them gets the etcd probe. The on-disk pod logs widen from the static control plane to every platform namespace (`kube-system`, `cattle-*`, `calico-*`, `longhorn-system`, ...), since the API cannot serve them. This is the case the bundle matters most for.

## Layout

```
khealth-bundle-<context>-<timestamp>/
  manifest.json       what is in the bundle and what could not be collected (per node: ok or the error, skipped and truncated items)
  report.json         the findings, as --export writes them
  snapshot.json       khealth's API snapshot (scrubbed, below)
  cluster/api/        /version, /readyz?verbose, /livez?verbose
  cluster/resources/  <resource>[.<group>].yaml, one List per type
  cluster/pods/<ns>/<pod>/<container>[.previous].log   through the API, with timestamps
  nodes/<node>/
    probe/node.txt, probe/etcd.txt   raw output of khealth's node and etcd probes (heavy tiers included)
    system/     os, versions, meminfo, PSI, df, mounts, ps, top, limits, failed units, unit files, time sync, SELinux/AppArmor/FIPS, dmesg, sysctl + lsmod, audit denials
    journal/    one file per kubernetes unit (rke2-server/agent, k3s, kubelet, containerd, ...), kernel, all warnings, the previous boot's last 5000 lines, host units (NetworkManager, firewalld, fapolicyd, chrony, iscsid, ...)
    files/      rke2/k3s agent/logs/*.log and containerd.log, /var/log/messages or syslog
    runtime/    crictl ps -a / pods / images / info (table and JSON), kubelet healthz
    pods/       /var/log/pods/<ns>_<pod>_<uid>/<container>/<n>.log: the two newest runs of each container, so the run before a crash is there even when the API cannot serve --previous
    network/    addresses, routes (all tables), rules, neighbours, link stats, listening sockets, iptables/ip6tables/nft/ipvs, firewalld/ufw, DNS files, CNI config
    config/     rke2/k3s config.yaml(.d) and registries.yaml, containerd/CRI-O config and hosts.toml, kubelet config, static pod manifests, certificate subjects/SANs/dates
    _gather/    node.env (staging dir, budget, bytes used, seconds), skipped, truncated, stderr.txt
```

The raw probe output is there so that the findings can be computed again from the bundle alone, and so that a
later analysis can put the journals, events and pod logs on one timeline.

## Cost and limits

| Setting (`gather:` in the config) | Flag | Default | What it caps |
|---|---|---|---|
| `since` | `--gather-since` | 24h | how far back journals, pod logs and on-disk pod logs go |
| `node_mb` | `--gather-node-mb` | 200 | uncompressed MiB per node; items are collected most useful first, and whatever does not fit is listed in `_gather/skipped` |
| `file_mb` | | 20 | per file; the newest end is kept and the cut noted in `_gather/truncated` |
| `pod_log_mb` | | 5 | per container log (API and on-disk) |

- **On the node**, `gather.sh` stages its outputs in a private directory under `/var/tmp` or `/tmp` and streams them back as one gzipped tar over the existing SSH session. The directory is removed on exit; a run that was killed is cleaned up by the next one after two hours. When neither directory has room (a full disk is a common reason to gather), tmpfs (`/run`, `/dev/shm`) is used only if MemAvailable holds four times the budget, so that the collection does not push a node that is short of memory into the OOM killer.
- **Resources.** The script runs under the same `renice 19` / `ionice` best-effort-lowest prologue as every probe, and every command has a 120 s timeout. It needs `tar` on the node, and uses `gzip` when present.
- **Locally**, the bundle is assembled in the system temp directory and packed once at the end, so plan for about `nodes × node_mb` of local disk.

## What is left out or masked

Review a bundle before it leaves your organisation. What is left out or masked:

- **Never read:** private keys, kubeconfigs (`rke2.yaml`, `admin.conf`, `kubelet.conf`), the encryption config, `/etc/cni/net.d/calico-kubeconfig`.
- **Secrets and ConfigMaps:** only the keys; each value is replaced by its length.
- **Helm values** in `snapshot.json`, and `valuesContent` / `chartContent` in HelmChart and HelmChartConfig: not collected.
- **Every object:** `managedFields` and the `kubectl.kubernetes.io/last-applied-configuration` annotation are removed. The annotation is a full copy of the object, env values included.
- **Env values** whose name looks like a credential (`pass`, `secret`, `token`, `key`, `cred`, `auth`, `private`) are masked in every pod and pod template. `valueFrom` references are kept.
- **Config dumps** go through the probe's `mask` / `maskreg`. On top of that, flags and env lines naming a token, password or secret are masked, as are `password` / `auth` / `token` keys in TOML.

Pod and journal logs are copied as they are: an application that logs its own secrets will have them in the bundle.

## Tested / supported

- **Tested** (2026-09-26):
  - the API half against k3s v1.33.4 in Docker, cluster and workload scope
  - the node half over real SSH against Debian 12 (dash)
  - the API-down fallback through `ssh.hosts`
  - `internal/gather` tests: running `gather.sh` under `sh`, tar path handling and limits, the scrubbing rules, pod selection
- **Not yet run** against the rke2 (RHEL 9, SELinux/fapolicyd) and kubeadm (Ubuntu 24.04) lab clusters: the
  checks still to do are in [GATHER-VALIDATION.md](../GATHER-VALIDATION.md).
- **Supported:** the distributions and node OSes in [SUPPORT.md](SUPPORT.md).
