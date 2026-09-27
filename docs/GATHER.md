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

## Analyzing a bundle (`--analyze`)

`khealth --analyze bundle.tar.gz` (or an unpacked directory) needs no kubeconfig and no SSH. It rebuilds the
checks' input from `snapshot.json` and the raw probe output, then evaluates it as of the moment the bundle was
gathered, with the local config's thresholds. The output prints the findings and compares them with the
`report.json` recorded at gather time. A difference means the checks changed between the two khealth versions,
or the thresholds did.

```sh
khealth --analyze khealth-bundle-prod-20260926-101112.tar.gz
khealth --analyze ./khealth-bundle-prod-20260926-101112 --export findings.xlsx   # also write the report (.json, .xlsx, .md or a directory)
```

A bundle whose `manifest.json` has a newer `format` than the running khealth reads is refused.

### Root-cause analysis

Before the findings, `--analyze` prints the probable causes, best supported first, followed by a timeline.

**The timeline** (`internal/rca`) puts everything the bundle recorded on one clock:

- every journal of every node, and rke2's `kubelet.log` / `containerd.log`, classified together with the log knowledge base so that restart noise is recognised as such
- the kernel log
- container logs, both on disk and through the API
- events
- each container's last termination and each node condition change from the snapshot

Only lines the knowledge base recognises become entries; a journal is mostly routine. Two corrections keep the nodes on one clock:

- Each node's times are shifted by the clock offset its probe measured, when that is over 2 s.
- klog lines, which carry local time without a zone, are read in the node's UTC offset, which `gather.sh` records.

**The rules** each take a cause and look for the effects that should follow it in time. The more of the chain appears, the higher the confidence (low, medium, high):

| Rule | Cause | Effects it looks for |
|---|---|---|
| etcd latency | slow fsync / apply warnings (or, without them, repeated leader elections) | leader elections, controllers losing their lease, kubelets failing node-lease renewals, NotReady nodes |
| disk | `no space left on device`, DiskPressure | evictions, image GC failures |
| memory | OOMKilled containers (with their limit); the kernel OOM killer, MemoryPressure | evictions for memory |
| image pull | failed pulls grouped by image | the cause, from the registry's answer: credentials, TLS, unreachable, missing tag, rate limit |
| crash loop | restarting containers: exit code, reason and the last error line of the previous run | exits with 0 (the command does not stay in the foreground) |
| liveness | failing liveness probes | the kubelet killing the container |
| NotReady node | the node's own warnings and errors in the 15 minutes before it turned | SSH failing too (the machine is down or cut off, not only the kubelet) |
| scheduling | FailedScheduling, grouped by reason | the pending pods |
| admission | Pod Security, ResourceQuota, admission webhooks | the controllers that cannot create pods |
| sandbox / volumes | FailedCreatePodSandBox (CNI), FailedMount / FailedAttachVolume | the pods stuck in ContainerCreating |
| host | fapolicyd and SELinux denials | |
| trust and join | token, CA, cluster-ID and member mismatches, clock skew, port in use, swap, kernel defaults, containerd or kubelet exiting, when they persist | |
| unit restarts | systemd restarting a service | the error the service logged just before its first restart |

Every piece of evidence names its bundle file and line (`nodes/cp-2/journal/rke2-server.log:1830`).
`--timeline FILE` writes the full timeline: JSON lines for `.jsonl`, text otherwise.

### Incidents, one at a time

Below the probable causes, `--analyze` lists the **incidents**, one line per workload, with the replicas folded into a count:

- OOM kills (a container's limit) and node OOM (the kernel killer)
- evictions, and the kubelet refusing to admit pods while the node is under pressure
- restarts, liveness kills, image pulls, unschedulable pods, denied creates, volume and sandbox (CNI) failures
- NotReady nodes and node pressure

`--incident ID` shows one incident in context:

```sh
khealth --analyze bundle.tar.gz --incident eviction-2
khealth --analyze bundle.tar.gz --tui          # the same, browsable: every tab from the bundle, Incidents first
```

The context has these parts:

- **Who caused it**, ranked, each suspect with its reasons:
  - **Evictions.** The kubelet evicts one pod at a time and stops as soon as the node is back above its threshold, so **the last eviction of the episode names the pod whose memory the node lacked**. That holds even when the kubelet's message carries no usage for it. Other signals add weight: usage above request (the kubelet's own eviction messages first, metrics otherwise), no memory limit, priority, and how long before the incident a pod was scheduled onto the node. Pods whose requests cover their use are not suspects. Fellow victims of the same episode are not causes.
  - **Every kind:**
    - a Deployment revision rolled out within the window before (a first deploy does not count)
    - a dependency that the container's last log lines name (`cannot connect to db:5432` → the `db` Service's workload) and that failed first
    - memory pressure, OOM or NotReady on the same node before a restart
- **The workload:** desired and ready replicas, revisions with their images, pods with restarts and memory.
- **The node at that moment:** every pod present, with QoS, priority, requests, limits, use and arrival time, the suspects first; plus requests and use against what the node can allocate.
- **Traffic:** access logs of ingress-nginx, Traefik (common and JSON format; `accessLog` must be enabled) and Envoy (Istio, Gateway API), matched to the Services that select the workload's pods (by upstream name, or pod IP). Shown as requests per minute with 5xx, 4xx and p95, the Ingress/HTTPRoute objects in front, and the 5xx nearest the incident. The gather always collects the controllers' logs, with 4× the per-pod cap.
- **The timeline around it:** the node, the namespace, and the control plane (etcd, leases).
- **The last log lines** of the container's previous run.
- **The cluster:** every node's requests and use.

The same view is the **Incidents tab** of the live TUI (key `7`). There, the incidents come from the events, pod states and node journals khealth already collects, and an opened incident reads pod logs, ReplicaSets, pod metrics and HTTPRoutes through the API in the background.

The rules are checked end to end by the Docker lab in [test/gatherlab](../test/gatherlab/README.md): a k3s cluster with staged incidents and a stand-in node over SSH.

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
- **Analysis.** Log files are streamed, and only the lines some knowledge-base pattern could match are kept. For a synthetic bundle of 3 × 250k journal lines, 3,000 pods, 20,000 events, 400 pod logs and 200k access-log lines:
  - timeline: 3.3 s, 60 MiB peak heap
  - probable causes: a few ms
  - one incident's context: a few ms
  - At four times that size (7M log lines): 13.7 s and 221 MiB. Details in [PERFORMANCE.md](PERFORMANCE.md).

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
  - `--analyze`: replay reproduces the gather-time findings. The gatherlab check (test/gatherlab) passes: every staged incident is named by its rule, nothing leaks. `internal/rca` tests cover the etcd chain, OOM, crash loop, scheduling, clock-skew correction and node time zones.
- **Not yet run** against the rke2 (RHEL 9, SELinux/fapolicyd) and kubeadm (Ubuntu 24.04) lab clusters: the
  checks still to do are in [GATHER-VALIDATION.md](../GATHER-VALIDATION.md).
- **Supported:** the distributions and node OSes in [SUPPORT.md](SUPPORT.md).
