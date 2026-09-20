# Performance: what khealth costs the systems it inspects

khealth is used on clusters that are already unwell. A diagnostic tool that
adds a quorum read to etcd every 30 s, or a second of CPU to every node it
watches, makes the thing it is diagnosing worse. This document covers how the
footprint is measured, what it is, how to run the benchmark against your own
cluster, and the rules the collection follows to stay small.

## Measuring

Three vantage points, all built in:

| Where | What is measured | How |
|---|---|---|
| **Nodes** | CPU seconds each probe and everything it spawned used, load average when it finished, output bytes | every script ends with a `PERF` section: `/proc/loadavg` and the POSIX `times` builtin (shell + children user/sys). Parsed into `Info.Cost` / `Probe.Cost` |
| **API server** | requests, response bytes, request bytes, wall time per refresh | a counting `http.RoundTripper` wrapped around client-go (`Client.Stats()`); `Fetch` records the delta in `Snapshot.Traffic` / `FetchDuration` |
| **This host** | CPU seconds per cycle, heap, goroutines, recompute count/time | `runtime/metrics` (`/cpu/classes/total` minus idle); works on Windows too |

Ways to see it:

- **`P`** in the TUI: last cycle per node/probe (wall, remote CPU, load, output),
  API traffic, local CPU, and per-node averages over the last 20 cycles as a
  share of one core.
- **`--perf-log file.jsonl`** (`perf.log`): one JSON record per refresh cycle
  with everything above; the status bar shows a one-line summary each cycle.
- **`--pprof 127.0.0.1:6060`** (`perf.pprof`): `go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30`
  for the local side.
- **`tools/perfbench`**: headless. Runs N refresh cycles (API snapshot, light
  probes, one heavy+STIG+config first-contact cycle, etcd probes), prints per
  probe wall / remote CPU / output and the equivalent share of one core at
  the configured refresh, and with `-monitor` samples CPU and load on every
  node once a second over a *separate* SSH session, before the probes start
  (baseline) and while they run. `-api-compare` fetches the snapshot again
  with the API-side reducers off. `-json` writes the full report.

```sh
go build -o perfbench ./tools/perfbench       # or ./build.sh with the tools path
./perfbench -cycles 5 -monitor -baseline 15s -api-compare -json bench.json -- --kubeconfig ~/.kube/config --ssh-user ubuntu
./perfbench -cycles 5 -- --no-nice            # A/B one knob: everything after -- is a khealth flag
./perfbench -cycles 3 -no-ssh                 # API only
```

- **`tools/scandrive`**: headless too, but it drives the real TUI model:
  every command the update loop returns is executed and fed back, so the
  refresh cycle, probes and the Security scan behave exactly as in the
  terminal. `-press 23s` presses `0` + `Shift+S` that long after the first
  snapshot; each message is logged with the header line, and the OS STIG
  sub-tab is printed when the scan finishes. Use it to reproduce
  timing-dependent behaviour (a scan pressed just before a refresh tick):
  `scandrive -press 23s -- --kubeconfig ~/.kube/x.yaml --ssh-user root --ssh-key ~/.ssh/id_rsa`.

Per-section CPU of a probe script (to find what to move out of the light
tier): run it with `times` at each section boundary, e.g.
`go run ./tools/scriptdump -config=false | ssh root@node sh -s` with `sec()`
redefined to `times >&2; echo "--- $1" >&2` - that is how the numbers below
were obtained.

## Measured (single-node RKE2 v1.34 / etcd 3.6.7 / Rocky 9, 72 pods, 30 s refresh)

Per refresh cycle, steady state:

| | before | after |
|---|---|---|
| API: bytes from the apiserver | 9.1 MB (JSON, quorum reads) | **2.3 MB** (protobuf, watch cache) |
| API: fetch wall time | 1.1 s | **0.32 s** |
| API: requests | 41 | 37 |
| local CPU for the fetch | 1.0 s | **0.2 s** |
| node: light probe remote CPU | 1.32 s (4.4 % of a core) | **0.19 s (0.65 %)** |
| node: light probe wall / output | 2.3 s / 39 KB | **0.21 s / 14 KB** |
| etcd probe remote CPU / wall | 0.43 s / 0.5 s | **0.10 s / 0.09 s** (no log scan while healthy, no etcdctl while the API exec probe answers) |
| **total remote CPU per node per cycle** | **1.75 s (5.8 % of a core)** | **0.29 s (1.0 %)** |

One-off cycles:

| | before | after |
|---|---|---|
| first contact (light + config + heavy) | 4.99 s CPU, 7.3 s wall, 1.3 MB | **~1.6 s CPU**, ~2.5 s wall (1 s of it the one-time CPU sample) |
| OS STIG facts (`Shift+S` on the Security tab) | 7.2 s CPU, 7.4 s wall - and the filesystem sweep stopped at 200 container-rootfs hits before reaching the host | **~3.5 s CPU / ~3.5 s wall**, of which the full host sweep (175 K entries) is 2.0 s / 1.4 s |
| first API snapshot (discovery + every CRD schema + helm payloads) | 18.7 MB | 18.7 MB, then cached (5 min / until a release changes) |
| `find` scans in the OS STIG probe | 174 | **39** (same output) |
| local `stig.Evaluate` per node per recompute | 3.5 ms, 1.2 MB allocated | **2.7 ms, 0.7 MB** (compiled patterns cached) |

The independent node sampler (1/s over a second SSH session) on that box:
baseline 26 % CPU across all cores, 37 % while five probe cycles ran back to
back with no pause, i.e. about +11 % during a burst that in normal operation
is spread over 2.5 minutes.

## What the collection does to stay small

**On the nodes**

- Every script runs under `renice -n 19` and `ionice -c 2 -n 7` (`ssh.nice`,
  default on). It yields to kubelet, etcd and the workloads; on an idle node
  nothing changes. The idle I/O class is not used because on a saturated disk
  it can starve the probe past its timeout and lose the data that matters.
- Nothing in the live tier waits. CPU utilization is the delta between this
  probe's `/proc/stat` counters and the previous probe's (`Info.CPUFromPrev`,
  a 30 s window) instead of a `sleep 1` on the node; only first contact
  samples twice. NTP state comes from `chronyc tracking` (6 ms) or
  timesyncd's `/run/systemd/timesync/synchronized`; `timedatectl` (which
  wakes `systemd-timedated` over D-Bus, ~0.8 s wall) only runs on config
  cycles when neither is there. The kubelet pid from the previous probe is
  reused instead of `pidof` walking `/proc` (40 ms).
- Three tiers instead of one script every cycle:
  - **live** (every refresh, ~0.2 s wall / 0.2 s CPU): `/proc` reads, `df`,
    one `systemctl show` for every unit of interest, kubelet cmdline, cheap
    hardening facts;
  - **config** (`heavy_every` cycles, first contact, `R`; ~1 s): certificates
    (`openssl` per file), sysctls, file modes, rke2/k3s config and manifests,
    registries, and the hardening commands that spawn real tools
    (`needs-restarting` alone is 0.3 s of python);
  - **heavy** (same cadence): journal, `crictl images/ps`, tarball manifests
    (cached by path/size/mtime), `du` of hostPath PVs, the registry pull
    dry run (`crictl pull` by digest, ~1 s wall in parallel per registry,
    0.03 s CPU);
  - **OS STIG** (`Shift+S` on the Security tab only, four stages per node,
    each its own SSH run): `sysctl -a`, package list, unit files, `find`
    scans (de-duplicated across the RHEL 8/9/10 and Ubuntu rule sets),
    config dumps, and one filesystem sweep. The sweep
    walks host filesystems only - overlay/nsfs mounts are running
    containers' root filesystems (150+ on a busy node) and containerd /
    docker image layer stores and kubelet pod volumes are pruned - in a
    single `find -printf` pass whose uid/gid checks run in awk against the
    account database: find's own `-nouser`/`-nogroup` call NSS once per
    file, which with `sss` in nsswitch was 25 s for the host. Unknown ids
    are confirmed with a few `getent` lookups so domain users still
    resolve. `timedatectl`, `update-crypto-policies --show` and
    `dnf repolist` were replaced by reading the files they report.
  Results of the non-live tiers are carried forward (`Info.MergeConfig`,
  `MergeHeavy`, `MergeSTIG`) so nothing disappears from the UI in between.
- systemd is queried once per script, not once per unit: each `systemctl show`
  is a D-Bus round trip (10-40 ms CPU, up to 800 ms wall for `timedatectl`
  while `timedated` activates). The old per-unit loop was also wrong on
  systemd 252, which ignores `-p` order.
- The etcd probe reads `/health` and `/metrics` from `--listen-metrics-urls`
  (plain HTTP on 127.0.0.1:2381 on rke2/k3s) before the TLS client port: no
  TLS handshake for etcd per refresh, and on etcd 3.6 the client port hands
  curl's HTTP/2 request to gRPC and answers 415, so it is also the one that
  works. The etcd container log (tens of MB) is only scanned for leader
  elections when the member is unhealthy or on a full cycle; the config
  sources/dumps, snapshot listings and backup hints run on full cycles; and
  the three `crictl exec etcdctl` calls are skipped while the API-side
  `kubectl exec` probe answered last cycle (they are the fallback for when
  the API is down). `Probe.Merge` carries every skipped section forward.
- A node whose previous probe is still running is **skipped**, never given a
  second session. A node whose probe took longer than half the refresh
  interval skips the next cycle (`ssh.backoff`), so a struggling host gets
  half the rate instead of a queue of sessions. Both show up in `P` and the
  perf log as `skipped`.

**On the API server**

- Lists use `resourceVersion=0` (`perf.watch_cache`): the apiserver answers
  from its watch cache instead of doing a quorum read against etcd for each
  of the ~25 lists. A dashboard does not need linearizable reads; etcd under
  investigation does not need 50 extra range requests a minute.
- Typed lists are requested as protobuf (`perf.protobuf`): 3-4x fewer bytes
  and far cheaper for the apiserver to encode than JSON. Raw endpoints
  (`/readyz`, `metrics.k8s.io`, kubelet proxy) stay JSON.
- Discovery + CRD definitions (each carries its full OpenAPI schema; MBs on a
  Rancher cluster) are cached for `perf.discovery_ttl` (5 min). Kubelet
  `configz` per node for `perf.configz_ttl` (10 min). Helm release payloads
  (every revision, gzipped+base64 in secrets) are re-read only when the
  metadata-only secret/configmap list shows an `owner=helm` object changed.
- Calls the token is refused (403) - and list calls for API types that are
  not installed (404: rke2 snapshot CRs on kubeadm, metrics-server absent,
  Rancher objects) - are remembered and not sent again for
  `perf.denied_ttl` (10 min) or until `R`. The cached error is still
  reported every cycle, so the RBAC findings stay visible; `P` lists what is
  being skipped. `nodes/proxy` and `pods/exec` are one rule for every node
  and every etcd pod, so one refusal stops all of them.
- Client-side rate limit stays at QPS 50 / burst 100 so a big cluster's
  first snapshot cannot flood the apiserver.

**On this host**

- The STIG + checks evaluation over all nodes used to run once per node
  message (O(nodes²) per cycle); node/etcd/helm/S3 messages now mark the state
  dirty and one recompute runs 250 ms later.

## Offline / airgapped environments

Everything the tool does is local to the operator's machine, the API server
and the nodes, except four things:

- **Helm update check** (operator machine -> chart repos / Artifact Hub): a
  2 s TCP reachability probe first, then helm's own cached `index.yaml` as
  the fallback, and unreachable hosts are not retried for 10 minutes.
  `helm.check_updates: false` / `--helm-updates=false` turns it off.
- **Preflight registry probe** (node -> each endpoint in `registries.yaml`,
  `curl`, 6 s cap, config cycles only): explicit mirror endpoints and
  `configs` keys are what you configured and are probed - on an airgapped
  node an unreachable internal Harbor is a real finding. A mirror that names
  a registry without endpoints (`mirrors: docker.io: {}`) would make the
  node contact the upstream registry itself; when the node has image
  tarballs in `agent/images` (airgap install) those are **not probed at
  all** - no egress attempt to trip a firewall alert, no "unreachable"
  finding - and appear as `skip` in the node's preflight table.
- **Registry pull dry run** (node -> the same registries, through
  containerd, heavy cycles only): `crictl pull` by digest of an image the
  node already holds, one per registry `registries.yaml` names, in
  parallel with a 20 s cap. Every blob is local, so containerd only
  resolves the manifest (one HEAD per endpoint) through the `hosts.toml`
  it rendered: ~1 s wall and 0.03 s CPU per registry, nothing downloaded,
  `crictl images` unchanged, four info lines in containerd's log. The same
  airgap rule applies to endpoint-less mirrors. containerd tries the next
  host on any error and falls through to the upstream registry after the
  mirrors - that is its behaviour on any pull - so a pass proves the chain,
  a failure names the host that failed, and the curl probe is what checks
  each endpoint on its own.
- **etcd S3 snapshot check** (node -> the S3 endpoint you configured).

No DNS, package repository, vendor site or telemetry is contacted.

## Where the remaining cost is: one SSH session per probe

Every probe is its own SSH session on the cached connection: channel open,
sshd's PAM session (faillock, lastlog, `pam_systemd` registering a logind
session, audit records), `sudo`, `/bin/sh`. Measured with the same
`x/crypto/ssh` code path the tool uses, running a trivial script:

| node | new session per script | persistent shell, script on stdin |
|---|---|---|
| rke2 / Rocky 9 | 46 ms | 7 ms |
| rke2 CIS profile / RHEL 9 STIG, FIPS, fapolicyd | 134 ms | 13 ms |
| kubeadm / Ubuntu 24.04 STIG | 84 ms | 5 ms |

A control-plane node gets two sessions per refresh (node + etcd probe), so
on a hardened node ~250 ms of the ~1 s light cycle is session setup, and
each session leaves a `session opened`/`closed` pair in `/var/log/secure`
and the audit log (about 200 lines per hour of watching). A persistent
root shell per node (one session for the life of the connection, scripts
written to its stdin with an end marker, respawned on timeout) would
remove both; it is the next structural change, not done yet.

fork+exec itself is 2.7x slower on the FIPS + fapolicyd node (2.1 ms vs
0.8 ms per process): the light probe's ~40 processes cost 0.1 s there
before they do anything, which is why the scripts avoid per-item loops
that spawn (`systemctl show` once for all units, one `ls` of the `.wants`
directories, awk instead of `stat` per file).

## Reading the numbers when troubleshooting

- `remote CPU / refresh` is the steady-state share of one core the tool takes
  on a node. 0.5 s per 30 s is 1.7 %. If a node shows several seconds per
  cycle, look at which probe: `node+heavy` and the `stig:*` scan stages are expected to be
  large but rare; `node` should be well under a second.
- `wall` much larger than `remote CPU` means the node is waiting, not
  computing: D-Bus (`systemctl`/`timedatectl`), a slow disk under `du`, or the
  SSH path. That is the case where backoff kicks in. A healthy node answers
  the light probe in ~200 ms, of which ~70 ms is the SSH channel + sudo and
  the rest ~40 small processes (`df`, `stat`, `grep`); going lower would mean
  rewriting the script as one awk program for a few tens of ms.
- API `bytes in` grows with pods and events. If a cluster has tens of
  thousands of events, `events` is the list to watch; the tool lists all
  types because normal events are needed for context.
- The Resources sub-tab (Inspect) counts instances of every API type with one
  list per type while it is open; on a cluster with hundreds of CRDs that is
  hundreds of cheap requests per refresh. Leave the tab when not needed.

## Knobs

```yaml
refresh: 30s        # everything scales with this
heavy_every: 6      # config + heavy tiers every N refreshes
ssh:
  nice: true        # renice/ionice the probes (--no-nice)
  backoff: true     # skip cycles for slow / still-running nodes (--no-backoff)
  nodes: [cp-1]     # limit SSH to the nodes being looked at
  concurrency: 8    # parallel sessions (also caps parallel load on a bastion)
perf:
  watch_cache: true # --no-watch-cache for a quorum read (only if you suspect the watch cache itself)
  protobuf: true    # --no-protobuf
  discovery_ttl: 5m
  configz_ttl: 10m
  denied_ttl: 10m   # refused / non-existent API calls are not retried for this long (R retries)
  log: ""           # --perf-log
  pprof: ""         # --pprof
```

`--no-ssh` / `s` turn the node side off entirely (API only). `R` is the
expensive key: it re-runs the OS STIG facts, the config tier and the heavy
tier on every node at once.
