# k8s-health-tui (`khealth`)

A terminal dashboard of **health checks that k9s/kubectl don't give you**, for
upstream Kubernetes (kubeadm/kubespray) and **RKE2** clusters. It is not a
resource browser — it answers "is this cluster actually healthy, and why not?"

It uses two sources:

1. **kubeconfig** – nodes, workloads, events, storage, `/readyz`, metrics-server,
   control-plane component flags (mirror pods), kubelet `configz`, Helm release
   secrets, rke2 `HelmChart`/`ETCDSnapshotFile` objects, Rancher agents.
2. **SSH to the nodes** (optional but recommended) – live CPU/memory/load, disks
   and inodes, systemd units, NTP/clock skew, certificate expiry, sysctls and
   file permissions, `registries.yaml` vs what containerd applied, image
   inventory and airgap tarball contents, journal logs, and on control-plane
   nodes the full etcd picture: how it is configured, `/health` + `/metrics`
   with the right client certs, `etcdctl` via `crictl`, snapshots and backup
   mechanisms.

## Tabs

| Key | Tab | What it shows |
|-----|-----|---------------|
| 1 | Overview | cluster summary, API `readyz`/`livez`, Rancher link, ranked findings (CRIT/WARN/INFO) |
| 2 | Nodes | conditions, kubelet version skew, live CPU/mem/load, root + data disk %, kubelet/rke2 unit state, uptime; Enter: mounts, certs, sysctls, kubelet args, requests vs allocatable |
| 3 | Inspect | sub-tabs `Controllers` (Deployments/DaemonSets/StatefulSets/Jobs/CronJobs, then pods not owned by any of them) / `Pods` / `Resources` (every API type from discovery, built-in like Ingress/Service and CRDs, with lazy instance counts; Enter lists instances with phase/conditions) / `Object`; Enter opens the **object inspector** (owner, children, secrets, configmaps, PVCs, service account, node, typed refs in CR specs) and Enter again drills into any reference, esc goes back; `t` = rollout restart (confirmed); `L` = **tail logs** of the selected pod or a controller's pods (stream with follow, `[`/`]` switch container, `{`/`}` switch pod, `p` previous instance, `w` wrap) |
| 4 | etcd | members/health/status via **`kubectl exec` into the etcd static pod** (member list first, then endpoint health/status against every client URL, alarms) with SSH probes (curl + certs, etcdctl via crictl, gRPC gateway) as fallbacks;  members/leader/raft, per-node health, db size vs quota, fragmentation, WAL fsync + backend commit latency, alarms, **config source** (rke2 config.yaml / generated etcd config / static pod / kubeadm manifest / systemd unit), rke2 `etcd-*` settings, S3 secret, cluster snapshot records, local snapshot files, timers/crons/CronJobs |
| 5 | Storage | StorageClasses, CSI drivers (per-node registration), PVCs with **used capacity** (kubelet `stats/summary`), PVs, node filesystems |
| 6 | Events | warning events, newest first |
| 7 | Addons | CNI (daemonsets + `/etc/cni/net.d` + rke2 `cni:`), CSI, CoreDNS/ingress/metrics-server/…, **Rancher management** (server URL, cluster-agent, fleet-agent, provisioned vs imported, `rancher-system-agent` per node, join topology via `server:`), **registries.yaml** vs containerd `certs.d`, registries actually used by pods, rke2 bundled HelmCharts + HelmChartConfig overrides |
| 8 | Helm | releases decoded from `sh.helm.release.v1` secrets (chart, version, status, revision, history); Enter: **values applied** + history; optional update check against repo `index.yaml` / Artifact Hub; `u` upgrades to the newest known version, `b` rolls back to a chosen revision (runs the `helm` CLI after a confirmation, `--read-only` disables) |
| 9 | Images | per node: image count/size, running containers, **unused images**, airgap tarballs (`/var/lib/rancher/rke2/agent/images/*.tar[.zst\|.gz]`, `.txt`) and which tarball images are running / which running images are not in any tarball |
| 0 | Security | sub-tabs `Rules` / `Node hardening`; reference releases shown in the header; **STIG / CIS** rules evaluated from apiserver/controller-manager/scheduler/etcd flags, kubelet configz, PSA labels, RBAC, privileged/host-namespace pods, plus node facts (rke2 `profile: cis`, sysctls, etcd user, file modes/ownership, SELinux, swap); `Node hardening` adds the DISA RHEL 8/9/10 and Ubuntu 20.04/22.04/24.04 STIG rules matched per node |
| = | RKE2 | **control-plane isolation** (taints, user pods on servers, requests vs allocatable, whether apiserver/etcd static pods carry `control-plane-resource-requests`);  `config.yaml`(.d) per node, data-dir, `server/manifests` (user vs bundled, HelmChartConfig contents), static pod manifests, audit/PSS policies, config drift between nodes |
| - | Logs | journal of rke2-server/agent, kubelet, containerd, rancher-system-agent **classified** into normal-startup noise / warnings / errors with explanations (token mismatch, CA mismatch, cluster-id mismatch, NOSPACE, PLEG, pull failures, protect-kernel-defaults, …); persistent startup noise is escalated |

Overview and etcd start with a tile row (gauges + sparklines over the last
refreshes for CPU/memory/disk/etcd db size/fragmentation/fsync, pod and
findings distribution); Nodes/Storage/Images/Security/Logs use bars and
sparklines inline. History is kept in memory for the session (90 samples).

**Node hardening** (per node, over SSH): SELinux runtime vs `/etc/selinux/config`, AppArmor, FIPS (`/proc/sys/crypto/fips_enabled` vs `fips=1` in grub / Ubuntu Pro), fapolicyd, auditd (+ rule count), firewalld/ufw (runtime vs unit-file / `ufw.conf`), Secure Boot, kernel lockdown, crypto policy, pending reboot. Runtime/boot mismatches are findings. The node detail (Enter on Nodes) opens with a dashboard of gauges and this table.

Keys: `Tab`/`Shift+Tab` (or `[`/`]`, number keys) switch tabs, `←`/`→` or `h`/`l` switch sub-tabs inside a tab, `j/k` move, `Enter` detail, `n` namespace,
`/` filter, `a` problems-only, `r` refresh, `R` full refresh (logs/images),
`s` toggle SSH, `?` help, `q` quit.

## Install / build

No Go on the machine? Use Docker:

```sh
./build.sh linux amd64      # -> dist/khealth-linux-amd64
./build.sh windows amd64    # -> dist/khealth-windows-amd64.exe
./build.sh darwin arm64
```

With Go 1.24+: `go build -o khealth ./cmd/khealth` (or `make build`, `make test`).

## Run

```sh
khealth                                   # current kubeconfig context, SSH as $USER with agent/default keys
khealth --context prod --ssh-user ubuntu --ssh-key ~/.ssh/prod.pem
khealth --no-ssh                          # API-only view
khealth --bastion jump@bastion.example.com --insecure-host-key
khealth --helm-updates                    # also look up newer chart versions (your `helm repo` list, then Artifact Hub)
khealth --ssh-user admin --ask-pass       # prompt for a password used when keys fail (and for sudo)
```

Copy `config.example.yaml` to `~/.config/k8s-health-tui/config.yaml` (or
`./k8s-health-tui.yaml`) for persistent settings, per-node address overrides,
thresholds, extra etcd backup directories, Helm repos, etc.

### What SSH needs on the nodes

* a user that can `sudo -n` (or root); the collection script is POSIX `sh` sent
  over stdin, no files are written on the node
* standard tools: `df`, `stat`, `systemctl`, `journalctl`, `openssl`, `curl`
  (etcd health/metrics), `sysctl`; `crictl` is found automatically
  (`/var/lib/rancher/rke2/bin/crictl` on rke2), `zstd` only to read `.tar.zst`
  manifests
* host keys must be in `~/.ssh/known_hosts` unless `strict_host_key: false`
* auth order: ssh-agent (incl. Windows OpenSSH agent) -> key file(s) ->
  password fallback. The password comes from `--ask-pass` (prompted, not
  echoed), `KHT_SSH_PASSWORD`, `ssh.password` in the config or `--ssh-password`;
  it is also used for keyboard-interactive auth and fed to `sudo -S` when the
  node's sudo is not `NOPASSWD`. Encrypted keys: `KHT_SSH_PASSPHRASE`.

Light collection runs every refresh (default 30s, ~2s per node, parallel);
heavy collection (journal, `crictl images`, tarball manifests) runs every
`heavy_every` refreshes or on `R`. Tarball manifests are cached by
path/size/mtime so large `.tar.zst` files are only read once.

### RBAC needed (read-only)

list/get on nodes, pods, namespaces, events, persistentvolumes(-claims),
storageclasses, csidrivers, csinodes, deployments, daemonsets, statefulsets,
jobs, cronjobs, clusterrolebindings, networkpolicies, secrets (Helm releases +
rke2 S3 config), configmaps, `etcdsnapshotfiles.k3s.cattle.io`,
`helmcharts/helmchartconfigs.helm.cattle.io`, `nodes/proxy` (kubelet configz),
`/readyz` `/livez` (`nonResourceURLs`), `metrics.k8s.io`. Missing permissions
degrade gracefully and show up as findings.

## etcd triage

When a member is unhealthy the etcd tab and the Overview findings carry a
**Triage** block: one entry per problem member, classified by correlating the
member list / endpoint health with the node's Ready condition, SSH
reachability, `rke2-server`/`k3s`/`kubelet` service state, the etcd static
pod's container status and the classified journal (cluster-id mismatch,
NOSPACE, disk full, missing etcd user, expired certs, port in use, clock
skew). Each entry states the quorum situation (healthy/needed, leader, term)
and numbered steps for that case. Nothing is executed; mutating commands
(`member remove`, `defrag`, `alarm disarm`, `--cluster-reset`) are printed.

When quorum is lost (power outage, all members down) the probe also reads
what is on disk on each node: the etcd container log
(`/var/log/pods/kube-system_etcd-*/etcd/*.log`, journal for k3s/systemd
etcd) for `elected leader ... at term N` lines and the node's own
`local-member-id`, plus `member/snap/<term>-<index>.snap` and the newest WAL
file. Nodes are ranked by the highest term at which they were leader, then
snapshot term/index and WAL activity, and the cluster finding names the node
to run `--cluster-reset` on. If the apiserver itself is unreachable the SSH
collection keeps going against the last node list it saw (or `ssh.hosts`)
and runs the etcd probe on every host.

## etcd S3 snapshots

For rke2/k3s the tool works out the effective S3 destination of every
server: `etcd-s3-*` keys from `config.yaml`(.d) (credential values are
reported as `<set>`, never read) merged with the `etcd-s3-config-secret` when
one is named (its values win). It then reports: S3 enabled on some servers but
not others, servers uploading to different endpoint/bucket/folder, missing
bucket or credentials, `skip-ssl-verify`, the secret not existing, the newest
S3-uploaded snapshot record being older than `etcd.max_backup_age`, records
whose upload failed, `s3-upload-fail` journal lines, and whether each server
can actually reach the endpoint: a `curl` from the node using the node's own
CA / TLS settings (any HTTP status counts as reachable; DNS, connect and
certificate errors are shown verbatim). No credentials are used for that
check. The etcd tab shows one row per server.

## How etcd is discovered

| Layout | Detection | Certs | etcdctl | Snapshots |
|--------|-----------|-------|---------|-----------|
| rke2 | `/var/lib/rancher/rke2/server/tls/etcd` | `server-ca.crt`, `server-client.crt/key` | `crictl exec` into the `etcd` container | `/var/lib/rancher/rke2/server/db/snapshots`, `ETCDSnapshotFile` CRs, `rke2-etcd-snapshots` ConfigMap, `etcd-s3-config-secret` |
| k3s | `/var/lib/rancher/k3s/server/tls/etcd` | same | curl only (embedded) | `/var/lib/rancher/k3s/server/db/snapshots` |
| kubeadm | `/etc/kubernetes/pki/etcd` | `ca.crt`, `healthcheck-client.*` or `apiserver-etcd-client.*` | `crictl exec` (containerd/cri-o) or host `etcdctl` | `etcd.backup_dirs`, common dirs, systemd timers, crons, CronJobs named *etcd* |
| kubespray/systemd | `/etc/ssl/etcd/ssl/ca.pem` | `admin-<host>.pem` | host `etcdctl` | same |

Config sources listed on the etcd tab: rke2 `config.yaml`(.d) `etcd-*` keys,
the rke2-generated `/var/lib/rancher/rke2/server/db/etcd/config`, static pod
manifests (`pod-manifests/etcd.yaml`, `/etc/kubernetes/manifests/etcd.yaml`),
`/etc/etcd/*`, `/etc/default/etcd`, `systemctl cat etcd`, and the
`--etcd-servers` the apiserver points to (external etcd). Override endpoint and
cert paths in `etcd:` when your layout differs.

## Security / STIG notes

The Security tab automates the checks that can be verified from configuration
and API state. Rule IDs come from the XCCDF of these releases, downloaded from
`https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/` (DISA) and the CIS
benchmark numbering:

| Reference | Release | IDs |
|---|---|---|
| DISA Kubernetes STIG | V2R6 (01 Apr 2026) | `V-2423xx`..`V-2424xx`, `V-2455xx`, `V-2548xx`, `V-2748xx` |
| DISA Rancher Government RKE2 STIG | V2R7 (01 Jul 2026) | `V-2545xx`; `RKE2-*` for hardening-guide prerequisites the STIG does not number |
| DISA Rancher Government MCM STIG | V2R2 (05 Jan 2026) | `V-2528xx`, `V-257292`; only on the cluster that runs Rancher (auth provider, `AUDIT_LEVEL`, new-user default role, single local admin, ingress 443 + NetworkPolicies to 444, `privateCA`/`ingress.tls.source=secret` from helm values) |
| CIS Kubernetes Benchmark | v2.0.1 (Jun 2026) / rke2 self-assessment v1.12 | `CIS-x.y.z` |
| DISA RHEL STIG | 8 V2R8, 9 V2R9, 10 V1R2 (01 Jul 2026) | per node, matched from `/etc/os-release` |
| DISA Ubuntu LTS STIG | 20.04 V2R4, 22.04 V2R9, 24.04 V1R6 | per node, matched from `/etc/os-release` |

RHEL rebuilds (Rocky, Alma, CentOS Stream, Oracle) are audited against the
RHEL STIG of the same major; nodes on other distributions fall back to generic
`OS-*` IDs. The `Node hardening` sub-tab shows the OS STIG matched per node,
a pass/fail summary column, and the per-rule results (FIPS, SELinux/AppArmor,
fapolicyd, auditd, firewall, USBGuard, chrony, and the kernel sysctls the
STIGs require) - enter on a rule row opens its detail and fix.

The mapping is best-effort: verify it against the release you are audited
against and treat `MANUAL` results as items to review. Secrets, tokens and
passwords are masked before any file content leaves the node.

## Layout

```
cmd/khealth            entry point
internal/config        defaults, YAML file, flags
internal/k8s           client-go snapshot, Helm decoding, helpers
internal/sshrun        SSH runner (agent/key/password, bastion, sudo, known_hosts)
internal/nodeinfo      node collection script + parser (resources, perms, registries, images, logs)
internal/etcd          etcd probe script + parser (config source, health, metrics, etcdctl, snapshots)
internal/logs          log pattern knowledge base + classifier
internal/stig          STIG/CIS rule engine (one file per reference: kubernetes, rke2, rancher, cis, os + rhel/ubuntu tables)
internal/helmcheck     chart update lookup (repo index.yaml / Artifact Hub)
internal/checks        findings engine (thresholds -> CRIT/WARN/INFO)
internal/ui            Bubble Tea app, tabs, detail views
```

## Ideas / roadmap

* certificate expiry from the API server endpoint itself (TLS dial), kubelet serving certs via CSR state
* rke2 upgrade readiness: version skew vs supervisor, `system-upgrade-controller` plans, pending Rancher plans on `rancher-system-agent`
* CNI deep checks: pod-to-pod / DNS probes from a debug pod, VXLAN/WireGuard MTU, `NetworkUnavailable` history
* CSI backend health (Longhorn volumes degraded, replica counts) via CRDs
* registry reachability from nodes (`crictl pull` dry run against mirrors), image signature/SBOM presence
* Helm: drift between HelmChartConfig and rendered values, charts pinned to deprecated APIs
* export findings as JSON / Prometheus metrics for alerting
* rke2 `cluster-reset` / restore rehearsal checklist, snapshot restore validation
* node time-series (sparklines) for CPU/mem/etcd latency across refreshes
