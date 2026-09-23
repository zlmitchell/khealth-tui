# khealth-tui

![etcd tab: triage of a stopped rke2-server and a stale member](docs/media/etcd-troubelshooting.png)

A terminal dashboard of **health checks that k9s/kubectl don't give you**, for upstream Kubernetes (kubeadm/kubespray) and **RKE2**/k3s clusters. It is not a resource browser - it answers "is this cluster actually healthy, and why not?"

Two sources, one screen:

- **kubeconfig** - nodes, workloads, events, storage, `/readyz`, control-plane flags, kubelet `configz`, Helm release secrets, rke2 `HelmChart`/`ETCDSnapshotFile`, Rancher agents
- **SSH to the nodes** (optional, recommended) - live CPU/memory/disks/inodes, systemd units, NTP, certificate expiry, sysctls and file modes, `registries.yaml` vs what containerd applied, images and airgap tarballs, journal logs, and on the servers the full etcd picture

## Why

- I run rke2 and kubeadm on STIG/FIPS hosts, often airgapped, often under Rancher; when they break the question is "why is that etcd member stale", not "which pod is red"
- checking a cluster used to mean ten tools - an API sanitizer, `kube-bench` and `oscap` per node, `etcdctl`, the log collector, the Longhorn CLI, InSpec, my own SSH loops - each used rarely enough to re-learn every time
- nothing on the market reads the kubeconfig and the nodes over SSH in one view, triages etcd, or knows the rke2/Rancher layer and the STIGs together
- it is client-side on purpose: an etcd restore happens while the apiserver is down, which is exactly when anything running inside the cluster is gone
- one binary for every cluster I can reach: `C` switches between every context in the kubeconfig and every cluster bootstrapped over SSH, so the daily rounds across a fleet are one keypress apart, and nothing has to be installed per cluster
- the survey of what exists and the gaps: [docs/WHY.md](docs/WHY.md)

## Preview

The screenshot above is the etcd tab's **Triage** block on a three-server RKE2 cluster with one server down and one stale member, each with the numbered steps for that case ([docs/ETCD.md](docs/ETCD.md)).

Walkthrough on an RKE2 cluster ([mp4](docs/media/video-preview-rke2.mp4), 8 MB):

https://github.com/user-attachments/assets/6ea280d7-9e2b-486a-ae72-420db5b0ba56

Walkthrough on a kubeadm cluster ([mp4](docs/media/video-preview-kubeadm.mp4), 5 MB):

https://github.com/user-attachments/assets/ec4e8438-a6a4-43bc-9202-92bfdc07e1b2

## Tabs

- `1` **Overview** - API `readyz`/`livez`, cluster summary, ranked findings CRIT/WARN/INFO
- `2` **Nodes** - conditions, version skew, live CPU/mem/load, disks, unit state; Enter: mounts, certs, sysctls, kubelet args
- `3` **Inspect** - controllers / pods / every API type incl. CRDs; object inspector that drills through owner, children, secrets, PVCs; `L` tails logs
- `4` **etcd** - members, leader, health, db size, latency, alarms, config source, snapshots; **Triage** cases; `X` = rescue (rejoin a server / restore a snapshot); `D` = defrag all members one at a time
- `5` **Storage** - StorageClasses, CSI drivers, PVC used capacity, backend health (Longhorn, Trident, Ceph); Enter: full claim/volume detail
- `6` **Events** - warning events, newest first
- `7` **Addons** - CNI + MTU + node-side network probes, CoreDNS/ingress/metrics-server, Rancher agents, `registries.yaml` vs containerd, upgrade plans, provisioned clusters
- `8` **Helm** - releases from `sh.helm.release.v1` secrets, values, history, update check; `u` upgrade (helm, or your HelmChart CR's `spec.version`), `b` rollback, `B` roll a failed release back to the last deployed revision
- `9` **Images** - per node: images, what is not running, dangling (untagged) images, airgap tarballs vs what is running
- `0` **Security** - opt-in scan (`Shift+S`): Kubernetes / RKE2 / Rancher MCM STIG, CIS, node hardening, full OS STIG per node
- `=` **RKE2** - control-plane isolation, `config.yaml(.d)` per node, manifests, config drift between servers
- `-` **Logs** - rke2/kubelet/containerd journal classified into noise / warnings / errors with explanations

Every column and keypress: [docs/TABS.md](docs/TABS.md).

## Install

- **release binary**: download `khealth-<os>-<arch>` and `checksums.txt` from the latest release, verify, rename to `khealth`

  ```sh
  curl -LO https://github.com/zlmitchell/khealth-tui/releases/latest/download/khealth-linux-amd64
  curl -LO https://github.com/zlmitchell/khealth-tui/releases/latest/download/checksums.txt
  sha256sum --ignore-missing -c checksums.txt && install -m 0755 khealth-linux-amd64 ~/.local/bin/khealth
  ```
- **no Go**: `./build.sh` (Docker) -> `dist/khealth-linux-amd64`; `./build.sh windows amd64`; `./build.sh all` builds every target and writes `dist/checksums.txt`
- **Go 1.26+**: `make build` -> `./khealth`; `make dist` = `build.sh all` with the local toolchain; `make test`
- **shell completion** (optional): `khealth --install-completions` (bash, zsh or fish), or `eval "$(khealth --completions)"` for the current shell. The binary computes the candidates, so flags, `--become` / `--ssh-address` values, kubeconfig contexts and `[user@]host` from `known_hosts` all complete and stay current with the build

## Run

```sh
khealth                                   # current kubeconfig context, SSH as $USER with agent/default keys
khealth --context prod --ssh-user ubuntu --ssh-key ~/.ssh/prod.pem
khealth --no-ssh                          # API-only view
khealth --bastion jump@bastion.example.com --insecure-host-key
khealth root@api.prod.corp --accept-new-host-keys=false  # refuse any node whose key is not already in known_hosts (recording it is the default)
khealth --ssh-user admin --ask-pass       # prompt for a password used when keys fail (and for sudo)
khealth root@10.0.0.11                    # no kubeconfig yet: fetch the admin kubeconfig over SSH from a server node
khealth --export ./reports --export-scan  # no TUI: one cycle + the security scan, JSON + XLSX, exit
```

- **no kubeconfig?** `khealth [user@]server` fetches `rke2.yaml` / `k3s.yaml` / `admin.conf` and rewrites the endpoint to one the apiserver cert is valid for; run with nothing and it lists the clusters it already knows
- **many clusters**: `C` opens a context picker - the kubeconfig's contexts plus every `~/.kube/khealth-*.yaml` bootstrapped earlier; switching drops the cache and starts a fresh first-contact cycle; each bootstrapped context remembers how its nodes were reached (user, key, port, `become`), never a password
- **config file**: `khealth --init-config` writes the annotated example; every key is optional, flags override
- **SSH needs**: a login that can become root (`sudo` / `dzdo` / `doas`, probed), standard tools (`df`, `systemctl`, `journalctl`, `openssl`, `curl`, `sysctl`; `crictl` found automatically), host keys in `known_hosts`
- **RBAC**: read-only list/get; the exact list is in the doc
- **footprint**: light collection every 30 s (~0.2 s per node), heavy tiers only while their tab is open, probes under `renice`/`ionice`; `P` shows what the last cycles cost
- all of the above in detail: [docs/RUNNING.md](docs/RUNNING.md)

## Docs

- [WHY.md](docs/WHY.md) - the tools that exist, what each covers, the gap this fills
- [TABS.md](docs/TABS.md) - every tab, column and key binding
- [RUNNING.md](docs/RUNNING.md) - kubeconfig bootstrap, config file, cluster menu, SSH auth and `become`, RBAC, collection tiers
- [ETCD.md](docs/ETCD.md) - triage cases, the rescue overview, S3 snapshots, how etcd is discovered per layout
- [RESCUE.md](docs/RESCUE.md) - every step, command and check of `X`: rejoin one server, restore a snapshot; what was learned on real clusters
- [SECURITY.md](docs/SECURITY.md) - STIG / CIS releases applied, scores, running the OS STIG scan
- [STIG.md](docs/STIG.md) - where the rules come from, how the OS tables are generated, adding rules
- [SUPPORT.md](docs/SUPPORT.md) - support matrix: what was run against a real cluster vs built from schemas
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - the update loop, tab-driven collection, repository layout
- [PERFORMANCE.md](docs/PERFORMANCE.md) - measured footprint, what keeps it small, knobs
- [REFRESH.md](docs/REFRESH.md) - refresh tiers and tuning
- [FAPOLICYD.md](docs/FAPOLICYD.md) - running the probes on fapolicyd-hardened hosts
- [ROADMAP.md](docs/ROADMAP.md) - done, partly done, open

## Releases

- versions are semantic and cut by CI from [conventional commits](https://www.conventionalcommits.org) on `main`: `fix:` -> patch, `feat:` -> minor, `feat!:` / `BREAKING CHANGE:` -> major; `chore:`/`docs:`/`ci:` release nothing
- each release: tag `vX.Y.Z`, `CHANGELOG.md` entry, and the five binaries plus `checksums.txt` (sha256) attached; the version is embedded (`khealth --version`)
- CI on every push and PR: gitleaks over the commits, `gofmt`, `go vet`, `go mod tidy` check, `go test -race`, `govulncheck`, cross-build of all targets; Renovate keeps Go modules, the Go toolchain and the actions current (weekly, grouped)

## Support

- **tested** on rke2 v1.34-v1.35 (single node and 3-server, `profile: cis`, RHEL 9 STIG/FIPS, Rancher v2.13, Longhorn) and kubeadm v1.35 (3-node stacked etcd, Ubuntu 24.04 STIG)
- **supported** (code paths and unit tests, no live cluster yet): k3s, Rancher-provisioned clusters, Trident, Rook-Ceph, cloud CSIs and CPIs, RHEL 8/10, Ubuntu 22.04
- full matrix: [docs/SUPPORT.md](docs/SUPPORT.md)

## Yes, I used Claude

- something that has to move as fast as everything does now... needs my attention to detail and a way to implement as fast as Claude does; that is how this was built
- every probe, rule and rescue step was run against the lab clusters in the [support matrix](docs/SUPPORT.md) before it was called tested
- if that is a problem for you: read the code, open an issue, or send a pull request with your additions or concerns
