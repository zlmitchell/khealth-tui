# Running khealth: kubeconfig bootstrap, configuration, SSH, RBAC

```sh
khealth                                   # current kubeconfig context, SSH as $USER with agent/default keys
khealth --context prod --ssh-user ubuntu --ssh-key ~/.ssh/prod.pem
khealth --no-ssh                          # API-only view
khealth --bastion jump@bastion.example.com --insecure-host-key
khealth --helm-updates=false              # skip the chart update check (on by default from your `helm repo` list and helm.repos)
khealth --ssh-user admin --ask-pass       # prompt for a password used when keys fail (and for sudo)
khealth root@10.0.0.11                   # no kubeconfig yet: fetch the admin kubeconfig over SSH from a server node (below)
khealth --export ./reports --export-scan  # no TUI: one collection cycle + the security scan, JSON + XLSX written, exit
```


### No kubeconfig, but SSH to the nodes

`khealth [user@]server-node` (or `--bootstrap-kubeconfig <server>[,<server>...]`) fetches the admin kubeconfig (`rke2.yaml` / `k3s.yaml` / `admin.conf`) from the first reachable server node and rewrites `server: https://127.0.0.1:6443` to an endpoint the apiserver certificate is actually valid for. Candidates come from the serving certificate's SANs, ranked from the operator's side: a DNS name that resolves to a VIP / load-balancer address first, then a bare VIP, then the node's own name or address, and the SSH host as a last resort (with a warning and the `tls-san:` line to add). Each candidate is verified against `/version` before it is written. The cluster, user and context are named after the cluster (`--bootstrap-name`, else the first label of the endpoint's DNS name, else the node hostname without its index) instead of rke2's `default`, so several bootstrapped files merge cleanly for context switching. The file goes to `~/.kube/khealth-<name>.yaml` (`--bootstrap-out` to change; an existing file is kept as `.bak`) and the TUI starts with it. When the configured kubeconfig does not load and `ssh.hosts` lists nodes, khealth offers the same thing interactively. `tls-san` entries in `config.yaml` that the certificate does not carry yet are reported: rke2/k3s only reissue the certificate on restart. The same works for upstream kubeadm clusters (`admin.conf`, `pki/apiserver.crt`, `apiServer.certSANs` in `kubeadm-config`; `kubeadm certs renew apiserver` reissues) and for k3s (`k3s.yaml`, `systemctl restart k3s`).

The RKE2 tab (labeled **Config** on non-rke2/k3s clusters) shows the same comparison live: the kubeconfig server (VIP vs single node), each control-plane node's configured SANs (`tls-san`, or kubeadm `certSANs` + `controlPlaneEndpoint`) against its serving certificate, and whether the kubeconfig host is in the certificate; mismatches are also Overview findings.

`khealth --init-config` writes the annotated example config to `~/.config/khealth/config.yaml` (`%AppData%/khealth/config.yaml` on Windows; `--config <path>` to put it elsewhere; it never overwrites) and `--print-config` prints it to stdout. `./khealth.yaml` in the working directory is also picked up (the pre-1.0 `k8s-health-tui` names are still read). Every key is optional; flags override the file. The source of the example is `internal/config/config.example.yaml`.

Run `khealth` with nothing else and it lists the clusters it knows (the kubeconfig in use plus every `~/.kube/khealth-*.yaml`) as a numbered menu, with `n` to bootstrap another from `[user@]host`. Each bootstrapped context remembers how its nodes were reached - `ssh-user`, `ssh-key`, `ssh-port`, `become` and the bootstrap host, stored as a `khealth` extension on the context, never a password - and both the menu and `C` re-apply it, so a cluster reached as `root` and one reached as `ubuntu` need no flags. Flags typed on the command line still win; picking a file that predates this remembers the current `--ssh-user` in it.

`C` inside the app opens a context picker: the contexts of the kubeconfig in use plus every `~/.kube/khealth-*.yaml`, so each cluster bootstrapped once is one keypress away; switching drops all cached results and starts a fresh first-contact cycle.

A file bootstrapped earlier is reused while it still connects: matched by server host before any SSH, or by the cluster CA once the admin kubeconfig is fetched. A stale one (endpoint no longer answers) is replaced in place with a `.bak`; `--bootstrap-fresh` skips the reuse.

Started with no usable kubeconfig and no host, khealth asks instead of failing: on a cluster node it offers the local `rke2.yaml` / `k3s.yaml` / `admin.conf` (copied through `sudo` into `~/.kube/khealth-local.yaml` when it is root-only); otherwise it asks for a server node (`[user@]host`, password prompt when there is no key or agent) and bootstraps from it. `--ssh-address` is the node address *type* (InternalIP / ExternalIP / Hostname) used for nodes listed by the API, not a host.

## What SSH needs on the nodes

* a login that can become root: root itself, or a user with `sudo`, `dzdo` (Centrify / Delinea) or `doas`. Each host is probed once (`become: auto` tries them in that order) and the first that works is cached: NOPASSWD is used when granted; otherwise the password is fed on stdin for `sudo` and `dzdo` (`doas` has no such mode and needs `nopass`). Pin a tool with `become: dzdo` / `--become dzdo`. The collection script is POSIX `sh` sent over stdin, no files are written on the node
* standard tools: `df`, `stat`, `systemctl`, `journalctl`, `openssl`, `curl` (etcd health/metrics), `sysctl`; `crictl` is found automatically (`/var/lib/rancher/rke2/bin/crictl` on rke2), `zstd` only to read `.tar.zst` manifests
* host keys must be in `~/.ssh/known_hosts` unless `strict_host_key: false`
* auth order: ssh-agent (incl. Windows OpenSSH agent) -> key file(s) -> password fallback. The password comes from `--ask-pass` (prompted, not echoed), `KHT_SSH_PASSWORD`, `ssh.password` in the config or `--ssh-password`; it is also used for keyboard-interactive auth and, unless `ssh.become_password` / `KHT_BECOME_PASSWORD` is set, for `sudo -S` / `dzdo -S` when NOPASSWD is not granted. Encrypted keys: `KHT_SSH_PASSPHRASE`.

Light collection runs every refresh (default 30s, ~0.2s wall / 0.2s CPU per node, parallel). The expensive tiers follow the visible tab ([ARCHITECTURE.md](ARCHITECTURE.md) §7): the journal is collected while the Logs tab is open (and hourly in the background for the log findings), the image inventories and registry pull dry run while Images or Addons is open, the `du` of hostPath PVs while Storage is open, the config tier (certificates, sysctls, file modes, rke2/k3s config, manifests, registries, slow hardening commands) on first contact and while RKE2 or Security is open - each refreshed every `heavy_every` refreshes while its tab stays open, fired at once when the tab is opened with stale facts, carried forward in between, and always shown with its age. `R` runs every tier on every node; `collect.always` pins tiers to every tab. Tarball manifests are cached by path/size/mtime so large `.tar.zst` files are only read once. The Security tab is opt-in: the STIG/CIS rules are not evaluated and the OS STIG facts (`sysctl -a`, package lists, `find` scans, config dumps) are not collected until you press `Shift+S` there; later cycles reuse the facts until the next `Shift+S`. [REFRESH.md](REFRESH.md) lists every remote call and its cadence; [ARCHITECTURE.md](ARCHITECTURE.md) describes the update loop, the tick, what a screen costs and the tab-driven collection (§7).

The tool is meant to be run against clusters that are already in trouble, so it measures and minimizes its own footprint: probes run under `renice`/`ionice`, API lists come from the apiserver watch cache in protobuf (no etcd quorum reads), a node whose probe is slow or still running is skipped rather than stacked, and `P` shows what the last cycles cost the API server, every node (remote CPU seconds per probe) and this host. `--perf-log file.jsonl` records it per cycle and `tools/perfbench` measures it headlessly with baseline-vs-during CPU sampling on the nodes. See [PERFORMANCE.md](PERFORMANCE.md).

## RBAC needed (read-only)

list/get on nodes, pods, namespaces, events, persistentvolumes(-claims), storageclasses, csidrivers, csinodes, deployments, daemonsets, statefulsets, jobs, cronjobs, clusterrolebindings, networkpolicies, secrets (Helm releases + rke2 S3 config), configmaps, `etcdsnapshotfiles.k3s.cattle.io`, `helmcharts/helmchartconfigs.helm.cattle.io`, `nodes/proxy` (kubelet configz), `/readyz` `/livez` (`nonResourceURLs`), `metrics.k8s.io`. Missing permissions degrade gracefully and show up as findings.
