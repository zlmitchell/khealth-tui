# `--gather` validation checklist

`--gather` is built and unit-tested, but has only been run against k3s in Docker and a Debian sshd container
(2026-09-26, lab network unreachable). It is **not complete** until every box below is ticked on the lab
clusters. Record the date and bundle name next to each item; anything that fails gets a fix and a re-run.

Build: `./build.sh windows amd64` (or `linux amd64` to run from a node). Keep every bundle until the review at
the end.

## Lab targets

| Cluster | Nodes | How to reach it |
|---|---|---|
| RKE2, RHEL 9.6 STIG/FIPS, SELinux + fapolicyd enforcing | redhat9-test-2 10.0.0.235, redhat9-test-3 10.0.0.223 (servers), redhat9-test 10.0.0.191 (worker) | `~/.kube/redhat9-test.yaml` still points at the old .143: use `multinode-a.yaml` (needs `rancher.zachhq.home` to resolve) or `khealth --bootstrap-kubeconfig root@10.0.0.235` |
| kubeadm v1.35, Ubuntu 24.04 STIG (USG login banner), 3 stacked-etcd CPs | 10.0.0.224, .240, .239 | `~/.kube/khealth-ubuntu-test.yaml` |
| RKE2 single node, Rocky 9 (perf box) | 10.0.0.111 | `~/.kube/rancher.yaml` |

Common flags: `--ssh-user root --ssh-key ~/.ssh/id_rsa`.

## 1. Cluster scope, root SSH (each cluster)

`khealth --kubeconfig <kc> --ssh-user root --ssh-key ~/.ssh/id_rsa --gather ./bundles`

- [ ] RKE2 RHEL  - [ ] kubeadm Ubuntu  - [ ] RKE2 .111
- [ ] Every node reports `ok` in the summary and in `manifest.json` (`probe`, `etcd_probe` on etcd nodes, `logs`).
- [ ] Ubuntu: the USG banner did not break the archive (all nodes `ok`, no "no archive in the node's output").
- [ ] Wall time and bundle size are noted here; no node close to the 15 min stream timeout.
- [ ] `report.json` findings match what the TUI shows for the same cluster at the same time (roughly the same count and areas).

## 2. Node contents (open `nodes/<node>/` on one server and one worker per cluster)

- [ ] RKE2: `journal/rke2-server.log` (servers) / `journal/rke2-agent.log` (worker) cover the window, with ISO timestamps.
- [ ] RKE2: `files/rke2/agent/logs/kubelet.log` and `files/rke2/agent/containerd/containerd.log` are present (the paths follow the data dir).
- [ ] kubeadm: `journal/kubelet.log`, `journal/containerd.log`, `config/kubelet.txt` (config.yaml + kubeadm-flags.env), and `config/static-pods.yaml` from `/etc/kubernetes/manifests`.
- [ ] `pods/kube-system_etcd-*/etcd/*.log` and the kube-apiserver logs are there: at most two runs per container, the lower number being the earlier run.
- [ ] `runtime/ps.json` and `runtime/pods.json` parse as JSON; `runtime/info.json` holds no registry passwords.
- [ ] `config/certs.txt` lists the rke2 `server/tls` or kubeadm `pki` certs with their dates and SANs, and no key material.
- [ ] `network/`: iptables and/or nft ruleset, routes and listening sockets are populated; firewalld zones on RHEL; ufw on Ubuntu.
- [ ] `system/denials.txt` exists on RHEL (ausearch present) and shows the node's real AVC/fanotify history.
- [ ] `journal/previous-boot.log` is present on nodes with persistent journald and more than one boot.
- [ ] `probe/node.txt` and `probe/etcd.txt` end with `===END`.
- [ ] `_gather/node.env` shows `staging=/var/tmp/...` (not tmpfs) and a `used_kb` well under the budget.

## 3. The node is left as it was

On each node, after the gather:

- [ ] No `khealth-gather.*` left in `/var/tmp`, `/tmp`, `/run` or `/dev/shm`.
- [ ] RHEL: no denials caused by the gather itself. Run `ausearch -m AVC,USER_AVC,FANOTIFY -ts <start time>` and check that nothing names tar, gzip, journalctl or crictl. fapolicyd did not block anything.
- [ ] AIDE / auditd: note how many audit records one gather adds (every command execs), so it is known before it runs on a customer's audited nodes.
- [ ] Node CPU and load during the gather stay modest: check `top` on a server while it runs, or `_gather/node.env` `times`. It runs under renice 19 / ionice.
- [ ] Interrupt a gather with Ctrl-C mid-run: the staging dir is removed (the SSH hangup reaches the trap). If it is not removed, confirm the next gather clears it after 2 h and write that down.

## 4. Secrets (the most important section)

Grep each bundle for real secret values taken from the nodes. Nothing may match.

```sh
tar -xzf bundle.tar.gz
grep -rlF "$(ssh root@10.0.0.235 cat /var/lib/rancher/rke2/server/token)" khealth-bundle-*/     # rke2 join token
grep -rlF "$(ssh root@10.0.0.235 cat /var/lib/rancher/rke2/server/node-token)" khealth-bundle-*/
grep -rl 'minioadmin' khealth-bundle-*/                                                 # MinIO creds in lh-test / trident-protect
grep -rl 'BEGIN .*PRIVATE KEY' khealth-bundle-*/
grep -rl 'client-key-data\|client-certificate-data' khealth-bundle-*/                  # any kubeconfig
```

- [ ] RKE2: the join token and the node token are absent.
- [ ] No private key and no kubeconfig anywhere.
- [ ] MinIO / S3 / AppVault credentials (Trident Protect, Longhorn backup target) are absent. Secrets appear as keys with `<value not collected, N chars>`.
- [ ] kubeadm: the secrets encryption key (`/etc/kubernetes/enc*.yaml` or wherever the install put it) is absent.
- [ ] HelmChart `valuesContent` is replaced, and `snapshot.json` has no Helm `ValuesYAML` content.
- [ ] `config/rancher.yaml`: `token:` / `agent-token:` lines are `<masked>` if config.yaml has them.

## 5. Non-root escalation

`--ssh-user "$SSH_AUTH_USER" --become sudo` with `KHT_SSH_PASSWORD` exported (creds in the repo's `.env`):

- [ ] RKE2 RHEL: every node `ok`. The sudo password is fed ahead of the script on the streamed session exactly as for the probes.
- [ ] The password does not appear in the bundle (`grep -rlF "$SSH_AUTH_PASSWORD"`) or in `_gather/stderr.txt`.

## 6. Workload scope

- [ ] `--gather-workload lh-test/deploy/web` (RKE2, Longhorn RWO): logs of all its pods, only namespace `lh-test` in namespaced resource files, and nodes = the pods' nodes plus the control plane.
- [ ] `--gather-workload lh-test/sts/db`, and a CronJob if one exists (Longhorn's `nightly` recurring job runs as a CronJob in `longhorn-system`).
- [ ] A deployment mid-rollout or crash-looping: both ReplicaSets' pods are included, with `.previous.log` for the restarted ones.
- [ ] `--gather-workload lh-test/deploy/nope` fails cleanly, without writing a bundle.

## 7. API down

Do not stop the apiserver. Use a kubeconfig whose server is unreachable, and list the nodes under `ssh.hosts` in a config file:

```yaml
ssh:
  hosts: {redhat9-test-2: 10.0.0.235, redhat9-test-3: 10.0.0.223, redhat9-test: 10.0.0.191}
```

- [ ] The summary says "API server not usable (...)", every host is gathered, and every host got the etcd probe.
- [ ] On-disk pod logs widen to the system namespaces (`pods/kube-system_*`, `cattle-*`, `longhorn-system_*`, ...).
- [ ] Without `ssh.hosts`: the "no node to reach over SSH" hint is printed and the exit is clean.
- [ ] Optional, the real thing: isolate redhat9-test-3 with the nft trick (see memory) and gather from the others. The bundle should show the isolation: etcd leader changes, peer errors in `journal/rke2-server.log` and the etcd pod logs.

## 8. Limits

- [ ] `--gather-node-mb 5`: the gather still succeeds; `manifest.json` lists `skipped` items per node, and the most useful items (system, journals of the k8s units, etcd pod logs) come first.
- [ ] A long window (`--gather-since 168h`) on a chatty node: `truncated` is populated, and each truncated file keeps the newest end.
- [ ] A node with a small `/var/tmp` (or a temporarily filled one): the gather falls back or fails with the "no staging directory" message, and does not stage in tmpfs without enough MemAvailable.

## 9. Regressions from shared changes

- [ ] `base.sh`: crictl detection moved above `sec DATADIR`. Run `perfbench -cycles 5 -monitor` on .111 and compare with docs/PERFORMANCE.md; the Images tab and registry pull dry run still work.
- [ ] `headless.Run`: `--export` still produces the same report, and now honours `--ssh-nodes`. That is a behaviour change: note it in the changelog commit.
- [ ] `sshrun.Run`: the TUI still probes all nodes; the reconnect-after-drop path still works (restart sshd on a node while the TUI runs).

## 10. Before calling it done

- [ ] Unpack a bundle on Windows (tar in PowerShell or 7-Zip) and on Linux; file names are fine on both.
- [ ] Update docs/GATHER.md "Tested / supported" with what was run above, and delete this file.
- [ ] Commit only the gather paths (another agent works in this repo: stage explicit paths). Commit type: `feat: log bundle for root-cause analysis (--gather)`.
- [ ] Open question, decide before closing: add a TUI key (on a selected workload, or cluster-wide) that runs the same gather in the background? It was part of the phase 1 proposal but has not been built.
