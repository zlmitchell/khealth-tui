# etcd rescue: what `X` on the etcd tab does, step by step

khealth can repair an rke2 / k3s / kubeadm control plane over SSH. This document lists every step it takes, the command behind it, what it checks before moving on, and what it leaves behind. The code is `internal/rescue` (plan and step engine) and `internal/rescue/scripts/*.sh` (what runs on the nodes, POSIX sh as root).

## Two modes

`X` first asks which situation you are in and recommends one from what the probes see:

| | Rejoin one server | Restore a snapshot |
|---|---|---|
| when | quorum is fine, one member is broken (service down, data corrupt, node reinstalled) | quorum is lost, or the data itself is bad |
| touches | that one server | every server |
| data | nothing is lost; the node syncs from the leader | the cluster returns to the snapshot; everything written since is gone |
| takes | ~30 s | 3-5 minutes for three servers |
| recommended when | a live leader is seen and a reachable node is not serving etcd | otherwise |

Requirements for both: SSH collection on (`s`), `actions.enabled` (not `--read-only`), the etcd probes of the servers, and an rke2, k3s or kubeadm control plane (external / kubespray etcd is refused with a pointer to the triage steps).

## What khealth knows when the apiserver is down

The picker works without the API. The etcd probe reads, on every reachable server, even with etcd stopped:

- the cluster's members from the `members` bucket of `member/snap/db` (name, id, peer URL; freed pages may still hold members removed since, so entries are keyed by peer address) and the `initial-cluster` line of the rke2-generated `db/etcd/config` or the kubeadm manifest;
- which member id was elected leader at which term, from the etcd log (`/var/log/pods/kube-system_etcd-*/etcd/*.log`, journal for k3s);
- the on-disk raft position (`member/snap/<term>-<index>.snap`, newest WAL) and the snapshot files.

Peers found this way become SSH targets on their peer address, so one reachable server is enough to learn and probe the whole control plane; `X` probes any node that has no probe yet and the picker updates as they answer. When the kubeconfig's apiserver is down but another server's is up, khealth switches to that one (same CA and credentials; `api ... (failover)` in the header) and every tab fills again. When `khealth user@server` is started with 6443 down, the bootstrap writes a kubeconfig pointing at that server anyway and the TUI comes up offline.

The picker shows per node: SSH reachability, etcd health, `leader` (live) or `last leader` (highest election term in any log), member name/id, leader term, raft index, snapshots on the node.

## The UI flow

1. mode (rejoin / restore), with the recommendation;
2. node: the server to rejoin, or the server to restore *from* (best source preselected: online healthy leader, then the highest election term, then raft index, then newest snapshot); unreachable nodes cannot be chosen;
3. restore only: the restore point on that node, newest first (local files the probe saw; S3 records on rke2/k3s only when the `etcd-s3-*` settings are inline in `config.yaml` - a config secret cannot be read while the apiserver is down);
4. preflight, read-only, on every server involved (below);
5. confirmation: the plan, every warning, and the word `restore` typed (the text scrolls with the arrows / PgUp / PgDn / Home / End, the input stays at the bottom);
6. the steps, live. The view follows the running step until you scroll (`j/k`, PgUp/PgDn, `g/G`; `f` follows again). `esc` hides the view (the rescue keeps running, `X` shows it again), `x` aborts after the step in progress, `q` refuses to quit while it runs (`ctrl+c` still does, cutting the step off).

A failing step stops everything: it is marked with the error and its last output lines, the remaining steps are skipped, and the notes say where every node's data is. Nothing retries silently except the two documented rke2 cases below. khealth never deletes etcd data: everything moved aside stays in the rescue directory.

## Preflight (`preflight.sh`, read-only)

On each server: `systemctl` present; data dir owner, mode, size, whether it holds member data, whether it is a mount point (refused for rke2/k3s, the cluster-reset cannot rename a mount point); free space; the rescue directory it will use (`<data-dir>/../etcd-rescue-<stamp>`, or inside a mount point); running etcd container. rke2/k3s: the binary, `reset-flag` absent (a previous cluster-reset never followed by a normal start), the config's `server:`, `cluster-init`, `profile`, `etcd-s3` keys, the `etcd` user. kubeadm: the etcd manifest's `--name`, `--initial-advertise-peer-urls`, image and `--initial-cluster`, a kube-apiserver manifest, `crictl` and a CRI socket, which of `etcdutl` / `etcdctl` / `ctr` / `podman` exist, and the API endpoint `admin.conf` uses (the `controlPlaneEndpoint`): when it is not the target itself the confirmation warns which follower or external address it is, since kubectl, kube-proxy and the CNI pods on the target depend on it. The restore target also checks the snapshot file exists and is readable. Rejoin also runs `status.sh` on the healthy member and refuses when it does not see quorum and a leader.

A follower that fails preflight or SSH is left out with a warning: it is neither stopped nor rejoined, and the final notes say what to do with it.

## Restore, rke2 / k3s

Servers: T = the restore source, F1..Fn = the others, in name order.

| # | node | step | what runs | checked |
|---|---|---|---|---|
| 1 | F1..Fn | Stop rke2-server | `stop.sh`: `systemctl stop rke2-server`; the etcd container the unit leaves behind (rke2 kills containerd, not the containers) is terminated like `rke2-killall.sh` does | unit not active; nothing listening on 2379/2380 (warning otherwise) |
| 2 | T | Stop rke2-server | same | same |
| 3 | T, F1..Fn | Move etcd data | `backup.sh`: `mv server/db/etcd <rescue>/etcd`, an empty `db/etcd` with the same owner/mode left behind (the cluster-reset renames it and fails when it is missing) | owner/mode recorded |
| 4 | T | Restore + cluster-reset, verify the data dir was replaced | `reset_rke2.sh`: `rke2 server --cluster-reset --cluster-reset-restore-path=<snapshot> --etcd-s3=false` (`--etcd-s3` for an S3 object; `--server=` added when the config has a join URL, which rke2 otherwise refuses), as a transient systemd unit, log and exit file in the rescue dir, polled | success only when the log says *membership has been reset* (rke2 exits 0 even after giving up). Then `verify_restore.sh`: `etcd-old-<time>` created by the reset, `member/snap/db` and `member/wal` written after it, *restored snapshot* in the log. If not: `wipe_again.sh` moves the dir aside (`<rescue>/etcd-attemptN`) and the restore runs once more; a second failure stops the rescue |
| 5 | T | Set data dir owner/mode | `perms.sh`: previous owner re-applied (`etcd:etcd` under `profile: cis`), `chmod 700`, `go-rwx` underneath, `restorecon -RF` on SELinux hosts | |
| 6 | T | Start rke2-server | `start.sh`: `systemctl start --no-block` | |
| 7 | T | Wait for etcd and the apiserver | `status.sh` polled: `/health`, member list, endpoint health, endpoint status, alarms, `/readyz` | exactly one member, healthy, leader, no alarms, apiserver answering. **Second cluster-reset** when the member list still holds other members or no leader appears within 5 min: stop, plain `--cluster-reset` (`reset-flag` cleared on purpose), perms, start, wait again |
| 8 | T | Restart the CNI agent | `cni_restart.sh`: the canal / calico-node / cilium / flannel pod on the node deleted, waited for | calico-node resyncs against the apiserver while it is still coming up and drops the routes to the pods already on the node |
| 9 | Fi | Rejoin: start rke2-server | `start.sh` with a drop-in `config.yaml.d/99-khealth-rescue.yaml`: `server: https://<T>:9345` (every follower joins through T - its own `server:` may name a server that is still stopped, or be absent on the `cluster-init` node, which would then found a new cluster) plus `token:` from `server/token` when the config has none (the first server never had one there) | |
| 10 | T | Wait until Fi is a healthy member | `status.sh` polled on T | member count = i+1, a member with Fi's peer address, no learner, all healthy, one leader, no alarms |
| 11 | Fi | Remove the join drop-in | `join_cleanup.sh` | the node's config is what it was |
| 12 | T | Check etcd status | `status.sh` | as 10 |
| | | steps 9-12 repeat for every follower | | |
| 13 | T | Verify the cluster | `status.sh` | all members healthy, one leader, apiserver up |
| 14 | T | Take a fresh snapshot | `rke2 etcd-snapshot save --name rescue-<stamp>` | |

## Restore, kubeadm

| # | node | step | what runs | checked |
|---|---|---|---|---|
| 1-2 | F1..Fn, T | Stop | `stop.sh`: `etcd.yaml`, `kube-apiserver.yaml`, `kube-controller-manager.yaml` and `kube-scheduler.yaml` moved out of `/etc/kubernetes/manifests` to `/etc/kubernetes/*.yaml.off`, containers waited for / stopped (the controllers too: left running on a follower they would reconnect to the restored apiserver with caches and watches from resource versions newer than the restored data) | no etcd, apiserver or controller container |
| 3 | all | Move etcd data | `backup.sh`: `mv /var/lib/etcd <rescue>/etcd` (contents only when it is a mount point) | |
| 4 | T | Restore as a one-member cluster | `restore_kubeadm.sh`: `etcdutl snapshot restore <snapshot> --data-dir /var/lib/etcd --name <name> --initial-cluster <name>=<peer> --initial-advertise-peer-urls <peer>` - host `etcdutl`, else `etcdctl`, else the pod's etcd image through `ctr -n k8s.io run` (containerd) or `podman run` with the data dir's parent and the snapshot's directory bind-mounted; under `systemd-run --wait` | `member/snap` and `member/wal` present |
| 5 | T | Set data dir owner/mode | `perms.sh` | |
| 6 | T | Start etcd | `start.sh`: `etcd.yaml` back into the manifests dir | |
| 7 | T | Wait for etcd | `status.sh` | one member, healthy, leader |
| 8 | T | Start kube-apiserver, restart controllers and kubelet | `unpark_api.sh`: `kube-apiserver.yaml`, `kube-controller-manager.yaml` and `kube-scheduler.yaml` back (a controller manifest that was never parked has its container stopped instead, kubelet recreates it); `systemctl restart kubelet` - none may keep working from resource versions newer than the restored data | `/readyz` |
| 9 | T | Register Fi as a learner member | `member_add.sh`: a stale member with Fi's name or peer URL removed, `etcdctl member add <name> --peer-urls=<peer> --learner`; the printed `ETCD_INITIAL_CLUSTER` kept | |
| 10 | Fi | Patch the etcd manifest | `patch_manifest.sh`: `--initial-cluster=<that list>`, `--initial-cluster-state=existing` in the parked manifest (copy kept in the rescue dir) | |
| 11 | Fi | Start etcd | `start.sh` | |
| 12 | T | Wait until Fi has synced and is promoted | `status.sh` polled with promotion: `etcdctl member promote` retried every poll until etcd accepts it | member count = i+1, no learner, all healthy, one leader |
| 13 | Fi | Start kube-apiserver, restart controllers and kubelet | `unpark_api.sh` | `/readyz` on Fi |
| 14 | T | Check etcd status | `status.sh` | |
| | | steps 9-14 repeat for every follower | | |
| 15 | T | Restart the CNI agent | `cni_restart.sh`, only now: a fresh CNI pod reaches the API through the service VIP, which kube-proxy on T still maps to every apiserver it last saw - kube-proxy itself follows the kubeconfig's `controlPlaneEndpoint`, which may be a follower (this cluster: 224) and is down until that follower is back. `kubectl` with `admin.conf`, falling back to T's own apiserver `https://<T ip>:6443` when the endpoint does not answer; the endpoint is probed (`/readyz`) before the pod is deleted and the pod is left alone (with a note) when it does not answer - a restart then would strand the node without CNI | |
| 16 | T | Verify the cluster | `status.sh` | |
| 17 | T | Take a fresh snapshot | `etcdctl snapshot save` into the directory the restored snapshot came from (through the etcd container's etcdctl when the host has none, via the data dir) | |

## Rejoin one server

N = the broken server, A = the healthy member it joins through (the live leader when there is one).

| # | node | step | what runs | checked |
|---|---|---|---|---|
| 1 | N | Stop | `stop.sh` | |
| 2 | N | Move etcd data | `backup.sh` | |
| 3 | A | Remove the stale member entry for N (rke2/k3s) | `member_remove.sh`: `etcdctl member remove` of every member whose peer URL is the address N is *recorded* at (`initial-advertise-peer-urls` in its etcd config on disk, else its node address) - rke2 refuses a join while a member of that name exists ("duplicate node name found") | |
| 3b | N | Rewrite node-ip (only when config.yaml pins an address N no longer holds) | `fix_node_ip.sh`: `node-ip: <old>` becomes N's current address in place, a `.khealth-<stamp>` copy is kept; a Rancher-delivered `50-rancher.yaml` is rewritten too, with a note that the next plan puts it back | |
| 4.. | | the rejoin steps of the restore (rke2/k3s 9-12, kubeadm 9-14) with A as T; the "healthy member" wait looks for N at its current address | | member count back to what A saw before |
| last | A | Verify the cluster | `status.sh` | all healthy, one leader, apiserver up |

**A server that changed address** (DHCP, re-IP): the cluster still lists its member at the old address, `config.yaml` may pin `node-ip:` to it (every listener rke2 renders binds to node-ip, so etcd dies with `bind: cannot assign requested address` and the kubelet keeps reporting the old InternalIP), and the other servers' `server:` may still point there. The preflight reads the addresses the node holds, the pinned `node-ip`, the recorded peer URL and every server's `server:`, and the confirmation says which of these is stale and what the rejoin does about it: the recorded entry is the one removed (step 3), `node-ip` is rewritten (3b), and a `server:` pointing at the old address is called out - rke2 restarts from its saved server list while that lasts, but point `server:` at a VIP or the new address afterwards. The Overview shows the same as findings (`config.yaml pins node-ip ...`, `server: ... points at the old address of ...`) without a rescue. khealth dials the node at the address the node object carries, which is the old one; three ways to tell it where the node is: `khealth root@<new address>` (the bootstrap notices the address belongs to that node and remembers it in the kubeconfig's context hint), Enter on the unreachable row in the rescue picker (asks for the address and probes it at once), or `ssh.hosts: {<node>: <address>}` in the config. Keeping the member's data instead (`etcdctl member update <id> --peer-urls=https://<new>:2380` on a healthy member, fix `node-ip`, restart) is the lighter route when the data is intact; the rejoin is the one khealth automates.

## `server:` is never rewritten

The target resets with `--server=` overridden on the command line; every follower joins through the temporary drop-in (`config.yaml.d/99-khealth-rescue.yaml`, `server: <target>` + token), removed once it is a member. Each server's own `server:` stays as it was, and the confirmation says where each one will join from at its next restart: another server by name (fine while that server answers at startup - rke2 also keeps its last known server list under `agent/etc`), a VIP / DNS name (what rke2 recommends), or an address no server holds any more (warned). Changing `server:` is a configuration decision (pointing every server at the rescue target would only move the single point of failure), so khealth reports it and leaves the file to the operator.

## What is left behind

- `<data-dir>/../etcd-rescue-<stamp>/etcd` on every node touched: the etcd data as it was. Never deleted by khealth; the notes say so. rke2 also keeps `db/etcd-old-<time>` from its own restore.
- `cluster-reset.log` / `cluster-reset-2.log` and the exit files in the rescue dir; `etcd.yaml.before-rescue` on patched kubeadm followers.
- The join drop-in is removed once the node is a member; a failed run may leave it (the notes list it).
- kubeadm followers' manifests keep the patched `--initial-cluster`; etcd only reads it with an empty data dir.
- Worker kubelets are not restarted (`systemctl restart kubelet` there if pods look stale).

## Behaviors learned on real clusters (all handled)

- SELinux: a restore started from an SSH session writes `unconfined_u` files the confined etcd container is denied; rke2 waits 15 min and exits
  0. Hence `systemd-run`, `restorecon`, and success judged on the log line.
- `rke2 server --cluster-reset` refuses to run while `server:` is set; `--server=` on the command line overrides the file.
- A node joining through `server:` needs `token:` in its config; the first server never had one there.
- The combined restore + reset has been seen not to replace the data dir, and to come up with the old peers still listed: verified on disk, second attempt / second reset.
- The etcd container outlives `systemctl stop rke2-server`.
- calico-node on the restored node drops the local pod routes while the apiserver comes up ("no route to host" from every pod there).
- With a member down, `etcdctl endpoint health/status --cluster -w json` prints the JSON array and then `Error: unhealthy cluster` on the same stream; the parser trims to the array.
- rke2 refuses a rejoin while the stale member of the same name exists.
- A server that changed address keeps `node-ip:` pinned to the old one (every rke2 listener binds to it) and stays registered at it; the node object's InternalIP follows the kubelet, so it stays old too. Nothing in the API says where the node went - only the node itself does. Once `node-ip` is right, rke2 re-issues the etcd server/peer and apiserver serving certificates on start with the new address added to the SANs (the old one stays), so the rejoined member's TLS works without a certificate rotate.

## Tested

- rke2 v1.35.8, RHEL 9.6 STIG (SELinux enforcing, fapolicyd, `profile: cis`): single node; three servers restoring from each of the three (cluster-init node and joined nodes), rejoin of a stopped cluster-init node through a follower; rejoin of the cluster-init node after its address changed (10.0.0.143 -> .191 with `node-ip` pinned: etcd in a bind crash loop, member still registered at the old address, the other servers' `server:` pointing at it) - reached through `khealth root@<new address>`, stale member removed, `node-ip` rewritten, back as a fresh member at the new address in one run.
- kubeadm v1.35.8, Ubuntu 24.04 STIG (etcd 3.6.6, canal, no host etcdutl: restore through `ctr` and the pod's etcd image): single node; three stacked control-plane nodes with `controlPlaneEndpoint` set to the init node's address, restoring from the endpoint node (184 s) and from a follower (104 s), and a rejoin of a node whose etcd data was removed under the running static pod (41 s). Found and fixed on those runs: the CNI restart on a target that is not the endpoint node stranded it (Calico's installer dies on the first refused connection through the service VIP, which kube-proxy - pinned to the stopped endpoint - still maps to every apiserver), hence the step's new position and endpoint check; kubelet recreates a moved-aside `/var/lib/etcd` as 0755 before etcd starts (`start.sh` creates it 0700 first); the followers' controller-manager and scheduler are parked with the apiserver instead of being left running against the restored data.
- Every scenario proven by objects created after the snapshot being gone (restore) or still present (rejoin), all nodes Ready, all pods Running.
