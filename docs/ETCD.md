# etcd: triage, rescue, snapshots and discovery

The etcd tab (`4`) is where khealth differs most from a resource browser: it reads the members from the etcd static pod, then from the nodes' disks when the API is gone, classifies every unhealthy member into a case with numbered steps, and can drive the repair. The step-by-step of the repair itself is in [RESCUE.md](RESCUE.md).

## etcd triage

When a member is unhealthy the etcd tab and the Overview findings carry a **Triage** block: one entry per problem member, classified by correlating the member list / endpoint health with the node's Ready condition, SSH reachability, `rke2-server`/`k3s`/`kubelet` service state, the etcd static pod's container status and the classified journal (cluster-id mismatch, NOSPACE, disk full, missing etcd user, expired certs, port in use, clock skew). Each entry states the quorum situation (healthy/needed, leader, term) and numbered steps for that case. Nothing is executed; mutating commands (`member remove`, `defrag`, `alarm disarm`, `--cluster-reset`) are printed.

When quorum is lost (power outage, all members down) the probe also reads what is on disk on each node: the etcd container log (`/var/log/pods/kube-system_etcd-*/etcd/*.log`, journal for k3s/systemd etcd) for `elected leader ... at term N` lines and the node's own `local-member-id`, plus `member/snap/<term>-<index>.snap` and the newest WAL file. Nodes are ranked by the highest term at which they were leader, then snapshot term/index and WAL activity, and the cluster finding names the node to run `--cluster-reset` on. If the apiserver itself is unreachable the SSH collection keeps going against the last node list it saw (or `ssh.hosts`) and runs the etcd probe on every host. When the kubeconfig's server does not answer at all, khealth tries the apiserver of the other control-plane nodes it knows (peers found on disk by the etcd probes, healthy members first; the last node list; `ssh.hosts`) with the same kubeconfig CA and credentials, and switches to the first that answers (`api ... (failover)` in the header). Dials time out after 5 s so a dead host does not stall the cycle. `khealth user@server-node` still starts when the API server is down: the bootstrap writes a kubeconfig pointing at that node with a note, the TUI comes up offline and the node is the SSH target.

## etcd rescue (restore a snapshot)

Every step, command and check is listed in [RESCUE.md](RESCUE.md). Live-tested on three-server rke2 (RHEL 9 STIG, `profile: cis`) and three-node kubeadm (Ubuntu 24.04 STIG) control planes: restore from any server, rejoin of a broken server (details and what was learned in the *Tested* section of that document).

`X` on the etcd tab repairs the control plane over SSH (needs SSH collection on, `actions.enabled`, and an rke2, k3s or kubeadm control plane). It first asks which situation you are in, and recommends one from what it sees:

- **quorum is fine, one member is broken** -> *rejoin one server*: that server is stopped, its etcd data moved aside (kept), its stale member entry removed from the surviving cluster and it rejoins through the healthy leader (rke2/k3s: temporary `server:` + token drop-in; kubeadm: learner add, manifest patch, promote). Nothing else is touched, nothing written since is lost. Takes about half a minute.
- **quorum is lost or the data is bad** -> *restore a snapshot*, below.

With the apiserver down khealth still knows the whole control plane: the etcd probe reads the cluster's members from the reachable node's disk (the `members` bucket of `member/snap/db`, the `initial-cluster` of the generated config or the static pod manifest) and from the etcd log which member id led at which term, and probes every peer over its peer address. The picker shows each node's member name/id, the live leader or the *last leader* (highest election term in any log), on-disk raft position and snapshots.

The restore walks through:

1. **node**: the etcd nodes with state, role, the last election term their log saw and their snapshots; the best restore source is preselected (an online healthy leader, then the freshest raft state);
2. **restore point**: that node's snapshot files, newest first (S3 records too on rke2/k3s when `etcd-s3-*` is inline in `config.yaml`; a config secret cannot be read while the apiserver is down);
3. **preflight** (read-only) on every server: binary, data dir owner/mode and size, free space, mount point, `reset-flag`, `server:`/`cluster-init`, kubeadm manifest (`--name`, peer URL, image), restore tools, the snapshot itself. An unreachable follower is left out with a warning;
4. **confirmation**: the plan, the warnings and a typed `restore`;
5. the steps, live, with an etcd member/health/leader check after every node. `esc` hides the view (the rescue continues), `x` aborts after the step in progress.

What it does, per the projects' documented procedures:

| | rke2 / k3s | kubeadm |
|---|---|---|
| stop | `systemctl stop rke2-server`/`k3s` on every server, followers first; the etcd process the unit leaves behind (it kills containerd, not the containers) is stopped too, so no stale member serves the old membership during the reset | park `etcd.yaml` and `kube-apiserver.yaml` out of `/etc/kubernetes/manifests` |
| keep | every node's `server/db/etcd` moved to `server/etcd-rescue-<time>/` (never deleted by khealth) | `/var/lib/etcd` moved to `/var/lib/etcd-rescue-<time>/` |
| restore | `rke2 server --cluster-reset --cluster-reset-restore-path=<snapshot> --etcd-s3=false` on the target (plus `--server=` when its config has a join URL, which rke2 otherwise refuses), as a transient systemd unit (`systemd-run`), polled until it prints *membership has been reset*; then verified on disk (old dir renamed to `etcd-old-<time>`, `member/snap/db` + WAL rewritten after the reset, the reset log says *restored snapshot*) - if not, the dir is moved aside and the restore runs once more | `etcdutl snapshot restore` as a one-member cluster: host `etcdutl`/`etcdctl`, else the pod's etcd image through `ctr`/`podman` |
| perms | previous owner re-applied (`etcd:etcd` under `profile: cis`), `0700`, `restorecon -RF` on SELinux hosts | same |
| start | `systemctl start`; wait for etcd, then `/readyz`. If the member list still shows the old peers, or no leader appears within 5 minutes, the known rke2 fix runs by itself: stop, a plain second `cluster-reset`, start, wait again. Then the CNI agent pod on the node is restarted: calico-node resyncs against the apiserver while it is still coming up and drops the routes to the pods already running there ("no route to host" from every pod on the node until it is restarted) | etcd manifest back; wait; apiserver manifest back; controller-manager, scheduler and kubelet restarted |
| rejoin | one follower at a time: start with a temporary drop-in (`server:` pointing at the target, plus the cluster token from `server/token` when the config has none - the `cluster-init` node never had one there and would otherwise found a new cluster; removed once it is a member), wait until it is a healthy voting member | `member add --learner`, patch its manifest (`--initial-cluster`, `state=existing`), start, promote once synced, apiserver back |
| after | verify (all members healthy, one leader, no alarms, apiserver up), fresh snapshot | same |

Running the restore as a transient systemd unit matters on SELinux hosts: a command started from an SSH session is `unconfined_u`, every file it writes carries that user, and the confined etcd container is denied its own data dir - rke2's cluster-reset then waits 15 minutes for an etcd that never comes up.

## etcd S3 snapshots

For rke2/k3s the tool works out the effective S3 destination of every server: `etcd-s3-*` keys from `config.yaml`(.d) (credential values are reported as `<set>`, never read) merged with the `etcd-s3-config-secret` when one is named (its values win). It then reports: S3 enabled on some servers but not others, servers uploading to different endpoint/bucket/folder, missing bucket or credentials, `skip-ssl-verify`, the secret not existing, the newest S3-uploaded snapshot record being older than `etcd.max_backup_age`, records whose upload failed, `s3-upload-fail` journal lines, and whether each server can actually reach the endpoint: a `curl` from the node using the node's own CA / TLS settings (any HTTP status counts as reachable; DNS, connect and certificate errors are shown verbatim). No credentials are used for that check. The etcd tab shows one row per server.

## How etcd is discovered

| Layout | Detection | Certs | etcdctl | Snapshots |
|--------|-----------|-------|---------|-----------|
| rke2 | `/var/lib/rancher/rke2/server/tls/etcd` | `server-ca.crt`, `server-client.crt/key` | `crictl exec` into the `etcd` container | `/var/lib/rancher/rke2/server/db/snapshots`, `ETCDSnapshotFile` CRs, `rke2-etcd-snapshots` ConfigMap, `etcd-s3-config-secret` |
| k3s | `/var/lib/rancher/k3s/server/tls/etcd` | same | curl only (embedded) | `/var/lib/rancher/k3s/server/db/snapshots` |
| kubeadm | `/etc/kubernetes/pki/etcd` | `ca.crt`, `healthcheck-client.*` or `apiserver-etcd-client.*` | `crictl exec` (containerd/cri-o) or host `etcdctl` | where the node's own backup job writes (below), `etcd.backup_dirs`, common dirs, CronJobs named *etcd* |
| kubespray/systemd | `/etc/ssl/etcd/ssl/ca.pem` | `admin-<host>.pem` | host `etcdctl` | same |

**Finding a kubeadm cluster's backups.** kubeadm schedules none, so the snapshots are wherever the operator's own job puts them - which khealth cannot guess, and guessing wrong meant the restore had nothing to offer. On a full cycle the probe resolves each etcd-ish systemd timer to its service and reads `ExecStart`, `Environment` and the `EnvironmentFile`, and reads the matching lines out of `/etc/cron.d`, `/etc/cron.*`, `/etc/crontab` and `/var/spool/cron`; when the command is a wrapper script, the first 8 KB of it are read too. The destination is taken from `etcdctl|etcdutl snapshot save <path>`, from `BACKUP_DIR` / `SNAPSHOT_DIR` / `SNAP_DIR` / `DEST_DIR`, and from a shell default of the form `${BACKUP_DIR:-/var/lib/etcd-backup}` - the usual way a wrapper states it. Those directories are scanned in the same run, so the files are listed, aged against `etcd.max_backup_age` and offered by the rescue (`X`). Only paths are taken from an `EnvironmentFile`: those hold S3 credentials and are never printed. The job itself is shown under "other backup mechanisms" with the command and the directory it writes to. `etcd.backup_dirs` still adds anything this cannot infer, and the rescue's `p` takes a path by hand.

Config sources listed on the etcd tab: rke2 `config.yaml`(.d) `etcd-*` keys, the rke2-generated `/var/lib/rancher/rke2/server/db/etcd/config`, static pod manifests (`pod-manifests/etcd.yaml`, `/etc/kubernetes/manifests/etcd.yaml`), `/etc/etcd/*`, `/etc/default/etcd`, `systemctl cat etcd`, and the `--etcd-servers` the apiserver points to (external etcd). Override endpoint and cert paths in `etcd:` when your layout differs.
