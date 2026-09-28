# gatherlab: a local lab for `--gather`, `--analyze` and the TUI

A one-node k3s cluster with staged incidents. The node is a systemd container, built the way kind builds its node image: k3s runs as a real unit, with sshd beside it. So khealth reaches the same node over the API and over SSH, and sees what it sees on a server:

- journald
- `k3s crictl` and the image store
- `/var/log/pods`
- embedded etcd

It does not replace the lab-cluster checks in [GATHER-VALIDATION.md](../../GATHER-VALIDATION.md): SELinux, fapolicyd, rke2's own layout and multi-node behaviour only show up there.

| Piece | What it is |
|---|---|
| `k3s` service | k3s v1.33 as node `lab-node`. The API is on `127.0.0.1:16443` and SSH on `127.0.0.1:2222` (root, with the throwaway key `out/id_lab` that the node generates at boot). The datastore is embedded etcd (`--cluster-init`); `LAB_DATASTORE=sqlite` runs k3s on SQLite through kine instead (no etcd). Traefik logs every request (`manifests/k3s-ingress.yaml`). |
| `manifests/shop.yaml` | Healthy workloads, a `db` that crashes, and a `crashy` whose last log line names `db`. Also a Secret and a literal credential env value that must never reach a bundle. |
| `manifests/incidents.yaml` | An unreachable registry, an OOMKill, an unschedulable request, a failing liveness probe, and a Pod Security rejection. |
| `manifests/noisy.yaml` | **The noisy neighbour.** An `api` behind an Ingress, with a traffic generator, runs a little over its memory request at default priority. A high-priority `batch/report` Job takes 4 GiB a minute in. The kubelet evicts `api`, then `report`, whose eviction ends the episode. The kubelet's threshold is set `LAB_EVICT_HEADROOM_MI` (default 3584) below the VM's memory; the node has its own cgroup namespace, so other containers on the Docker VM do not count. **Docker needs a VM of 8 GiB or more**. |
| `k3s/plant.sh` | Writes the journal lines of an etcd slow-disk incident, in causal order: slow fsyncs, leader elections, the scheduler losing its lease, then kubelet node-lease failures. |
| `check` service | Profile `test`. It builds khealth from this checkout and waits `LAB_SETTLE` seconds (default 180) for the incidents to play out. Then it gathers, analyzes, and asserts the expected root causes. It opens two incidents: the `api` eviction must name `batch/report`, with the failed requests at the ingress controller, and `crashy`'s restart must blame `db`. It also checks that no secret leaked. |

## Run the check

```sh
docker compose -f test/gatherlab/compose.yaml up -d --build
docker compose -f test/gatherlab/compose.yaml --profile test run --rm check   # ends with gatherlab: PASS / FAIL
docker compose -f test/gatherlab/compose.yaml down -v
```

The bundle, the analysis and the full timeline stay in `test/gatherlab/out/` (git-ignored).

## The same lab on kubeadm and rke2

Two more compose files run the same incidents and the same `check.sh` on other distributions, so the gather and the analysis are tested against each layout. Only one small file per lab differs (`manifests/<distro>-ingress.yaml`): it points the traffic generator's `edge` Service at that distribution's ingress controller.

- **`compose.kubeadm.yaml`**: the upstream layout. The node is kind's node image (`kindest/node`, which kind and Cluster API's Docker provider boot) with sshd and a `kubeadm init` unit added (`kubeadm/`).
- **`compose.rke2.yaml`**: `rke2-server` from the release tarball as a systemd unit, as the k3s lab runs k3s (`rke2/`).

| | k3s (`compose.yaml`) | kubeadm (`compose.kubeadm.yaml`) | rke2 (`compose.rke2.yaml`) |
|---|---|---|---|
| Node | one `k3s` unit | `kubelet` and `containerd` units | one `rke2-server` unit with its own containerd; the kubelet logs to `agent/logs/kubelet.log` |
| Control plane, etcd | in the k3s process; data in `/var/lib/rancher/k3s/server/db` | static pods in `/etc/kubernetes/manifests`; data in `/var/lib/etcd` | static pods in `agent/pod-manifests`; data in `/var/lib/rancher/rke2/server/db` |
| Ingress | Traefik, access log turned on | ingress-nginx, installed by `kubeadm/lab-kubeadm.sh` | the bundled `rke2-ingress-nginx`, given a ClusterIP Service |
| Planted etcd incident | `k3s/plant.sh`: the journal, as `k3s` | `kubeadm/plant.sh`: appended to the etcd, scheduler and controller-manager pod logs in `/var/log/pods`; node-lease failures to the journal as `kubelet` | the same script (rke2 overwrites lines appended to `kubelet.log`, so the node-lease failures go to the journal here too) |
| API, SSH, output | `127.0.0.1:16443`, `:2222`, `out/` | `127.0.0.1:26443`, `:2223`, `out/kubeadm/` | `127.0.0.1:36443`, `:2224`, `out/rke2/` |

```sh
docker compose -f test/gatherlab/compose.kubeadm.yaml up -d --build          # or compose.rke2.yaml
docker compose -f test/gatherlab/compose.kubeadm.yaml --profile test run --rm check
docker compose -f test/gatherlab/compose.kubeadm.yaml down -v
```

`check.sh` also asserts that the analysis gives the lab's own etcd data directory, and that it names no other distribution's paths.

The labs' ports and output directories don't clash, but each noisy neighbour needs 4 GiB, so run one at a time on an 8 to 12 GiB Docker VM. rke2 itself uses about 1 GiB more than k3s, so its lab defaults `LAB_EVICT_HEADROOM_MI` to 4608. To poke at a lab by hand, use the config below with that lab's output directory, SSH port and API port.

## Poke at it by hand

```sh
docker compose -f test/gatherlab/compose.yaml up -d --build
cat > /tmp/lab.yaml <<'EOF'
ssh:
  user: root
  key: test/gatherlab/out/id_lab
  strict_host_key: false
  hosts: {lab-node: "127.0.0.1:2222"}
helm: {check_updates: false}
EOF
khealth --config /tmp/lab.yaml --kubeconfig test/gatherlab/out/kubeconfig.yaml                       # the TUI
khealth --config /tmp/lab.yaml --kubeconfig test/gatherlab/out/kubeconfig.yaml --gather /tmp/b.tar.gz
khealth --analyze /tmp/b.tar.gz --timeline /tmp/timeline.txt
khealth --analyze /tmp/b.tar.gz --tui                                                                 # the bundle in the TUI
```

To render every view of chosen incidents as text (the UX review loop), from the repository root in the golang container:

```sh
KHT_BUNDLE=$PWD/test/gatherlab/out/lab.tar.gz KHT_DUMP=$PWD/test/gatherlab/out/views.txt KHT_INCIDENTS=eviction-2,restart-2   go test -run TestDumpOfflineBundle ./internal/ui
```

To test a new rule, stage its incident in `manifests/incidents.yaml`, or in `k3s/plant.sh` for node-side logs. Then add the line the rule should print to `check.sh`.
