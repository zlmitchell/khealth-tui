# gatherlab: a local lab for `--gather` and `--analyze`

A one-node k3s cluster with staged incidents, plus a Debian sshd container that stands in for the node over SSH.
k3s in Docker has neither sshd nor journald. With the lab you can exercise the whole bundle path on a laptop:
the API dump, the node stream over real SSH, the offline replay and the root-cause rules. It does not replace
the lab-cluster checks in [GATHER-VALIDATION.md](../../GATHER-VALIDATION.md): SELinux, fapolicyd, rke2's own
logs, real etcd and multi-node behaviour only show up there.

| Service | What it is |
|---|---|
| `k3s` | k3s v1.33 as node `lab-node`, API on `127.0.0.1:16443`. It applies `manifests/shop.yaml` (healthy workloads, a crash loop, a Secret and a literal credential env value) and `manifests/incidents.yaml` (unreachable registry, OOMKill, unschedulable request, failing liveness probe, Pod Security rejection). |
| `node` | sshd on `127.0.0.1:2222`, mapped to `lab-node` through `ssh.hosts`. At start it generates a throwaway key pair in `out/` and plants the logs of an etcd slow-disk incident (`node/plant.sh`): slow fsyncs, then leader elections, then the scheduler losing its lease, then kubelet node-lease failures. |
| `check` | Profile `test`. It builds khealth from this checkout, waits `LAB_SETTLE` seconds (default 120) for the incidents to play out, gathers, analyzes, and asserts the expected root causes plus no leaked secrets. |

## Run the check

```sh
docker compose -f test/gatherlab/compose.yaml up -d --build
docker compose -f test/gatherlab/compose.yaml --profile test run --rm check   # ends with gatherlab: PASS / FAIL
docker compose -f test/gatherlab/compose.yaml down -v
```

The bundle, the analysis and the full timeline stay in `test/gatherlab/out/` (git-ignored).

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
```

To test a new rule, stage its incident in `manifests/incidents.yaml`, or in `node/plant.sh` for node-side logs. Then add the line the rule should print to `check.sh`.
