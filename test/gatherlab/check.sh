#!/bin/sh
# End-to-end check of --gather and --analyze against the lab (run by the
# compose "check" service from the repository root): build khealth, wait
# for the incidents to play out, gather over the API and SSH, analyze the
# bundle offline, and assert the root causes and that no secret leaked.
# Outputs land in test/gatherlab/out/ (bundle, analysis, timeline);
# LAB_DISTRO=kubeadm (compose.kubeadm.yaml) checks the kubeadm lab, whose
# outputs land in out/kubeadm/.
set -e
L=test/gatherlab
LAB_DISTRO=${LAB_DISTRO:-k3s}
case $LAB_DISTRO in
  k3s)     OUT=$L/out;         API=https://k3s:16443;    HOSTAPI='https://127.0.0.1:16443'; NODE=k3s ;;
  kubeadm) OUT=$L/out/kubeadm; API=https://kubeadm:6443; HOSTAPI='https://127.0.0.1:26443'; NODE=kubeadm ;;
  rke2)    OUT=$L/out/rke2;    API=https://rke2:6443;    HOSTAPI='https://127.0.0.1:36443'; NODE=rke2 ;;
  *) echo "LAB_DISTRO: k3s, kubeadm or rke2, not $LAB_DISTRO"; exit 2 ;;
esac
fail=0

echo "building khealth ..."
go build -o /tmp/khealth ./cmd/khealth

# the kubeconfig the lab wrote points at 127.0.0.1 (for the host); from
# here the server is the lab's service
sed "s#$HOSTAPI#$API#" $OUT/kubeconfig.yaml > /tmp/kubeconfig.yaml
cat > /tmp/khealth.yaml <<EOF
ssh:
  user: root
  key: $OUT/id_lab
  strict_host_key: false
  hosts:
    lab-node: "$NODE:22"
helm:
  check_updates: false
EOF

# restarts, the OOMKill and the probe kills need the pods to have run a while
echo "letting the incidents play out for ${LAB_SETTLE}s ..."
sleep "$LAB_SETTLE"

/tmp/khealth --config /tmp/khealth.yaml --kubeconfig /tmp/kubeconfig.yaml --gather $OUT/lab.tar.gz
/tmp/khealth --analyze $OUT/lab.tar.gz --timeline $OUT/timeline.txt > $OUT/analyze.txt
cat $OUT/analyze.txt

expect() {
  if grep -qF -- "$1" $OUT/analyze.txt; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}
echo
echo "=== expected root causes ($LAB_DISTRO)"
reject() {
  if grep -qF -- "$1" $OUT/analyze.txt; then echo "FAIL  another distribution's wording: $1"; grep -nF -- "$1" $OUT/analyze.txt | cut -c1-200; fail=1; else echo "ok    no \"$1\""; fi
}
# the advice names this distribution's paths, not another's
case $LAB_DISTRO in
  k3s)     expect "etcd's data is in /var/lib/rancher/k3s/server/db/etcd"; reject /var/lib/rancher/rke2 ;;
  kubeadm) expect "kubeadm v1."; expect "etcd's data is in /var/lib/etcd"; reject rke2; reject /var/lib/rancher ;;
  rke2)    expect "+rke2r"; expect "etcd's data is in /var/lib/rancher/rke2/server/db/etcd"; reject /var/lib/rancher/k3s ;;
esac
expect "etcd disk latency on lab-node"
if [ "$LAB_DATASTORE" = sqlite ]; then
  expect "no etcd: k3s keeps the cluster state in SQLite (kine) on lab-node"
fi
expect "leader elections from"
expect "lost their leader lease"
expect "kubelets failed to renew their node lease"
expect "Pods rejected by Pod Security admission"
expect "Pods cannot be scheduled"
expect "Insufficient cpu"
expect "Image cannot be pulled: registry.invalid.example/shop/api:1.4.2"
expect "the registry is unreachable from the node"
expect "Containers killed for exceeding their memory limit (OOMKilled)"
expect "memory limit 24Mi"
expect "Liveness probe failing"
expect "last error logged: FATAL: cannot connect to db:5432"
expect "the same as at gather time"

echo "=== incidents in context"
# the noisy neighbour: api evicted, batch/report to blame, the 5xx at Traefik
ev=$(grep -E '^  eviction-[0-9]+ .* shop/deploy/api ' $OUT/analyze.txt | awk '{print $1}' | head -1)
if [ -z "$ev" ]; then
  echo "FAIL  no eviction of shop/api in the incident list (the node never crossed the eviction threshold? see LAB_EVICT_HEADROOM_MI in compose.yaml)"; fail=1
else
  /tmp/khealth --analyze $OUT/lab.tar.gz --incident "$ev" > $OUT/incident-eviction.txt
  sed -n '1,/^Node /p' $OUT/incident-eviction.txt
  expectIn() {
    if grep -qF -- "$2" "$1"; then echo "ok    $2"; else echo "FAIL  $2  (in $(basename $1))"; fail=1; fi
  }
  expectIn $OUT/incident-eviction.txt "low on resource: memory"
  expectIn $OUT/incident-eviction.txt "most likely pushed by batch/report-"
  expectIn $OUT/incident-eviction.txt "the node stopped evicting once it was evicted"
  expectIn $OUT/incident-eviction.txt "Traffic to shop/api via ingress api api.lab/"
  expectIn $OUT/incident-eviction.txt "req"
fi
# the dependency: crashy names db, which crashed first
rs=$(grep -E '^  restart-[0-9]+ .* shop/deploy/crashy/' $OUT/analyze.txt | awk '{print $1}' | head -1)
if [ -n "$rs" ]; then
  /tmp/khealth --analyze $OUT/lab.tar.gz --incident "$rs" > $OUT/incident-restart.txt
  if grep -qF "shop/deploy/db" $OUT/incident-restart.txt; then echo "ok    crashy's restart blames its dependency db"; else echo "FAIL  crashy's restart does not name db"; fail=1; fi
else
  echo "FAIL  no restart incident for shop/crashy"; fail=1
fi

echo "=== secrets"
mkdir -p /tmp/lab && tar -xzf $OUT/lab.tar.gz -C /tmp/lab
for s in hunter2-should-never-leak literal-secret-should-be-masked aHVudGVyMi1zaG91bGQ "BEGIN OPENSSH PRIVATE KEY" client-key-data; do
  if grep -rlF -- "$s" /tmp/lab >/dev/null; then echo "FAIL  leaked: $s"; grep -rlF -- "$s" /tmp/lab; fail=1; else echo "ok    not in the bundle: $s"; fi
done

echo
if [ $fail = 0 ]; then echo "gatherlab: PASS"; else echo "gatherlab: FAIL"; fi
exit $fail
