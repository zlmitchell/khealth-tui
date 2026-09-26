#!/bin/sh
# End-to-end check of --gather and --analyze against the lab (run by the
# compose "check" service from the repository root): build khealth, wait
# for the incidents to play out, gather over the API and SSH, analyze the
# bundle offline, and assert the root causes and that no secret leaked.
# Outputs land in test/gatherlab/out/ (bundle, analysis, timeline).
set -e
L=test/gatherlab
OUT=$L/out
fail=0

echo "building khealth ..."
go build -o /tmp/khealth ./cmd/khealth

# the kubeconfig k3s wrote points at 127.0.0.1 (for the host); from here
# the server is the k3s service
sed 's#https://127.0.0.1:16443#https://k3s:16443#' $OUT/kubeconfig.yaml > /tmp/kubeconfig.yaml
cat > /tmp/khealth.yaml <<EOF
ssh:
  user: root
  key: $OUT/id_lab
  strict_host_key: false
  hosts:
    lab-node: "node:22"
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
echo "=== expected root causes"
expect "etcd disk latency on lab-node"
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

echo "=== secrets"
mkdir -p /tmp/lab && tar -xzf $OUT/lab.tar.gz -C /tmp/lab
for s in hunter2-should-never-leak literal-secret-should-be-masked aHVudGVyMi1zaG91bGQ "BEGIN OPENSSH PRIVATE KEY" client-key-data; do
  if grep -rlF -- "$s" /tmp/lab >/dev/null; then echo "FAIL  leaked: $s"; grep -rlF -- "$s" /tmp/lab; fail=1; else echo "ok    not in the bundle: $s"; fi
done

echo
if [ $fail = 0 ]; then echo "gatherlab: PASS"; else echo "gatherlab: FAIL"; fi
exit $fail
