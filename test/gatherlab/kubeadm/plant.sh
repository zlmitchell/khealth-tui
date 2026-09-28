#!/bin/sh
# Plant the log lines of an etcd disk incident, a few seconds apart and in
# causal order: slow fsyncs, then leader elections, then the scheduler and
# controller-manager losing their leases, then the kubelet failing to renew
# its node lease. On kubeadm and rke2 the control plane runs as static
# pods, so each line goes where it would really be: appended (CRI format)
# to the etcd, kube-scheduler and kube-controller-manager logs under
# /var/log/pods, and the kubelet's to the journal. (rke2's kubelet logs to
# agent/logs/kubelet.log, but its writer does not append: a line added
# there is overwritten within seconds. The journal's warnings.log carries
# them on both.) The rca etcd rule must tie them into one chain. The rke2
# lab copies this file (compose.rke2.yaml builds from gatherlab/).
set -e
podlog() { ls -t /var/log/pods/kube-system_"$1"-lab-node_*/"$1"/*.log 2>/dev/null | head -1; }
for c in etcd kube-scheduler kube-controller-manager; do
  until [ -n "$(podlog $c)" ]; do sleep 2; done
done
cri() { printf '%s stderr F %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$2" >> "$(podlog "$1")"; sleep 2; }
klog() { printf 'E%s %s       1 %s' "$(date -u +%m%d)" "$(date -u +%H:%M:%S.%6N)" "$1"; }
ts() { date -u +%Y-%m-%dT%H:%M:%S.%6NZ; }

for i in 1 2 3 4 5; do
  cri etcd '{"level":"warn","ts":"'"$(ts)"'","caller":"wal/wal.go:805","msg":"slow fdatasync","took":"1.8s","expected-duration":"1s"}'
done
for i in 1 2 3; do
  cri etcd '{"level":"info","ts":"'"$(ts)"'","msg":"raft.node: 8e9e05c52164694d changed leader from 8e9e05c52164694d to 91bc3c398fb3c146 at term 7"}'
done
cri kube-scheduler "$(klog 'leaderelection.go:340] "Failed to update lock" err="failed to renew lease kube-system/kube-scheduler: timed out waiting for the condition"')"
cri kube-controller-manager "$(klog 'leaderelection.go:340] "Failed to update lock" err="failed to renew lease kube-system/kube-controller-manager: timed out waiting for the condition"')"
for i in 1 2 3; do
  klog 'controller.go:195] "Failed to update lease" err="Put https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/lab-node: context deadline exceeded"' |
    systemd-cat -t kubelet -p err
  sleep 2
done
