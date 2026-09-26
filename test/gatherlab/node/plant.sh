#!/bin/sh
# Plant the logs of an etcd disk incident on the stand-in node, timed
# relative to now: slow fsyncs first, then leader elections, the
# scheduler losing its lease, and the kubelet failing to renew its node
# lease. The rca etcd rule must tie them into one chain. Also an older
# run of the etcd container (0.log), as kubelet keeps it after a restart.
set -e
NODE=$1
ts() { date -u -d "-$1 sec" +%Y-%m-%dT%H:%M:%S.%NZ; }
kl() { date -u -d "-$1 sec" "+%m%d %H:%M:%S.%6N"; }
E=/var/log/pods/kube-system_etcd-${NODE}_1111/etcd
S=/var/log/pods/kube-system_kube-scheduler-${NODE}_2222/kube-scheduler
K=/var/lib/rancher/rke2/agent/logs
mkdir -p "$E" "$S" "$K"
echo "$(ts 7200) stderr F {\"level\":\"info\",\"msg\":\"starting etcd\"}" > "$E/0.log"
: > "$E/1.log"; : > "$S/2.log"; : > "$K/kubelet.log"
for s in 1900 1850 1800 1760 1700 1650 1600; do
  echo "$(ts $s) stderr F {\"level\":\"warn\",\"caller\":\"wal/wal.go:805\",\"msg\":\"slow fdatasync\",\"took\":\"1.8s\",\"expected-duration\":\"1s\"}" >> "$E/1.log"
done
for s in 1720 1640 1580; do
  echo "$(ts $s) stderr F {\"level\":\"info\",\"msg\":\"raft.node: 8e9e05c52164694d changed leader from 8e9e05c52164694d to 91bc3c398fb3c146 at term 7\"}" >> "$E/1.log"
done
for s in 1690 1610; do
  echo "$(ts $s) stderr F E0926 leaderelection.go:340] \"Failed to update lock\" err=\"failed to renew lease kube-system/kube-scheduler: timed out waiting for the condition\"" >> "$S/2.log"
done
for s in 1680 1620 1570; do
  echo "E$(kl $s)    1234 controller.go:195] \"Failed to update lease\" err=\"Put https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/${NODE}: context deadline exceeded\"" >> "$K/kubelet.log"
done
echo "I$(kl 1500)    1234 kubelet.go:100] routine line" >> "$K/kubelet.log"
