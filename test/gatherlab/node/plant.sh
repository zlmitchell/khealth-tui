#!/bin/sh
# Plant the log lines of an etcd disk incident in the node's journal, a
# few seconds apart and in causal order: slow fsyncs, then leader
# elections, then the scheduler losing its lease, then the kubelet failing
# to renew its node lease. The rca etcd rule must tie them into one chain.
# Tagged k3s at warning priority: journal/warnings.log carries them.
w() { printf '%s\n' "$1" | systemd-cat -t k3s -p warning; sleep 2; }
for i in 1 2 3 4 5; do
  w '{"level":"warn","caller":"wal/wal.go:805","msg":"slow fdatasync","took":"1.8s","expected-duration":"1s"}'
done
for i in 1 2 3; do
  w '{"level":"info","msg":"raft.node: 8e9e05c52164694d changed leader from 8e9e05c52164694d to 91bc3c398fb3c146 at term 7"}'
done
w 'E0926 leaderelection.go:340] "Failed to update lock" err="failed to renew lease kube-system/kube-scheduler: timed out waiting for the condition"'
w 'E0926 leaderelection.go:340] "Failed to update lock" err="failed to renew lease kube-system/kube-controller-manager: timed out waiting for the condition"'
for i in 1 2 3; do
  w 'E0926 controller.go:195] "Failed to update lease" err="Put https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/lab-node: context deadline exceeded"'
done
