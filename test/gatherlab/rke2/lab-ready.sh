#!/bin/sh
# rke2 applies the lab's manifests itself (server/manifests, copied there
# by lab-setup.sh). Wait until they are in, then write the host's
# kubeconfig. The unit turns active then: the compose healthcheck waits
# for that.
set -e
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml PATH=$PATH:/var/lib/rancher/rke2/bin
until kubectl get --raw /readyz >/dev/null 2>&1; do sleep 2; done
until kubectl -n batch get job report >/dev/null 2>&1 && kubectl -n shop get svc edge >/dev/null 2>&1; do sleep 2; done
# rke2's add-ons (Canal, CoreDNS, ingress-nginx) come up through helm jobs
# after the API: the workloads wait on the CNI, the traffic on the ingress
kubectl wait node/lab-node --for=condition=Ready --timeout=15m
until kubectl -n kube-system get ds rke2-ingress-nginx-controller >/dev/null 2>&1; do sleep 2; done
kubectl -n kube-system rollout status ds/rke2-ingress-nginx-controller --timeout=15m
# for the host: the API is published on 127.0.0.1:36443 (compose.rke2.yaml)
sed 's#server: https://127.0.0.1:6443#server: https://127.0.0.1:36443#' $KUBECONFIG > /out/kubeconfig.yaml
chmod 644 /out/kubeconfig.yaml
echo "gatherlab: rke2 cluster ready, workloads applied"
