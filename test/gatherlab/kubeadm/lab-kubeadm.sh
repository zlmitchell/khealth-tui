#!/bin/sh
# kubeadm init on first boot (lab-kubeadm.service), then what a kubeadm
# cluster does not ship: a CNI (kind's kindnet), an ingress controller
# (ingress-nginx, which logs every request by default) and the lab's
# workloads. The unit turns active once all of it is applied: the compose
# healthcheck waits for that.
set -e
export KUBECONFIG=/etc/kubernetes/admin.conf
M=/lab/manifests

if [ ! -f /etc/kubernetes/admin.conf ]; then
  # preflight trips over the container (kernel modules, swap, /proc/sys)
  kubeadm init --config /etc/kubernetes/lab-kubeadm.yaml --skip-phases=preflight --skip-token-print
fi
until kubectl get --raw /readyz >/dev/null 2>&1; do sleep 2; done

# one node: it runs the workloads too
kubectl taint nodes lab-node node-role.kubernetes.io/control-plane:NoSchedule- 2>/dev/null || true
sed 's#{{ .PodSubnet }}#10.244.0.0/16#' /kind/manifests/default-cni.yaml | kubectl apply -f -

kubectl apply -f /lab/ingress-nginx.yaml
kubectl annotate --overwrite ingressclass nginx ingressclass.kubernetes.io/is-default-class=true
# the Ingress below goes through the controller's admission webhook
kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=15m

# the webhook's endpoint can trail the rollout by a few seconds
n=0
until kubectl apply -f $M/kubeadm-ingress.yaml -f $M/shop.yaml -f $M/incidents.yaml -f $M/noisy.yaml; do
  n=$((n+1)); [ $n -lt 30 ] || exit 1; sleep 5
done

# for the host: the API is published on 127.0.0.1:26443 (compose.kubeadm.yaml)
sed 's#server: https://lab-node:6443#server: https://127.0.0.1:26443#' /etc/kubernetes/admin.conf > /out/kubeconfig.yaml
chmod 644 /out/kubeconfig.yaml
echo "gatherlab: kubeadm cluster ready, workloads applied"
