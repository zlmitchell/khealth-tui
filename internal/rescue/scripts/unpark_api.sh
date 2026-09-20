# kubeadm: etcd on this node is healthy again - put the kube-apiserver
# manifest back, and restart the components that cache cluster state
# (controller-manager and scheduler containers, kubelet) so none of them
# keeps working from resource versions newer than the restored data.
if [ -f $PARKED/kube-apiserver.yaml.off ]; then
  mv $PARKED/kube-apiserver.yaml.off $MANIFESTS/kube-apiserver.yaml || die "cannot restore the kube-apiserver manifest"
  say "restored $MANIFESTS/kube-apiserver.yaml"
elif [ -f $MANIFESTS/kube-apiserver.yaml ]; then
  say "kube-apiserver manifest already in place"
else
  die "no kube-apiserver manifest to restore"
fi
for n in kube-controller-manager kube-scheduler; do
  for c in $("$CRICTL" -r "$CRI_EP" ps -q --name "^$n\$" 2>/dev/null); do
    "$CRICTL" -r "$CRI_EP" stop "$c" >/dev/null 2>&1 && say "restarted $n ($c)"
  done
done
systemctl restart kubelet 2>&1 && say "restarted kubelet"
say "unpark=ok"
