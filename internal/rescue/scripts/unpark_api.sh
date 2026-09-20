# kubeadm: etcd on this node is healthy again - put the kube-apiserver,
# kube-controller-manager and kube-scheduler manifests back (stop.sh parked
# them), and restart the components that cache cluster state (the controller
# containers when they were not parked, kubelet) so none of them keeps
# working from resource versions newer than the restored data.
for m in kube-apiserver kube-controller-manager kube-scheduler; do
  if [ -f $PARKED/$m.yaml.off ]; then
    mv $PARKED/$m.yaml.off $MANIFESTS/$m.yaml || die "cannot restore the $m manifest"
    say "restored $MANIFESTS/$m.yaml"
  elif [ -f $MANIFESTS/$m.yaml ]; then
    say "$m manifest already in place"
    [ "$m" = kube-apiserver ] && continue
    for c in $("$CRICTL" -r "$CRI_EP" ps -q --name "^$m\$" 2>/dev/null); do
      "$CRICTL" -r "$CRI_EP" stop "$c" >/dev/null 2>&1 && say "restarted $m ($c)"
    done
  elif [ "$m" = kube-apiserver ]; then
    die "no kube-apiserver manifest to restore"
  fi
done
systemctl restart kubelet 2>&1 && say "restarted kubelet"
say "unpark=ok"
