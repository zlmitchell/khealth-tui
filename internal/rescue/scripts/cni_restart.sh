# After the restore the CNI agent on the restored node (calico-node in canal
# on rke2) resyncs against an apiserver that is still coming up and drops
# the routes to the pods already running here ("no route to host" from
# every pod on the node until it is restarted). Restart the CNI DaemonSet
# pod(s) on this node once the apiserver answers, and wait for them to run
# again. Nothing to do is not an error (host-network CNIs, no match).
nodes=$($KUBECTL get nodes -o jsonpath='{.items[*].metadata.name}' 2>&1) || die "kubectl failed: $(echo "$nodes" | head -1)"
NODE=$(echo "$nodes" | tr ' ' '\n' | grep -ix "$(hostname)" | head -1)
[ -n "$NODE" ] || NODE='__NODE__'
say "node=$NODE"
pods=$($KUBECTL -n kube-system get pods --field-selector spec.nodeName="$NODE" -o name 2>/dev/null | grep -E 'canal|calico-node|cilium-[a-z0-9]+$|flannel|kube-router|weave|multus' | grep -v -E 'typha|operator|install')
if [ -z "$pods" ]; then
  say "no CNI agent pod found on $NODE (nothing restarted)"
else
  n=0
  for p in $pods; do
    $KUBECTL -n kube-system delete "$p" --wait=false >/dev/null 2>&1 && { say "restarted $p"; n=$((n+1)); }
  done
  i=0
  while [ $i -lt 24 ]; do
    r=$($KUBECTL -n kube-system get pods --field-selector spec.nodeName="$NODE" --no-headers 2>/dev/null | grep -E 'canal|calico-node|cilium-[a-z0-9]+ |flannel|kube-router|weave|multus' | grep -v -E 'typha|operator|install' | grep -c ' Running ')
    [ "$r" -ge "$n" ] && break
    sleep 5; i=$((i+1))
  done
  say "cni_running=$r/$n"
  [ "$r" -ge "$n" ] || die "the CNI pod(s) on $NODE did not come back within 2 minutes"
fi
say "cni=ok"
