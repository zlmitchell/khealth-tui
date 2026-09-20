# Stop the control-plane on this node so nothing serves or writes etcd while
# the cluster is rebuilt. rke2/k3s: stop the server unit (the documented
# procedure); kubeadm: park the etcd, kube-apiserver, kube-controller-manager
# and kube-scheduler static pod manifests so kubelet stops the pods and does
# not bring them back (the controllers too: left running they would reconnect
# to the restored apiserver with caches and watches from resource versions
# newer than the restored data). Any etcd container that lingers afterward
# is stopped explicitly.
case "$KIND" in
  rke2|k3s)
    say "systemctl stop $SVC"
    systemctl stop $SVC 2>&1 || say "systemctl stop returned $?"
    st=$(systemctl is-active $SVC 2>/dev/null)
    say "svc_state=$st"
    case "$st" in active|activating|deactivating|reloading) die "$SVC is still $st";; esac
    ;;
  *)
    for m in etcd kube-apiserver kube-controller-manager kube-scheduler; do
      if [ -f $MANIFESTS/$m.yaml ]; then
        mv $MANIFESTS/$m.yaml $PARKED/$m.yaml.off || die "cannot park $m.yaml"
        say "parked $MANIFESTS/$m.yaml -> $PARKED/$m.yaml.off"
      elif [ -f $PARKED/$m.yaml.off ]; then
        say "$m.yaml already parked"
      fi
    done
    i=0
    while [ $i -lt 30 ]; do
      c=$("$CRICTL" -r "$CRI_EP" ps -q --name '^(etcd|kube-apiserver|kube-controller-manager|kube-scheduler)$' 2>/dev/null)
      [ -z "$c" ] && break
      sleep 2; i=$((i+1))
    done
    ;;
esac
if [ -n "$CRICTL" ] && [ -n "$CRI_EP" ]; then
  for c in $("$CRICTL" -r "$CRI_EP" ps -q --name '^(etcd|kube-apiserver|kube-controller-manager|kube-scheduler)$' 2>/dev/null); do
    "$CRICTL" -r "$CRI_EP" stop "$c" >/dev/null 2>&1 && say "stopped lingering container $c"
  done
fi
if command -v ss >/dev/null 2>&1; then
  # rke2's unit kills containerd on stop (KillMode=process) and leaves the
  # etcd container running unmanaged, still serving the old membership on
  # 2379/2380: stop that process the way rke2-killall.sh does
  for pid in $(ss -Hltnp 2>/dev/null | awk '$4 ~ /:(2379|2380)$/' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u); do
    [ "$(cat /proc/$pid/comm 2>/dev/null)" = etcd ] || continue
    kill "$pid" 2>/dev/null && say "stopped orphaned etcd process $pid (its container outlived the unit)"
  done
  i=0
  while [ $i -lt 30 ] && ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE ':(2379|2380)$'; do sleep 1; i=$((i+1)); done
  l=$(ss -Hltnp 2>/dev/null | awk '$4 ~ /:(2379|2380)$/ {print $4, $6}' | head -3 | tr '\n' ';')
  [ -n "$l" ] && say "warning: something still listens on 2379/2380: $l"
fi
say "stopped=ok"
