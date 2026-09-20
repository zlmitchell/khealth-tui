# kubeadm follower: its parked etcd manifest must describe the cluster it
# joins (the member list `member add` printed) with state=existing; etcd
# only reads these flags when the data dir is empty, which it now is. The
# manifest as it was is kept in the rescue directory.
IC='__INITIAL_CLUSTER__'
[ -n "$IC" ] || die "initial cluster list is empty"
M=$PARKED/etcd.yaml.off
[ -f "$M" ] || die "$M missing (was the manifest parked?)"
mkdir -p "$RESCUE" && cp -p "$M" "$RESCUE/etcd.yaml.before-rescue"
grep -q -- '--initial-cluster=' "$M" || die "no --initial-cluster= in $M"
sed -i -E "s#^([[:space:]]*- )--initial-cluster=.*#\1--initial-cluster=$IC#" "$M" || die "sed failed"
if grep -q -- '--initial-cluster-state=' "$M"; then
  sed -i -E 's#^([[:space:]]*- )--initial-cluster-state=.*#\1--initial-cluster-state=existing#' "$M"
else
  sed -i -E "s#^([[:space:]]*- )--initial-cluster=.*#&\n\1--initial-cluster-state=existing#" "$M"
fi
grep -E -- '--initial-cluster' "$M" | sed 's/^[[:space:]]*//'
say "patched=ok"
