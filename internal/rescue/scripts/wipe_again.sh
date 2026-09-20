# rke2/k3s: the cluster-reset did not replace the data dir - move whatever
# is there into the rescue dir as well (never deleted) and leave an empty
# dir with the same owner/mode for the next attempt, like backup.sh did.
mkdir -p "$RESCUE" || die "cannot create $RESCUE"
n=1; while [ -e "$RESCUE/etcd-attempt$n" ]; do n=$((n+1)); done
if [ -d "$DATADIR" ]; then
  mv "$DATADIR" "$RESCUE/etcd-attempt$n" || die "mv $DATADIR failed"
  say "moved $DATADIR to $RESCUE/etcd-attempt$n"
fi
mkdir -p "$DATADIR" || die "cannot recreate $DATADIR"
ref=$RESCUE/etcd; [ -d "$ref" ] || ref=$RESCUE/etcd-attempt$n
chown --reference="$ref" "$DATADIR" 2>/dev/null; chmod --reference="$ref" "$DATADIR" 2>/dev/null
say "wiped=ok"
