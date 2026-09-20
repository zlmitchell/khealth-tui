# Move the etcd member data aside into the rescue directory (never deleted
# by khealth). Moving rather than copying keeps disk usage flat and is what
# the restore needs anyway: the data dir must not exist (kubeadm) or is
# replaced (rke2/k3s). The original owner and mode are printed so the
# restored directory gets the same ones.
mkdir -p "$RESCUE" || die "cannot create $RESCUE"
chmod 700 "$RESCUE"
if [ -d "$DATADIR" ]; then
  say "owner=$(stat -c '%U:%G' "$DATADIR" 2>/dev/null)"
  say "mode=$(stat -c '%a' "$DATADIR" 2>/dev/null)"
  case "$RESCUE" in
    "$DATADIR"/*)
      # the rescue dir lives inside the data dir (mount point): move the contents
      for f in "$DATADIR"/* "$DATADIR"/.[!.]*; do
        [ -e "$f" ] || continue
        [ "$f" = "$RESCUE" ] && continue
        mv "$f" "$RESCUE"/ || die "mv $f $RESCUE/ failed"
      done
      say "moved contents of $DATADIR to $RESCUE"
      ;;
    *)
      mv "$DATADIR" "$RESCUE/etcd" || die "mv $DATADIR $RESCUE/etcd failed"
      say "moved $DATADIR to $RESCUE/etcd"
      ;;
  esac
else
  say "no $DATADIR to back up"
fi
case "$KIND" in
  rke2|k3s)
    # cluster-reset renames the data dir to etcd-old-<time> before restoring
    # and fails when there is none: leave an empty one with the same owner/mode
    if [ ! -d "$DATADIR" ]; then
      mkdir -p "$DATADIR" || die "cannot recreate $DATADIR"
      [ -d "$RESCUE/etcd" ] && chown --reference="$RESCUE/etcd" "$DATADIR" 2>/dev/null && chmod --reference="$RESCUE/etcd" "$DATADIR" 2>/dev/null
      say "recreated empty $DATADIR"
    fi
    ;;
esac
say "backup=ok"
