# rke2/k3s: config.yaml pins node-ip to an address this node no longer
# holds (__OLD__), so every listener rke2 renders from it - etcd peer and
# client URLs, the kubelet's node address - fails to bind. Rewrite it to
# __NEW__ in place (the file keeps a .khealth-<stamp> copy); a config.yaml.d
# drop-in would be dropped again with the rescue's own one. Only a value
# equal to __OLD__ is touched: the node keeps anything else it pins.
OLD='__OLD__'; NEW='__NEW__'
[ -n "$OLD" ] && [ -n "$NEW" ] || die "no old/new address given"
n=0
for f in $CONFDIR/config.yaml $CONFDIR/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  if head -c 64 "$f" 2>/dev/null | grep -q '^[[:space:]]*{'; then
    grep -qE "\"node-ip\"[[:space:]]*:[[:space:]]*\"$OLD\"" "$f" || continue
    cp -p "$f" "$f.khealth-$STAMP" || die "cannot back up $f"
    sed -i -E "s/(\"node-ip\"[[:space:]]*:[[:space:]]*\")$OLD\"/\\1$NEW\"/" "$f" || die "cannot rewrite $f"
  else
    grep -qE "^[[:space:]]*node-ip[[:space:]]*:[[:space:]]*\"?$OLD\"?[[:space:]]*(#.*)?$" "$f" || continue
    cp -p "$f" "$f.khealth-$STAMP" || die "cannot back up $f"
    sed -i -E "s/^([[:space:]]*node-ip[[:space:]]*:[[:space:]]*\"?)$OLD(\"?[[:space:]]*(#.*)?)$/\\1$NEW\\2/" "$f" || die "cannot rewrite $f"
  fi
  say "rewrote node-ip $OLD -> $NEW in $f (copy: $f.khealth-$STAMP)"
  case "$f" in *config.yaml.d/50-rancher.yaml) say "NOTE: $f is written by rancher-system-agent and comes back with the next plan: change the machine's address in Rancher as well";; esac
  n=$((n+1))
done
[ $n -eq 0 ] && say "no config file pins node-ip: $OLD (nothing to rewrite)"
say "fix_node_ip=ok"
