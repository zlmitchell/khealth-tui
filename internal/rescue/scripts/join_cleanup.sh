# rke2/k3s: a follower is a healthy member again, or (on the target) every
# follower is back: remove the temporary server: drop-in so the node's
# configuration is what it was before the rescue. 99-khealth-rescue.yaml is
# the name older versions used.
n=0
for f in $CONFDIR/config.yaml.d/zz-khealth-rescue.yaml $CONFDIR/config.yaml.d/99-khealth-rescue.yaml; do
  [ -f "$f" ] && { rm -f "$f" && say "removed $f" && n=$((n+1)); }
done
[ "$n" = 0 ] && say "no drop-in to remove"
say "cleanup=ok"
