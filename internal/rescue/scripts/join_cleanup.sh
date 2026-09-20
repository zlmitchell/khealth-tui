# rke2/k3s follower is a healthy member again: remove the temporary join
# drop-in so the node's configuration is what it was before the rescue.
f=$CONFDIR/config.yaml.d/99-khealth-rescue.yaml
if [ -f "$f" ]; then rm -f "$f" && say "removed $f"; else say "no drop-in to remove"; fi
say "cleanup=ok"
