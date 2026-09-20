# kubeadm, on the restored node: register a follower as a learner member
# (it does not count for quorum until promoted, so a slow resync cannot
# take the cluster down again). A stale entry with the same name or peer
# URL is removed first. The ETCD_INITIAL_CLUSTER line etcdctl prints is
# what the follower's manifest must carry (patch_manifest.sh).
NAME='__NAME__'; PEER='__PEER__'
[ -n "$NAME" ] && [ -n "$PEER" ] || die "member name/peer URL unknown"
list=$(run_ctl member list 2>&1) || die "member list: $list"
for id in $(echo "$list" | awk -F', ' -v n="$NAME" -v p="$PEER" '$3==n || $4==p {print $1}'); do
  say "removing stale member $id: $(run_ctl member remove "$id" 2>&1 | head -1)"
done
out=$(run_ctl member add "$NAME" --peer-urls="$PEER" --learner 2>&1) || die "member add: $(echo "$out" | head -1)"
echo "$out" | grep -E '^Member|^ETCD_' | grep -v ETCD_INITIAL_CLUSTER_TOKEN
ic=$(echo "$out" | grep '^ETCD_INITIAL_CLUSTER=' | cut -d'"' -f2)
[ -n "$ic" ] || die "member add printed no ETCD_INITIAL_CLUSTER"
say "initial_cluster=$ic"
say "member_add=ok"
