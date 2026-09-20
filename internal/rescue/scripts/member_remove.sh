# rke2/k3s, on the healthy anchor: drop the stale member entry of the
# server that is about to rejoin (its peer address __PEER__): rke2 refuses
# the join while a member with that name still exists ("duplicate node
# name found"). Only entries whose peer URL is that address are touched; the
# node is stopped, so nothing serves that address right now.
PEER='__PEER__'
[ -n "$PEER" ] || die "no peer address given"
list=$(run_ctl member list 2>&1) || die "member list: $(echo "$list" | head -1)"
n=0
for id in $(echo "$list" | awk -F', ' -v h="$PEER" '$4 ~ ("//" h ":") || $4 ~ ("//\[" h "\]:") {print $1}'); do
  name=$(echo "$list" | awk -F', ' -v i="$id" '$1==i {print $3}')
  out=$(run_ctl member remove "$id" 2>&1) || die "member remove $id ($name): $(echo "$out" | head -1)"
  say "removed stale member $id ($name, $PEER)"
  n=$((n+1))
done
[ $n -eq 0 ] && say "no member entry for $PEER (nothing to remove)"
say "members_now=$(run_ctl member list 2>/dev/null | grep -c .)"
say "member_remove=ok"
