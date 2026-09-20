# OS STIG filesystem sweep: world-writable directories, unowned files,
# home directory modes, system binaries, audit logs, SSH host keys.
# Evaluated by internal/stig/osnamed.go (STIGSWEEP kinds). The slowest part
# of the OS STIG collection (one find pass over every local filesystem), so
# it is its own scan stage and its own timeout. Runs with os_stig.sh and
# os_stig_facts.sh: on Shift+S (staged) or as one script (perfbench).
#
# Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh only (dash on
# Ubuntu, busybox on Flatcar). Embedded into the Go binary with //go:embed -
# edit here, not in the .go file. Sections are delimited by `sec NAME`
# (===NAME lines) and parsed by the Go side; keep names in sync with the
# parser.
sec STIGSWEEP
# Host filesystems only: overlay/nsfs mounts are running containers' root
# filesystems (150+ on a busy node) and the image layer stores are not the
# host either. One find pass prints numeric uid/gid, type and mode and awk
# applies the checks: find's own -nouser/-nogroup call NSS once per file
# (25 s here with sss in nsswitch, 1 s this way); ids awk does not know are
# confirmed with a few getent lookups so domain users still resolve.
mounts=$(df --local -P -x tmpfs -x devtmpfs -x overlay -x nsfs -x squashfs -x efivarfs -x fuse.lxcfs 2>/dev/null | awk 'NR>1{print $6}')
UIDS=$(timeout 10 getent passwd 2>/dev/null | cut -d: -f3 | tr '\n' ' '); [ -n "$UIDS" ] || UIDS=$(cut -d: -f3 /etc/passwd 2>/dev/null | tr '\n' ' ')
GIDS=$(timeout 10 getent group 2>/dev/null | cut -d: -f3 | tr '\n' ' '); [ -n "$GIDS" ] || GIDS=$(cut -d: -f3 /etc/group 2>/dev/null | tr '\n' ' ')
[ -n "$mounts" ] && timeout 120 find $mounts -xdev \( -path '*/io.containerd.snapshotter.v1.*' -o -path '*/io.containerd.runtime.v2.task' -o -path '*/kubelet/pods' -o -path /var/lib/docker/overlay2 -o -path /var/lib/containers/storage \) -prune -o -printf '%U|%G|%y|%m|%f|%p\n' 2>/dev/null | awk -F'|' -v uids="$UIDS" -v gids="$GIDS" '
BEGIN { n=split(uids,a," "); for(i=1;i<=n;i++) U[a[i]]=1; n=split(gids,a," "); for(i=1;i<=n;i++) G[a[i]]=1 }
out>=200 { exit }
{ uid=$1; gid=$2; typ=$3; mode=$4; name=$5; path=$6
  o=substr(mode,length(mode),1)+0; ww=(o==2||o==3||o==6||o==7); sticky=(length(mode)==4 && substr(mode,1,1)%2==1)
  if (typ=="d" && ww) { if(!sticky) {print "WWNOSTICKY|" path; out++} if(uid+0>999) {print "WWUSER|" path "|" uid; out++} if(gid+0>999) {print "WWGROUP|" path "|" gid; out++} }
  if (!(uid in U) && nu[uid]++<5) {print "NOUSER?|" uid "|" path; out++}
  if (!(gid in G) && ng[gid]++<5) {print "NOGROUP?|" gid "|" path; out++}
  if (name=="shosts.equiv" || name==".shosts") {print "SHOSTS|" path; out++}
}' | while IFS='|' read -r k id path; do
  case "$k" in
    'NOUSER?') case " $known " in *" u$id "*) ;; *) if getent passwd "$id" >/dev/null 2>&1; then known="$known u$id"; else echo "NOUSER|$path"; fi;; esac;;
    'NOGROUP?') case " $known " in *" g$id "*) ;; *) if getent group "$id" >/dev/null 2>&1; then known="$known g$id"; else echo "NOGROUP|$path"; fi;; esac;;
    *) if [ -n "$path" ]; then echo "$k|$id|$path"; else echo "$k|$id"; fi;;
  esac
done
timeout 60 find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin -xdev \( -perm /022 -printf 'BINPERM|%p|%m\n' \) -o \( ! -user root -printf 'BINOWNER|%p|%U\n' \) -o \( -gid +999 -printf 'BINGROUP|%p|%G\n' \) 2>/dev/null | head -50
awk -F: '($3>=1000)&&($1!="nobody")&&($7 !~ /(nologin|false)$/){print $1":"$4":"$6}' /etc/passwd 2>/dev/null | while IFS=: read -r u g h; do
  if [ -d "$h" ]; then stat -c "HOME|$u|%a|%g|%n" "$h" 2>/dev/null; else echo "HOMEMISSING|$u|$h"; continue; fi
  find "$h" -maxdepth 1 -type f -name '.*' ! -name .bash_history -perm /037 -printf "INITPERM|$u|%p|%m\n" 2>/dev/null | head -10
  find "$h" -maxdepth 1 -type f -name '.*' -perm -002 -printf "INITWW|$u|%p\n" 2>/dev/null | head -5
  grep -iHs umask "$h"/.[!.]* 2>/dev/null | grep -v bash_history | grep -v '^[^:]*:[[:space:]]*#' | head -5 | sed "s#^#UMASK|$u|#"
  grep -iHs 'path=' "$h"/.[!.]* 2>/dev/null | grep -v bash_history | grep -v '^[^:]*:[[:space:]]*#' | head -5 | sed "s#^#PATHLINE|$u|#"
  find "$h" -maxdepth 2 -mindepth 1 ! -name '.*' \( -perm /027 -printf "HOMEPERM|$u|%p|%m\n" \) -o \( ! -gid "$g" -printf "HOMEGROUP|$u|%p|%G\n" \) 2>/dev/null | head -10
done
if [ -d /var/log/audit ]; then
  stat -c 'AUDITDIR|%n|%a|%U|%G' /var/log/audit 2>/dev/null
  find /var/log/audit -maxdepth 1 -type f \( -perm /177 -printf 'AUDITLOGPERM|%p|%m\n' \) -o \( ! -user root -printf 'AUDITLOGOWNER|%p|%U\n' \) -o \( ! -group root -printf 'AUDITLOGGROUP|%p|%G\n' \) 2>/dev/null | head -10
fi
stat -c 'SSHKEY|%n|%a' /etc/ssh/ssh_host_*_key 2>/dev/null
