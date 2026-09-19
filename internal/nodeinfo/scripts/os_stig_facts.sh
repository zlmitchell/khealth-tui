# Facts for the OS STIG rules that ComplianceAsCode checks with hand-written
# OVAL rather than a template: account database invariants, one filesystem
# sweep, short commands and small config dumps. Evaluated by
# internal/stig/osnamed.go (keyed by CAC rule name). Runs with os_stig.sh:
# once per node on first contact and on R.
#
# Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh only (dash on
# Ubuntu, busybox on Flatcar). Embedded into the Go binary with //go:embed -
# edit here, not in the .go file. Sections are delimited by `sec NAME`
# (===NAME lines) and parsed by the Go side; keep names in sync with the
# parser. Never print secrets: /etc/shadow is reduced to hash type and ages.
sec STIGCMD
kv() { printf '%s=%s\n' "$1" "$2"; }
kv default_target "$(systemctl get-default 2>/dev/null)"
kv efi "$([ -d /sys/firmware/efi ] && echo 1 || echo 0)"
if command -v update-crypto-policies >/dev/null 2>&1; then
  # --show only prints /etc/crypto-policies/config (python start-up otherwise)
  kv crypto_policy "$(grep -v '^#' /etc/crypto-policies/config 2>/dev/null | head -1 | tr -d '[:space:]')"
  kv crypto_check "$(update-crypto-policies --check 2>&1 | head -1)"
  kv crypto_applied "$(update-crypto-policies --is-applied 2>&1 | head -1)"
fi
kv nx "$(grep -qw nx /proc/cpuinfo 2>/dev/null && echo 1 || echo 0)"
kv promisc "$(ip -o link 2>/dev/null | grep -c PROMISC)"
kv wireless "$(ls -d /sys/class/net/*/wireless 2>/dev/null | wc -l)"
# what timedatectl would report, without waking systemd-timedated (~0.9 s)
kv rtc_local "$(awk 'NR==3{print ($1=="LOCAL")?"yes":"no"}' /etc/adjtime 2>/dev/null)"
tz=$(readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##'); [ -n "$tz" ] || tz=$(cat /etc/timezone 2>/dev/null)
kv timezone "$tz"
kv root_passwd "$(passwd -S root 2>/dev/null | awk '{print $2}')"
if command -v rpm >/dev/null 2>&1; then
  kv gpg_keys "$(rpm -q gpg-pubkey --qf '%{SUMMARY};' 2>/dev/null)"
  kv rpm_verify_cron "$(rpm -V cronie crontabs 2>/dev/null | awk '$2 != "c"' | head -5 | tr '\n' ';')"
  kv rpm_verify_sshd "$(rpm -V openssh-server 2>/dev/null | awk '$2 != "c"' | head -5 | tr '\n' ';')"
  # enabled repos from the repo files themselves (dnf -C repolist is 0.2 s of python for the same answer)
  kv repos "$(awk -F= '/^\[/{r=substr($0,2,length($0)-2); en[r]=1} /^enabled[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); en[r]=($2=="1"||$2=="true"||$2=="yes")} END{for(r in en) if(en[r]) print r}' /etc/yum.repos.d/*.repo 2>/dev/null | sort | tr '\n' ' ')"
  kv redhat_release "$(cat /etc/redhat-release 2>/dev/null)"
fi
kv faillock_ctx "$(ls -Zd /var/log/faillock 2>/dev/null | awk '{print $1}')"
kv dev_unlabeled "$(find /dev -context '*:unlabeled_t:*' \( -type c -o -type b \) 2>/dev/null | head -5 | tr '\n' ';')"
if [ "$(systemctl is-active firewalld 2>/dev/null)" = active ]; then
  z=$(firewall-cmd --get-default-zone 2>/dev/null)
  kv firewalld_default_zone "$z"
  kv firewalld_active_zones "$(firewall-cmd --get-active-zones 2>/dev/null | awk 'NR%2==1' | tr '\n' ' ')"
  kv firewalld_target "$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)"
  kv firewalld_services "$(firewall-cmd --zone="$z" --list-services 2>/dev/null)"
  kv firewalld_ports "$(firewall-cmd --zone="$z" --list-ports 2>/dev/null)"
fi
kv ssh_keys_unprotected "$(for k in /root/.ssh/id_* /home/*/.ssh/id_*; do [ -f "$k" ] || continue; case "$k" in *.pub) continue;; esac; ssh-keygen -y -P '' -f "$k" >/dev/null 2>&1 && printf '%s;' "$k"; done)"
kv aide_db "$(ls /var/lib/aide/aide.db.gz /var/lib/aide/aide.db /var/lib/aide/aide.db.new.gz 2>/dev/null | head -1)"
kv aide_cron "$(grep -rhs aide /etc/cron.* /etc/crontab /var/spool/cron 2>/dev/null | grep -v '^#' | head -3 | tr '\n' ';')"
kv aide_timer "$(systemctl list-timers --all --no-legend --plain 2>/dev/null | grep -i aide | head -1)"
kv sudo_group "$(getent group sudo 2>/dev/null | cut -d: -f4)"
kv tmpfiles_rootfiles "$(grep -hs /usr/share/rootfiles/ /etc/tmpfiles.d/*.conf 2>/dev/null | tr '\n' ';')"
kv keytabs "$(ls /etc/*.keytab 2>/dev/null | tr '\n' ' ')"
kv usbguard_rules "$(grep -cvE '^[[:space:]]*(#|$)' /etc/usbguard/rules.conf 2>/dev/null)"
if command -v postconf >/dev/null 2>&1; then
  kv postfix_relay "$(postconf -n smtpd_client_restrictions 2>/dev/null)"
  kv postfix_root_alias "$(postmap -q root hash:/etc/aliases 2>/dev/null)"
fi
kv opensc_drivers "$(opensc-tool --get-conf-entry app:default:card_drivers 2>/dev/null)"
kv sssd_ca_subject "$(openssl x509 -noout -subject -in /etc/sssd/pki/sssd_auth_ca_db.pem 2>/dev/null)"
kv dod_certs "$(grep -rils 'DOD' /etc/ssl/certs 2>/dev/null | head -3 | tr '\n' ' ')"
kv ipsec_active "$(systemctl is-active ipsec 2>/dev/null)"
kv tftp_execstart "$(grep -is execstart /usr/lib/systemd/system/tftp.service 2>/dev/null)"
kv emergency_sulogin "$(grep -hs sulogin /usr/lib/systemd/system/emergency.service /etc/systemd/system/emergency.service.d/*.conf 2>/dev/null | tr '\n' ';')"
kv rescue_sulogin "$(grep -hs sulogin /usr/lib/systemd/system/rescue.service /etc/systemd/system/rescue.service.d/*.conf 2>/dev/null | tr '\n' ';')"
kv grub_superusers "$(grep -hs 'superusers=' /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg /boot/grub/grub.cfg 2>/dev/null | head -1)"
kv grub_password "$(grep -hso 'GRUB2_PASSWORD=grub.pbkdf2.sha512' /boot/grub2/user.cfg /boot/efi/EFI/*/user.cfg 2>/dev/null | head -1; grep -hso 'password_pbkdf2 [^ ]*' /boot/grub/grub.cfg 2>/dev/null | head -1)"
kv named_include "$(grep -hs include /etc/named.conf 2>/dev/null | tr '\n' ';')"
kv ipsec_include "$(grep -hs include /etc/ipsec.conf /etc/ipsec.d/*.conf 2>/dev/null | tr '\n' ';')"
kv pam_sudo_succeed "$(grep -hs pam_succeed_if /etc/pam.d/sudo 2>/dev/null | grep -v '^#' | head -1)"
kv fapolicy_rules_tail "$(tail -3 /etc/fapolicyd/compiled.rules 2>/dev/null | tr '\n' ';')"
kv dconf_stale "$(for db in $(find /etc/dconf/db -maxdepth 1 -type f 2>/dev/null); do dm=$(stat -c %Y "$db"); km=$(stat -c %Y "$db".d/* 2>/dev/null | sort -n | tail -1); [ -n "$km" ] && [ "$dm" -lt "$km" ] && printf '%s;' "$db"; done)"
kv audit_log_file "$(grep -hs '^log_file' /etc/audit/auditd.conf 2>/dev/null | sed 's/.*=[[:space:]]*//')"
sec SSSD
grep -hsE '^[[:space:]]*(pam_cert_auth|certificate_verification|offline_credentials_expiration|cache_credentials|ldap_user_certificate|services)[[:space:]]*=' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf 2>/dev/null
sec UFWSTATUS
command -v ufw >/dev/null 2>&1 && ufw status verbose 2>/dev/null
sec SEMANAGE
command -v semanage >/dev/null 2>&1 && semanage login -l 2>/dev/null
sec LSBLK
lsblk -rno NAME,TYPE,MOUNTPOINT 2>/dev/null
sec PASSWD
cat /etc/passwd 2>/dev/null
sec GROUP
cat /etc/group 2>/dev/null
sec SHADOWMETA
awk -F: '{h=$2; t=(h==""?"empty":(h ~ /^[!*]/?"locked":substr(h,1,3))); print $1":"t":"$4":"$5":"$7":"$8}' /etc/shadow 2>/dev/null
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
