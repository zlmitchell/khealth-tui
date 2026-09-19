# OS STIG facts consumed by the ComplianceAsCode template evaluators
# (internal/stig/ostemplates.go): generic sections only; the data-derived
# stat/find/dump sections are appended by stigdata.ProbeScript(). Collected
# once per node (first contact) and on R. Parsed by nodeinfo.parseOSStig.
#
# Sent to nodes over SSH by khealth as `sudo sh -s`; POSIX sh only (dash on
# Ubuntu, busybox on Flatcar). Embedded into the Go binary with //go:embed -
# edit here, not in the .go file. Sections are delimited by `sec NAME`
# (===NAME lines) and parsed by the Go side; keep names in sync with the
# parser. Never print secrets: pass file dumps through `mask`.
sec SYSCTLALL; sysctl -a 2>/dev/null
sec PKGS
if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\n' 2>/dev/null
elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${db:Status-Status}\n' 2>/dev/null | awk '$2=="installed"{print $1}'; fi
sec UNITFILES; systemctl list-unit-files --no-legend --plain --no-pager 2>/dev/null
sec UNITSALL; systemctl list-units --all --no-legend --plain --no-pager --type=service,socket,timer 2>/dev/null
sec FINDMNT; findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null
sec FSTAB; grep -vE '^[[:space:]]*(#|$)' /etc/fstab 2>/dev/null
sec SSHD; sshd -T 2>/dev/null
sec AUDITRULES; auditctl -l 2>/dev/null
sec AUDITRULESD; cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null | grep -vE '^[[:space:]]*(#|$)'
sec MODPROBE; grep -hE '^[[:space:]]*(install|blacklist)[[:space:]]' /etc/modprobe.d/*.conf /etc/modprobe.conf 2>/dev/null
sec LSMOD; lsmod 2>/dev/null | awk 'NR>1{print $1}'
sec GRUBCFG
grubby --info=ALL 2>/dev/null | grep '^args='
grep -E '^GRUB_CMDLINE_LINUX' /etc/default/grub 2>/dev/null
