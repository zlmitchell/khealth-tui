package checks

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalPreflight raises the "will rke2 keep running / can this node be
// re-provisioned" findings from nodeinfo.Preflight (scripts/preflight.sh):
// swap, fapolicyd, auditd disk actions, noexec mounts, account expiry,
// proxies, the vSphere cloud-init ISO, firewalld/NetworkManager, iptables,
// SELinux packages, sysctls and the private registry probe.
func evalPreflight(name string, ni *nodeinfo.Info, in Input, add func(Severity, string, string, string, string)) {
	p := &ni.Preflight
	thr := in.Cfg.Thresholds
	v := distro.For(ni.Dist)
	if (ni.Dist == "" || ni.Dist == "unknown") && in.Snap != nil {
		v = distro.For(in.Snap.Distribution)
	}
	dataDir := ni.DataDir
	if dataDir == "" {
		dataDir = v.DataDir
	}
	isRancher := distro.IsRancher(v.Name)
	// rke2/k3s run the kubelet as a child of their own unit
	kubeletUp := false
	for _, s := range []string{"kubelet", "rke2-server", "rke2-agent", "k3s", "k3s-agent"} {
		if svc := ni.Service(s); svc != nil && svc.Active == "active" {
			kubeletUp = true
		}
	}

	// ---- swap ----
	if len(p.Swaps) > 0 {
		var total int64
		var devs []string
		for _, s := range p.Swaps {
			total += s.SizeKB
			devs = append(devs, s.Name)
		}
		// rke2/k3s write failSwapOn: false into 00-rke2-defaults.conf, so
		// swap only stops kubeadm nodes and kubelets whose config overrides it
		allowed := p.FailSwapOn == "false" || ni.KubeletFlags["fail-swap-on"] == "false"
		if ni.KubeletFlags["fail-swap-on"] == "true" {
			allowed = false
		}
		if p.Probed && p.FailSwapOn == "" && !allowed && isRancher && ni.KubeletFlags["fail-swap-on"] == "" {
			allowed = true // rke2/k3s default when the drop-in was not readable
		}
		switch {
		case allowed:
			if ni.SwapTotal-ni.SwapFree > 0 {
				add(SevInfo, "node", name, fmt.Sprintf("swap in use (%s of %s): the kubelet runs with failSwapOn=false (%s default) so it tolerates it, but the kernel swaps system daemons and STIG images usually expect swap off", strutil.HumanBytes(float64(ni.SwapTotal-ni.SwapFree)), strutil.HumanBytes(float64(ni.SwapTotal)), ni.Dist), "swapoff -a and drop the fstab entry unless memorySwap.swapBehavior=LimitedSwap is intended")
			}
		case kubeletUp:
			add(SevCrit, "node", name, fmt.Sprintf("swap active (%s on %s): the running kubelet started before it was enabled and refuses to start with swap on - it will not come back after the next restart or reboot", strutil.HumanBytes(float64(total)*1024), strings.Join(devs, ",")), "swapoff -a and remove the swap line from /etc/fstab (or "+v.KubeletArg("fail-swap-on=false", "failSwapOn: false")+")")
		default:
			add(SevCrit, "node", name, fmt.Sprintf("swap active (%s on %s) and the kubelet is not running: kubelet fails with 'running with swap on is not supported'", strutil.HumanBytes(float64(total)*1024), strings.Join(devs, ",")), "swapoff -a; remove the swap line from /etc/fstab; "+v.Restart(ni.ControlPlane))
		}
	} else if p.Probed && len(p.FstabSwap) > 0 {
		add(SevWarn, "node", name, "swap is off now but /etc/fstab still lists it: it comes back at the next reboot and the kubelet will not start", "comment out the swap line in /etc/fstab: "+strutil.FirstLine(p.FstabSwap[0]))
	}

	// ---- fapolicyd ----
	fapActive := p.Units["fapolicyd.service"].Active || strings.HasPrefix(ni.ServiceState("fapolicyd"), "active")
	if fapActive && p.Probed {
		fa := p.Fapolicyd
		var covered bool
		var ruleFiles []string
		for _, r := range fa.K8sRules {
			file, rule, _ := strings.Cut(r, ":")
			ruleFiles = append(ruleFiles, file)
			if d := ruleDir(rule); d != "" && (strings.HasPrefix(dataDir+"/", d) || strings.HasPrefix(dataDir, strings.TrimSuffix(d, "/"))) {
				covered = true
			}
		}
		rulesFile := v.FapolicydFile
		if i := strings.LastIndex(rulesFile, "/"); i >= 0 {
			rulesFile = rulesFile[i+1:]
		}
		switch {
		case fa.Permissive == "1":
			add(SevInfo, "security", name, "fapolicyd runs permissive (logs only, does not block)", "")
		case !isRancher:
			// packaged kubelet/containerd are in the RPM trust db; only real denials matter
		case len(fa.K8sRules) == 0:
			add(SevCrit, "node", name, "fapolicyd is enforcing but no rules.d rule allows the "+v.Name+" paths: containerd-shim/runc under "+dataDir+" are denied ('operation not permitted') and pods stay ContainerCreating", "write "+v.FapolicydFile+" with 'allow perm=any all : dir=<dir>' for "+strings.Join(v.FapolicydDirs, " ")+", then fagenrules --load && systemctl restart fapolicyd")
		case !covered:
			add(SevCrit, "node", name, "fapolicyd rules allow /var/lib/rancher but data-dir is "+dataDir+": "+v.Binaries+" there are denied", "add 'allow perm=any all : dir="+dataDir+"/' to "+v.FapolicydFile+"; fagenrules --load; systemctl restart fapolicyd")
		case fa.CompiledK8s == 0:
			add(SevCrit, "node", name, "fapolicyd rules.d has the "+v.Name+" rules but compiled.rules does not: fagenrules --load never ran, the daemon enforces the old rule set", "fagenrules --load && systemctl restart fapolicyd")
		default:
			if fa.DenyFile != "" && len(ruleFiles) > 0 {
				sort.Strings(ruleFiles)
				if ruleFiles[0] >= fa.DenyFile {
					add(SevCrit, "node", name, fmt.Sprintf("fapolicyd rule order: %s sorts after the catch-all deny in %s, so the %s allow rules never match", ruleFiles[0], fa.DenyFile, v.Name), "rename the rules file to a lower number than "+fa.DenyFile+" (e.g. "+rulesFile+"); fagenrules --load; restart fapolicyd")
				}
			}
			if fa.RulesdMtime > fa.CompiledMtime && fa.CompiledMtime > 0 {
				add(SevWarn, "node", name, "fapolicyd rules.d changed after compiled.rules was generated: the running rule set is stale", "fagenrules --load && systemctl restart fapolicyd")
			}
		}
		// storage drivers execute host binaries the distribution's rules do
		// not cover - for the drivers that actually run here: the directory
		// alone (a leftover of an uninstalled driver) proves nothing
		if fa.Permissive != "1" && (len(fa.K8sRules) > 0 || !isRancher) {
			for _, d := range p.CSI.HostDirs {
				if d == "/var/lib/longhorn" && slices.Contains(p.CSI.HostDirs, "/var/lib/longhorn/engine-binaries") {
					continue
				}
				if !csiDirInUse(d, p.CSI.Drivers, in.Snap) {
					continue
				}
				if _, ok := fa.Covers(d); ok {
					continue
				}
				who := csiOwner(d)
				add(SevCrit, "storage", name, fmt.Sprintf("fapolicyd has no allow rule for %s: %s executes from there and gets 'operation not permitted'", d, who), "add 'allow perm=any all : dir="+strings.TrimSuffix(d, "/")+"/' to /etc/fapolicyd/rules.d/81-csi.rules (before the deny file); fagenrules --load; systemctl restart fapolicyd")
			}
		}
		if p.DeniesProbed {
			var k8sCount, other int
			var top *nodeinfo.FapDeny
			for i := range p.Denies {
				d := &p.Denies[i]
				if k8sPath(d.Exe, dataDir) || k8sPath(d.Path, dataDir) {
					k8sCount += d.Count
					if top == nil || d.Count > top.Count {
						top = d
					}
				} else {
					other += d.Count
				}
			}
			if top != nil {
				ago := ""
				if !top.Last.IsZero() {
					ago = " (last " + strutil.HumanDur(in.Now.Sub(top.Last)) + " ago)"
				}
				add(SevCrit, "node", name, fmt.Sprintf("fapolicyd denied %d executions of %s/CSI binaries today, e.g. %s -> %s%s", k8sCount, v.Name, top.Exe, top.Path, ago), "ausearch -m FANOTIFY -ts today -i; add the path to "+v.FapolicydFile+" and fagenrules --load")
			} else if other > 0 {
				add(SevInfo, "security", name, fmt.Sprintf("fapolicyd denied %d executions today (none under %s paths)", other, v.Name), "ausearch -m FANOTIFY -ts today -i")
			}
		}
	}

	// ---- storage drivers' host prerequisites ----
	if p.Probed && p.CSI.Has("longhorn") {
		if !p.CSI.ISCSID {
			add(SevWarn, "storage", name, "Longhorn CSI is registered but iscsid is not running: v1 volumes cannot attach on this node", "install open-iscsi / iscsi-initiator-utils and systemctl enable --now iscsid")
		}
		if p.Units["multipathd.service"].Active && p.CSI.MultipathBlacklist <= 0 {
			add(SevWarn, "storage", name, "multipathd is running without a blacklist while Longhorn is installed: multipath claims Longhorn block devices and volumes fail to mount", "blacklist Longhorn devices in /etc/multipath.conf (devnode \"^sd[a-z0-9]+\") or disable multipathd; see Longhorn troubleshooting")
		}
	}

	// ---- auditd disk actions ----
	if p.Probed && len(p.Auditd) > 0 && (p.Units["auditd.service"].Active || strings.HasPrefix(ni.ServiceState("auditd"), "active")) {
		logFile := p.Auditd["log_file"]
		if logFile == "" {
			logFile = "/var/log/audit/audit.log"
		}
		dir := logFile[:strings.LastIndex(logFile, "/")+1]
		if m := ni.MountFor(dir); m != nil {
			// halt/single take the node down; suspend only stops audit logging
			// (a compliance gap, not an outage)
			fatal := func(action string) bool {
				a := strings.ToLower(p.Auditd[action])
				return a == "halt" || a == "single"
			}
			suspends := func(action string) bool { return strings.EqualFold(p.Auditd[action], "suspend") }
			adminMB := auditMB(p.Auditd["admin_space_left"], m.SizeKB)
			spaceMB := auditMB(p.Auditd["space_left"], m.SizeKB)
			freeMB := m.AvailKB / 1024
			keep := strings.EqualFold(p.Auditd["max_log_file_action"], "keep_logs")
			var actions []string
			for _, k := range []string{"admin_space_left_action", "disk_full_action", "disk_error_action"} {
				if fatal(k) {
					actions = append(actions, k+"="+p.Auditd[k])
				}
			}
			if len(actions) > 0 {
				near := m.UsePct >= thr.DiskWarnPct || (adminMB > 0 && freeMB < adminMB*4) || (spaceMB > 0 && freeMB < spaceMB*2)
				msg := fmt.Sprintf("auditd %s: the node halts or drops to single-user when %s runs out of space (%s free, %d%% used, admin_space_left=%s)", strings.Join(actions, ","), m.Mountpoint, strutil.HumanBytes(float64(freeMB)*1024*1024), m.UsePct, p.Auditd["admin_space_left"])
				hint := "rotate/archive audit logs, grow the partition, or set the actions to syslog/rotate"
				if keep {
					msg += "; max_log_file_action=keep_logs so the logs only grow"
					hint = "archive old audit.log.N files off-box (STIG keeps keep_logs), grow " + m.Mountpoint + ", or move admin_space_left_action away from halt/single"
				}
				if near {
					add(SevCrit, "node", name, msg, hint)
				} else if fatal("space_left_action") {
					add(SevWarn, "node", name, msg, hint)
				}
			} else if (suspends("admin_space_left_action") || suspends("disk_full_action")) && (m.UsePct >= thr.DiskWarnPct || (adminMB > 0 && freeMB < adminMB*4)) {
				add(SevWarn, "security", name, fmt.Sprintf("auditd suspends logging when %s runs out of space (%s free, %d%% used): audit records are lost silently", m.Mountpoint, strutil.HumanBytes(float64(freeMB)*1024*1024), m.UsePct), "free space on "+m.Mountpoint+" or rotate audit logs")
			}
		}
	}

	// ---- noexec mounts ----
	if p.Probed {
		for _, path := range []string{dataDir, "/opt/cni", "/var/lib/kubelet"} {
			m := p.MountOpt(path)
			if m == nil || !m.Has("noexec") {
				continue
			}
			sev := SevCrit
			what := v.Binaries + " under " + path + " cannot execute"
			if path == "/var/lib/kubelet" {
				sev = SevWarn
				what = "pod volumes under /var/lib/kubelet cannot hold executables (init scripts, helper binaries)"
			}
			add(sev, "node", name, fmt.Sprintf("%s is on %s mounted noexec: %s", path, m.Mountpoint, what), "remount without noexec or give "+path+" its own mount; STIG only requires noexec on /tmp, /var/tmp, /dev/shm and removable media")
		}
	}

	// ---- accounts: password/account expiry and faillock ----
	if p.Probed && p.Today > 0 {
		sshUser := p.SudoUser
		if sshUser == "" {
			sshUser = in.Cfg.SSH.User
		}
		for _, a := range p.Accounts {
			role, sev := "user", SevInfo
			switch a.Name {
			case sshUser:
				role, sev = "ssh user", SevCrit
			case "root":
				role, sev = "root", SevWarn
			case "etcd":
				continue // nologin service account: aging does not affect the etcd process
			}
			if exp := a.PasswordExpiry(); exp > 0 {
				left := exp - p.Today
				grace := ""
				if a.Inactive >= 0 {
					grace = fmt.Sprintf(" (account locks %d days later)", a.Inactive)
				}
				switch {
				case left <= 0:
					s := sev
					if role == "user" {
						s = SevInfo
					}
					msg := fmt.Sprintf("password of %s %s expired %d days ago%s", role, a.Name, -left, grace)
					hint := "chage -M 99999 " + a.Name + " or set a new password; a service/ssh account should use ssh keys with NOPASSWD sudo"
					if role == "ssh user" {
						msg += ": sudo/password prompts break collection and any SSH-driven provisioning"
					}
					add(s, "security", name, msg, hint)
				case left <= 14:
					s := SevWarn
					if role == "user" {
						s = SevInfo
					}
					add(s, "security", name, fmt.Sprintf("password of %s %s expires in %d days%s", role, a.Name, left, grace), "chage -l "+a.Name+"; rotate it or exempt the account from PASS_MAX_DAYS")
				}
			}
			if a.PW == "set" && a.LastChange == 0 && role != "user" {
				add(sev, "security", name, fmt.Sprintf("%s %s must change the password at next login (shadow lastchg=0): PAM forces an interactive passwd, so ssh/sudo automation fails", role, a.Name), "chage -d $(date +%Y-%m-%d) "+a.Name+" after setting a password, or -d -1 to disable aging")
			}
			if a.Expire > 0 && a.Expire <= p.Today {
				s := sev
				if role == "user" {
					s = SevWarn
				}
				add(s, "security", name, fmt.Sprintf("account %s %s expired %d days ago: logins are refused", role, a.Name, p.Today-a.Expire), "chage -E -1 "+a.Name)
			}
			if a.PW == "locked" && role == "ssh user" {
				add(SevInfo, "security", name, "password of ssh user "+a.Name+" is locked: key logins work, password sudo does not", "keep NOPASSWD sudo for this account")
			}
		}
		for user, n := range p.Faillock {
			if p.FaillockDeny > 0 && n >= p.FaillockDeny {
				sev := SevWarn
				if user == sshUser {
					sev = SevCrit
				}
				add(sev, "security", name, fmt.Sprintf("%s is locked out by pam_faillock (%d failed attempts, deny=%d)", user, n, p.FaillockDeny), "faillock --user "+user+" --reset; find the client retrying with stale credentials")
			}
		}
		// the provisioning user cloud-init created for Rancher: it must not be
		// subject to STIG password aging (no password, key auth) and must keep
		// NOPASSWD sudo, or Rancher/automation over SSH breaks when it rotates
		maxDays := strutil.AtoiOr(p.LoginDefs["PASS_MAX_DAYS"], 99999)
		for _, u := range provisioningUsers(p) {
			a := p.Account(u)
			if a == nil {
				continue
			}
			sudo, hasSudo := p.Sudo[u]
			switch {
			case a.PW == "set" && a.Max >= 0 && a.Max < 99999:
				add(SevWarn, "security", name, fmt.Sprintf("provisioning user %s (cloud-init) has a password with aging (max %d days, PASS_MAX_DAYS=%d): the STIG rotation policy expires it and SSH/sudo automation as this user stops working", u, a.Max, maxDays), "passwd -l "+u+" (key-only login, no password to age) and keep NOPASSWD sudo; or make it a system account (useradd -r) with no password; cloud-init: lock_passwd: true")
			case a.PW == "set":
				add(SevInfo, "security", name, fmt.Sprintf("provisioning user %s has a password exempt from aging (max %d): STIG scanners flag it (RHEL-08-020200); lock the password instead", u, a.Max), "passwd -l "+u)
			}
			if hasSudo && !sudo.NoPasswd {
				if a.PW != "set" {
					add(SevCrit, "security", name, "provisioning user "+u+" has no password and no NOPASSWD sudo rule: sudo asks for a password that does not exist, so Rancher/automation over SSH cannot escalate (STIG RHEL-08-010380 removed NOPASSWD?)", "restore /etc/sudoers.d/90-cloud-init-users: "+u+" ALL=(ALL) NOPASSWD:ALL, or exempt this account in the STIG remediation")
				} else {
					add(SevWarn, "security", name, "provisioning user "+u+" must type its password for sudo: SSH automation must supply it and it rotates with the STIG policy", "NOPASSWD sudo for the provisioning account, or use a service account with key auth")
				}
			}
			if hasSudo && sudo.Keys == 0 && a.PW != "set" {
				add(SevWarn, "security", name, "provisioning user "+u+" has neither a password nor authorized_keys: no way to log in as it", "")
			}
		}
		// etcd user (rke2 CIS/STIG profile): a system account, nologin, no password
		if strings.Contains(ni.Settings["profile"], "cis") && ni.ControlPlane && !ni.EtcdUser {
			add(SevCrit, "security", name, "profile: cis is set but there is no etcd user on the host: "+v.Server+" refuses to start (CIS pre-flight)", "useradd -r -c 'etcd user' -s /sbin/nologin -M etcd -U")
		}
		if e := p.Account("etcd"); e != nil {
			var bad []string
			if e.UID >= 1000 {
				bad = append(bad, fmt.Sprintf("uid %d is not a system uid", e.UID))
			}
			if !strings.HasSuffix(e.Shell, "nologin") && !strings.HasSuffix(e.Shell, "false") {
				bad = append(bad, "shell "+e.Shell)
			}
			if e.PW == "set" {
				bad = append(bad, "has a password (aging applies)")
			}
			if len(bad) > 0 {
				add(SevWarn, "security", name, "etcd user does not match the RKE2 STIG (useradd -r -s /sbin/nologin -M etcd -U): "+strings.Join(bad, ", "), "usermod -s /sbin/nologin etcd; passwd -l etcd; the etcd process runs as its uid and never logs in")
			}
			if ni.ControlPlane {
				if perm := ni.Perm(dataDir + "/server/db/etcd"); perm != nil && (perm.User != "etcd" || perm.Group != "etcd") {
					add(SevWarn, "security", name, fmt.Sprintf("etcd data directory is owned by %s:%s, not etcd:etcd (RKE2 STIG / CIS 1.1.12)", perm.User, perm.Group), "chown -R etcd:etcd "+dataDir+"/server/db/etcd")
				}
			}
		}
	}

	// ---- proxies ----
	if p.Probed && len(p.Proxy) > 0 {
		var proxySet, noProxy []string
		var files []string
		for _, l := range p.Proxy {
			switch l.Key {
			case "HTTP_PROXY", "HTTPS_PROXY", "CONTAINERD_HTTP_PROXY", "CONTAINERD_HTTPS_PROXY":
				if l.Value != "" {
					proxySet = append(proxySet, l.Key)
					files = append(files, l.File)
				}
			case "NO_PROXY", "CONTAINERD_NO_PROXY":
				noProxy = append(noProxy, strings.Split(l.Value, ",")...)
			}
		}
		if len(proxySet) > 0 {
			if len(noProxy) == 0 {
				add(SevWarn, "node", name, strings.Join(strutil.Uniq(proxySet), ",")+" set in "+strutil.Uniq(files)[0]+" without NO_PROXY: node-to-node traffic (supervisor 9345, kubelet 10250, etcd) goes through the proxy", "add NO_PROXY=127.0.0.0/8,<node CIDRs>,<cluster/service CIDRs>,.svc,.cluster.local")
			} else if in.Snap != nil {
				var uncovered []string
				for i := range in.Snap.Nodes {
					for _, ad := range in.Snap.Nodes[i].Status.Addresses {
						if ad.Type == corev1.NodeInternalIP && !noProxyCovers(noProxy, ad.Address) {
							uncovered = append(uncovered, ad.Address)
						}
					}
				}
				if len(uncovered) > 0 {
					add(SevWarn, "node", name, fmt.Sprintf("NO_PROXY does not cover node IPs %s: supervisor/kubelet/etcd traffic to them goes through the proxy", strutil.TruncList(uncovered, 4)), "add the node subnet to NO_PROXY in "+strutil.Uniq(files)[0]+" and "+v.Restart(ni.ControlPlane))
				}
			}
		}
	}

	// ---- vSphere: cloud-init ISO and VMware Tools ----
	if p.Probed {
		vm := p.Virt.VMware()
		ci := p.CloudInit
		seed := ci.Seed()
		var disabled []string
		for _, m := range p.Modprobe {
			if (m.Module == "cdrom" || m.Module == "sr_mod" || m.Module == "isofs") && m.Disables() {
				if m.Directive == "blacklist" && p.Modules[m.Module] {
					continue // blacklist only stops autoload; it is loaded anyway
				}
				disabled = append(disabled, m.File+": "+m.Line)
			}
		}
		if len(disabled) > 0 && ci.Installed {
			switch {
			case strings.HasPrefix(seed, "/dev/sr"):
				add(SevCrit, "node", name, "cloud-init read its NoCloud seed from "+seed+" (the Rancher user-data ISO on the virtual CD-ROM) but "+disabled[0]+" disables the CD-ROM driver: after a reboot cloud-init finds no datasource (hostname, network, users, ssh keys and the rke2 registration are not reapplied) and VMs provisioned from this image never come up", "drop the cdrom/sr_mod/isofs lines from modprobe.d (the STIG asks for usb-storage, not cdrom); keep the ISO attached")
			case vm:
				add(SevWarn, "node", name, disabled[0]+" disables the CD-ROM driver on a VMware VM with cloud-init: Rancher's vSphere driver delivers cloud-init as an ISO on a virtual CD-ROM (NoCloud), so machines built from this image cannot be provisioned", "remove the cdrom/sr_mod/isofs modprobe lines if this image is used for Rancher vSphere provisioning")
			default:
				add(SevInfo, "node", name, disabled[0]+" disables the CD-ROM driver: cloud-init NoCloud ISO datasources will not work on this image", "")
			}
		}
		if strings.HasPrefix(seed, "/dev/sr") && ci.DatasourceList != "" && !strings.Contains(ci.DatasourceList, "NoCloud") {
			add(SevWarn, "node", name, "cloud-init datasource_list "+ci.DatasourceList+" excludes NoCloud but this node was seeded from "+seed, "add NoCloud to datasource_list in /etc/cloud/cloud.cfg.d")
		}
		if len(ci.Errors) > 0 {
			add(SevWarn, "node", name, "cloud-init reported errors: "+strutil.TruncList(ci.Errors, 2), "cloud-init status --long; /var/log/cloud-init.log")
		} else if len(ci.ResultErrors) > 0 {
			add(SevWarn, "node", name, "cloud-init result.json lists errors: "+strutil.TruncList(ci.ResultErrors, 2), "cloud-init status --long; /var/log/cloud-init.log")
		} else if len(ci.LogErrors) > 0 {
			add(SevWarn, "node", name, "cloud-init.log has errors: "+strutil.TruncStr(ci.LogErrors[len(ci.LogErrors)-1], 200), `grep -E '\[(ERROR|CRITICAL)\]' /var/log/cloud-init.log`)
		}
		if fu := ci.FailedUnits(); len(fu) > 0 {
			add(SevWarn, "node", name, "cloud-init units failed on the last boot: "+strings.Join(fu, ", ")+" - the Rancher user-data (users, ssh keys, rke2 registration) may be half-applied", "journalctl -u "+strings.Fields(fu[0])[0]+"; cloud-init status --long")
		}
		if vm {
			switch {
			case !p.Virt.VMTools:
				add(SevWarn, "node", name, "VMware VM without open-vm-tools: Rancher's vSphere driver waits for the VM IP through VMware Tools, so provisioning and machine health checks hang and guest shutdown is not graceful", "install open-vm-tools and enable vmtoolsd")
			case !p.Units["vmtoolsd.service"].Active && !p.Units["open-vm-tools.service"].Active:
				add(SevWarn, "node", name, "vmtoolsd is not running on this VMware VM: Rancher cannot read the VM IP or shut the guest down gracefully", "systemctl enable --now vmtoolsd")
			}
		}
	}

	// ---- firewalld / NetworkManager / nm-cloud-setup ----
	cni := strings.ToLower(ni.Settings["cni"])
	if cni == "" {
		for _, c := range ni.CNI {
			cni += strings.ToLower(c.Name + " " + strings.Join(c.Types, " "))
		}
		if cni == "" {
			cni = "canal"
		}
	}
	calicoLike := strings.Contains(cni, "canal") || strings.Contains(cni, "calico") || strings.Contains(cni, "flannel")
	if isRancher && (p.Units["firewalld.service"].Active || strings.HasPrefix(ni.ServiceState("firewalld"), "active")) && calicoLike {
		add(SevWarn, "node", name, "firewalld is active: the RKE2 docs require it disabled with Canal/Calico (its rule reloads break the CNI iptables chains)", "systemctl disable --now firewalld; use the CNI network policy or nftables rules that leave the cali*/KUBE-* chains alone")
	}
	if p.Probed && isRancher && p.Units["NetworkManager.service"].Active && calicoLike {
		managed := true
		for _, l := range p.NMUnmanaged {
			if strings.Contains(l, "cali") || strings.Contains(l, "flannel") || strings.Contains(l, "tunl") || strings.Contains(l, "vxlan") {
				managed = false
			}
		}
		if managed {
			add(SevWarn, "node", name, "NetworkManager manages the CNI interfaces (no unmanaged-devices for cali*/flannel*): it rewrites their routes and breaks pod connectivity after network events", "write /etc/NetworkManager/conf.d/rke2-canal.conf with [keyfile] unmanaged-devices=interface-name:cali*;interface-name:flannel*;interface-name:tunl*;interface-name:vxlan.calico and reload NetworkManager")
		}
		if u := p.Units["nm-cloud-setup.service"]; u.Active || u.Enabled || p.Units["nm-cloud-setup.timer"].Active || p.Units["nm-cloud-setup.timer"].Enabled {
			add(SevWarn, "node", name, "nm-cloud-setup is enabled: it resets routing tables and breaks Canal/Calico (RKE2 known issue on RHEL 8.4+)", "systemctl disable --now nm-cloud-setup.service nm-cloud-setup.timer; reboot")
		}
	}

	// ---- iptables version ----
	if p.Probed && p.Iptables != "" {
		if m := iptablesVer.FindStringSubmatch(p.Iptables); m != nil {
			maj, _ := strconv.Atoi(m[1])
			min, _ := strconv.Atoi(m[2])
			pat, _ := strconv.Atoi(m[3])
			if (maj == 1 && min == 8 && pat <= 4) || (maj == 1 && min == 6 && pat == 1) {
				add(SevWarn, "node", name, "host iptables "+m[0]+" has known bugs (1.6.1 and 1.8.0-1.8.4 corrupt rule sets); the CNI can still fall back to its own copy", "upgrade iptables to >= 1.8.5 or remove the host package so the CNI uses its bundled version")
			}
		}
	}

	// ---- SELinux packages ----
	if p.Probed && ni.SELinux == "Enforcing" && isRancher && len(p.SEPkgs) > 0 {
		missing := map[string]bool{}
		for _, l := range p.SEPkgs {
			if strings.HasSuffix(l, "is not installed") {
				missing[strings.Fields(l)[1]] = true
			}
		}
		sev := SevWarn
		if ni.Settings["selinux"] == "true" {
			sev = SevCrit
		}
		if missing["container-selinux"] || (ni.Dist == "rke2" && missing["rke2-selinux"]) || (ni.Dist == "k3s" && missing["k3s-selinux"]) {
			add(sev, "node", name, "SELinux is enforcing but the "+ni.Dist+"-selinux/container-selinux policy packages are not installed: containers and the runtime run with the wrong labels and get denied", "dnf install "+ni.Dist+"-selinux container-selinux from the rancher repo (or use the RPM install), then restart "+ni.Dist)
		}
		// a Rancher-provisioned node also runs rancher-system-agent, which
		// has its own policy package; a plain rke2 node needs rke2-selinux only
		if provisioned := ni.Rancher.Provisioned || ni.Service("rancher-system-agent") != nil; provisioned && missing["rancher-selinux"] {
			add(sev, "node", name, "SELinux is enforcing on a Rancher-provisioned node but rancher-selinux is not installed: rancher-system-agent runs unlabeled and its plans (config, registries, manifests) are denied", "dnf install rancher-selinux (rancher rpm repo), then systemctl restart rancher-system-agent; a non-Rancher rke2 node needs rke2-selinux only")
		}
		// the other way round: the host and rke2 are confined, the pods are
		// not - selinux: true is what makes containerd label containers
		// (container_t with MCS categories); without it they run unconfined
		// however hardened the host looks
		if !missing["container-selinux"] && !missing[ni.Dist+"-selinux"] && ni.Settings["selinux"] != "true" {
			add(SevWarn, "node", name, "SELinux is enforcing and the policy packages are installed, but "+v.ConfigName+" has no selinux: true: containerd runs the pods unconfined (no container_t label), the host policy protects "+ni.Dist+" only", "add selinux: true to "+v.ConfigFile+" and restart "+v.Server+" / "+v.Agent+" (one node at a time; pods restart with labels)")
		}
	}

	// ---- sysctls that stop routing / kubelet ----
	if fwd, ok := ni.Sysctl["net.ipv4.ip_forward"]; ok && fwd == "0" {
		add(SevCrit, "node", name, "net.ipv4.ip_forward=0: pod traffic is not routed through this node (Wicked/NetworkManager or a sysctl.d drop-in reset it)", "sysctl -w net.ipv4.ip_forward=1 and persist it in /etc/sysctl.d/90-"+v.Name+".conf")
	}
	if v := ni.Sysctl["fs.inotify.max_user_instances"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n < 8192 {
			add(SevInfo, "node", name, fmt.Sprintf("fs.inotify.max_user_instances=%d (8192 recommended for nodes with many pods or log watchers)", n), "echo 'fs.inotify.max_user_instances = 8192' > /etc/sysctl.d/99-inotify.conf; sysctl --system")
		}
	}

	// ---- cloud provider / CSI on this node ----
	if in.Snap != nil {
		evalCloudNode(name, ni, in, in.Snap.Cloud(), add)
	}

	// ---- private registries ----
	if p.Probed {
		for _, f := range p.RegFiles {
			if f.Missing {
				add(SevCrit, "images", name, fmt.Sprintf("registries.yaml configs %s: %s %s does not exist, TLS to that registry fails", f.Key, f.Kind, f.Path), "restore the file or fix the path in "+v.Registries+", then "+v.RegistryReload)
			}
		}
		mismatches, badKeys := registryKeyMismatches(ni.Registries)
		for _, r := range p.RegProbes {
			if badKeys[r.Host] {
				continue // the key names no endpoint; the mismatch finding below explains it
			}
			if msg, hint, sev, ok := regVerdict(r, v); ok {
				add(sev, "images", name, msg, hint)
			}
		}
		if p.CurlMissing && len(ni.RegistryMirrors) > 0 {
			add(SevInfo, "images", name, "curl is not installed on the node: registry credentials in registries.yaml were not probed", "")
		}
		for _, m := range mismatches {
			add(SevWarn, "images", name, m, "the configs key must equal the endpoint host:port exactly, port included, or containerd never sends the credentials/TLS settings")
		}
	}

	// ---- registry pull dry run through containerd (heavy) ----
	if p.PullsProbed {
		if p.CrictlMissing && len(ni.RegistryMirrors) > 0 {
			add(SevInfo, "images", name, "crictl is not on the node: the registry mirrors were not pull-tested through containerd", "")
		}
		for _, r := range p.Pulls {
			if msg, hint, sev, ok := pullVerdict(r, p, len(ni.Tarballs) > 0, dataDir, v); ok {
				add(sev, "images", name, msg, hint)
			}
		}
	}
}

// pullVerdict interprets one crictl pull dry run (RegPull). The detail is
// containerd's error and the host it names is the one that failed: a mirror
// endpoint, or the registry itself after every mirror answered 404 (the
// image is not on the mirror and containerd fell through). The curl probe
// of the same host tells the two sides apart: curl reads registries.yaml,
// containerd the hosts.toml rendered from it.
func pullVerdict(r nodeinfo.RegPull, p *nodeinfo.Preflight, airgap bool, dataDir string, v distro.Vocab) (msg, hint string, sev Severity, ok bool) {
	if r.OK || r.Skipped != "" {
		return "", "", 0, false
	}
	low := strings.ToLower(r.Detail)
	failed := pullFailedHost(r.Detail)
	via := "registry " + r.Registry
	if len(r.Endpoints) > 0 {
		via += " through its mirror " + strings.Join(r.Endpoints, ", ")
	}
	hostsToml := "/etc/containerd/certs.d/" + r.Registry + "/hosts.toml"
	if distro.IsRancher(v.Name) {
		hostsToml = dataDir + "/agent/etc/containerd/certs.d/" + r.Registry + "/hosts.toml"
	}
	curlNote := ""
	if failed != "" && curlReached(p, failed) {
		curlNote = "; curl from the node with the registries.yaml settings reaches " + failed + ", so the rendered " + hostsToml + " is what differs"
	}
	fixHint := "compare " + hostsToml + " with " + v.Registries + " and the containerd log, then " + v.RegistryReload
	img := shortRef(r.Image)
	switch {
	case len(r.Endpoints) > 0 && failed != "" && !hostIn(failed, r.Endpoints):
		// every mirror answered 404 and the fallback to the registry itself failed
		if airgap {
			return fmt.Sprintf("mirror %s does not hold %s (404) and containerd fell through to %s, unreachable from this airgapped node: images the mirror lacks cannot be pulled again", strings.Join(r.Endpoints, ", "), img, failed), "push the images the node runs to the mirror, or ignore when they only ever come from the agent/images tarballs", SevInfo, true
		}
		return fmt.Sprintf("mirror %s does not hold %s (404) and containerd fell through to %s, which failed: %s", strings.Join(r.Endpoints, ", "), img, failed, r.Detail), "push the image to the mirror, or fix the node's path to " + failed, SevWarn, true
	case strings.Contains(low, "unauthorized") || pullStatus(low, "401"):
		return fmt.Sprintf("containerd cannot pull from %s: authentication rejected (%s)%s", via, r.Detail, curlNote), "the configs entry whose key equals the endpoint host:port is what becomes the auth header; " + fixHint, SevCrit, true
	case strings.Contains(low, "forbidden") || pullStatus(low, "403") || strings.Contains(low, "denied"):
		return fmt.Sprintf("containerd is refused by %s: %s%s", via, r.Detail, curlNote), "check the robot account's project permissions / registry ACLs", SevWarn, true
	case strings.Contains(low, "not found"):
		return fmt.Sprintf("%s no longer serves %s (not found): the node runs an image that cannot be pulled again", via, img), "the image was deleted or garbage-collected on the registry; push it back before the node needs it", SevInfo, true
	case strings.Contains(low, "timed out"):
		return fmt.Sprintf("containerd's pull from %s timed out%s", via, curlNote), fixHint, SevWarn, true
	}
	return fmt.Sprintf("containerd cannot pull from %s: %s%s", via, r.Detail, curlNote), fixHint, SevWarn, true
}

// pullStatus says whether the error carries this HTTP status as a word
// (a bare "401" could as well be three digits of a digest).
func pullStatus(low, code string) bool {
	return regexp.MustCompile(`(^|[^0-9a-f])` + code + `($|[^0-9a-f])`).MatchString(low)
}

// shortRef trims a digest reference to 12 hex digits for prose.
func shortRef(ref string) string {
	if i := strings.Index(ref, "@sha256:"); i > 0 {
		return ref[:min(len(ref), i+8+12)]
	}
	return ref
}

var pullHostRe = []*regexp.Regexp{
	regexp.MustCompile(`https?://([^/"\s]+)`),
	regexp.MustCompile(`pulling from host (\S+) failed`),
	regexp.MustCompile(`lookup ([^\s:]+)`),
}

// pullFailedHost extracts the host containerd's error names.
func pullFailedHost(detail string) string {
	for _, re := range pullHostRe {
		if m := re.FindStringSubmatch(detail); m != nil {
			return m[1]
		}
	}
	return ""
}

// hostIn matches a host against a list, with and without the default port.
func hostIn(h string, list []string) bool {
	for _, e := range list {
		if e == h || strings.TrimSuffix(e, ":443") == strings.TrimSuffix(h, ":443") {
			return true
		}
	}
	return false
}

// curlReached says whether the curl probe of the same host got an answer
// that means "reachable and, if credentials were needed, accepted".
func curlReached(p *nodeinfo.Preflight, host string) bool {
	for _, r := range p.RegProbes {
		if !hostIn(r.Host, []string{host}) {
			continue
		}
		if r.Code == 200 || (r.Code == 401 && r.TokenCode == 200) {
			return true
		}
	}
	return false
}

var iptablesVer = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

func ruleDir(rule string) string {
	if i := strings.Index(rule, "dir="); i >= 0 {
		d := rule[i+4:]
		if j := strings.IndexAny(d, " \t"); j >= 0 {
			d = d[:j]
		}
		return d
	}
	return ""
}

// csiDirInUse reports whether the driver that executes from dir is present:
// registered with this node's kubelet (plugins_registry), else installed in
// the cluster (CSIDriver objects). FlexVolume dirs have no driver object to
// check and count when present.
func csiDirInUse(dir string, nodeDrivers []string, snap *k8s.Snapshot) bool {
	var want []string
	switch {
	case strings.HasPrefix(dir, "/var/lib/longhorn"):
		want = []string{"longhorn"}
	case strings.HasPrefix(dir, "/opt/pwx"):
		want = []string{"portworx", "pxd"}
	case strings.HasPrefix(dir, "/var/lib/rook"):
		want = []string{"ceph"}
	case strings.HasPrefix(dir, "/var/lib/trident"):
		want = []string{"trident"}
	case strings.HasPrefix(dir, "/var/openebs"):
		want = []string{"openebs"}
	default:
		return true
	}
	var names []string
	names = append(names, nodeDrivers...)
	if snap != nil {
		for i := range snap.CSIDrivers {
			names = append(names, snap.CSIDrivers[i].Name)
		}
	}
	for _, n := range names {
		for _, w := range want {
			if strings.Contains(strings.ToLower(n), w) {
				return true
			}
		}
	}
	return false
}

// csiOwner names the storage driver that executes from a host directory.
func csiOwner(dir string) string {
	switch {
	case strings.HasPrefix(dir, "/var/lib/longhorn"):
		return "Longhorn (engine binaries the instance-manager runs from the host filesystem)"
	case strings.HasPrefix(dir, "/opt/pwx"):
		return "Portworx"
	case strings.Contains(dir, "volumeplugins") || strings.Contains(dir, "kubelet-plugins"):
		return "FlexVolume / kubelet volume plugins"
	case strings.HasPrefix(dir, "/var/lib/rook"):
		return "Rook/Ceph"
	case strings.HasPrefix(dir, "/var/lib/trident"):
		return "NetApp Trident"
	case strings.HasPrefix(dir, "/var/openebs"):
		return "OpenEBS"
	}
	return "a storage driver"
}

func k8sPath(path, dataDir string) bool {
	for _, pre := range []string{dataDir, "/var/lib/rancher", "/opt/cni", "/var/lib/kubelet", "/run/k3s", "/usr/local/bin/rke2", "/usr/local/bin/k3s", "/usr/bin/rke2", "/var/lib/longhorn", "/opt/pwx", "/var/lib/rook", "/var/lib/trident", "/var/openebs"} {
		if strings.HasPrefix(path, pre) {
			return true
		}
	}
	return strings.Contains(path, "containerd") || strings.Contains(path, "runc")
}

// auditMB turns an auditd space threshold ("250", "25%" of the partition)
// into megabytes.
func auditMB(v string, sizeKB int64) int64 {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "%") {
		pct, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64)
		if err != nil {
			return 0
		}
		return int64(float64(sizeKB) / 1024 * pct / 100)
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func noProxyCovers(entries []string, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	for _, e := range entries {
		e = strings.TrimSpace(strings.Trim(e, `"'`))
		if e == "" {
			continue
		}
		if e == "*" || e == ip {
			return true
		}
		if pfx, err := netip.ParsePrefix(e); err == nil && pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// provisioningUsers are the accounts cloud-init created for the platform
// (Rancher's vSphere/AWS templates): sudoers.d/90-cloud-init-users entries,
// the image's default_user when it has an account, and the ssh user when
// it is one of them.
func provisioningUsers(p *nodeinfo.Preflight) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range append(append([]string{}, p.CIUsers...), p.CIDefault) {
		if u == "" || u == "root" || seen[u] || p.Account(u) == nil {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// regVerdict interprets one curl probe of a registry endpoint.
func regVerdict(r nodeinfo.RegProbe, v distro.Vocab) (msg, hint string, sev Severity, ok bool) {
	where := r.Host
	if r.Skipped != "" {
		return "", "", SevInfo, false
	}
	if r.Implicit {
		where += " (no mirror endpoint in registries.yaml: containerd pulls from the registry itself)"
	}
	if r.Exit != 0 && r.Code == 0 {
		reason := map[int]string{
			6: "cannot resolve the host (DNS)", 7: "connection refused", 28: "timed out", 35: "TLS handshake failed (plain HTTP endpoint declared https, or FIPS/cipher mismatch)",
			51: "certificate name does not match the host", 56: "connection reset", 58: "client certificate (cert_file/key_file) rejected", 60: "certificate not trusted",
		}[r.Exit]
		if reason == "" {
			reason = fmt.Sprintf("curl exit %d", r.Exit)
		}
		hint = "check the endpoint in registries.yaml, DNS/proxy from the node, and the registry"
		if r.Exit == 60 {
			hint = "set ca_file (the registry CA) under configs in " + v.Registries + ", or insecure_skip_verify: true"
		}
		return fmt.Sprintf("registry %s unreachable from the node: %s (%s)", where, reason, r.URL), hint, SevWarn, true
	}
	authNote := "registries.yaml has no credentials for it"
	if r.Auth {
		authNote = "the credentials in registries.yaml"
	}
	switch {
	case r.Code == 200:
		return "", "", 0, false
	case r.Code == 401 && r.TokenCode == 200:
		return "", "", 0, false
	case r.Code == 401 && r.Auth:
		return fmt.Sprintf("registry %s rejects %s (HTTP 401): image pulls from it fail once the local cache misses", where, authNote), "rotate the username/password (robot token) in " + v.Registries + " on every node and " + v.RegistryReload + "; check the configs key matches the endpoint host:port", SevCrit, true
	case r.Code == 401:
		return fmt.Sprintf("registry %s requires authentication and %s (HTTP 401)", where, authNote), "add a configs entry with auth.username/password for " + where + " in " + v.Registries, SevWarn, true
	case r.Code == 403:
		return fmt.Sprintf("registry %s refuses the request (HTTP 403): the account lacks pull permission or the node IP is denied", where), "check the robot account's project permissions / registry ACLs", SevWarn, true
	case r.Code == 404:
		return fmt.Sprintf("registry %s: no /v2/ API at %s (wrong path or port in the endpoint?)", where, r.URL), "endpoints are scheme://host:port; containerd appends /v2 itself", SevWarn, true
	case r.Code >= 300 && r.Code < 400:
		return fmt.Sprintf("registry %s redirects /v2/ (HTTP %d): the endpoint is probably http:// on an https-only registry or the reverse", where, r.Code), "use the scheme the registry actually serves in registries.yaml", SevWarn, true
	case r.Code >= 500:
		return fmt.Sprintf("registry %s returns HTTP %d", where, r.Code), "the registry itself is unhealthy", SevWarn, true
	}
	return "", "", 0, false
}

// registryKeyMismatches finds configs keys that differ from a mirror
// endpoint host only by the port (the classic "credentials never used"
// registries.yaml mistake).
func registryKeyMismatches(files []nodeinfo.ConfigFile) ([]string, map[string]bool) {
	var out []string
	bad := map[string]bool{}
	for _, cf := range files {
		var endpoints, keys []string
		top, reg := "", ""
		for _, l := range strings.Split(cf.Content, "\n") {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			ind := len(l) - len(strings.TrimLeft(l, " \t"))
			switch {
			case ind == 0:
				top = strings.TrimSuffix(strings.Fields(t)[0], ":")
			case ind == 2 && strings.HasSuffix(t, ":"):
				reg = strings.Trim(strings.TrimSuffix(t, ":"), `"'`)
				if top == "configs" && reg != "*" {
					keys = append(keys, reg)
				}
			case top == "mirrors" && strings.HasPrefix(t, "-"):
				e := strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "-")), `"'`)
				e = strings.TrimPrefix(strings.TrimPrefix(e, "https://"), "http://")
				if i := strings.Index(e, "/"); i >= 0 {
					e = e[:i]
				}
				if e != "" {
					endpoints = append(endpoints, e)
				}
			}
		}
		for _, k := range keys {
			exact := false
			for _, e := range endpoints {
				if e == k {
					exact = true
				}
			}
			if exact {
				continue
			}
			kh, _, _ := strings.Cut(k, ":")
			for _, e := range endpoints {
				eh, _, _ := strings.Cut(e, ":")
				if eh == kh && e != k {
					out = append(out, fmt.Sprintf("registries.yaml configs key %q does not match mirror endpoint %q (port differs): its auth/TLS settings are never applied", k, e))
					bad[k] = true
					break
				}
			}
		}
	}
	return out, bad
}

// preflightNodeRows summarizes the preflight facts for the node detail view:
// FIELD, VALUE, STATE rows.
func PreflightRows(ni *nodeinfo.Info, cfg config.Config, now time.Time) [][3]string {
	var rows [][3]string
	p := &ni.Preflight
	row := func(k, v, state string) { rows = append(rows, [3]string{k, v, state}) }
	if len(p.Swaps) > 0 {
		var devs []string
		for _, s := range p.Swaps {
			devs = append(devs, fmt.Sprintf("%s %s", s.Name, strutil.HumanBytes(float64(s.SizeKB)*1024)))
		}
		row("swap", strings.Join(devs, ", "), "warn")
	} else {
		st := "ok"
		v := "off"
		if len(p.FstabSwap) > 0 {
			v, st = "off (still in /etc/fstab)", "warn"
		}
		row("swap", v, st)
	}
	if !p.Probed {
		return rows
	}
	if p.Fapolicyd.Present {
		v := fmt.Sprintf("rules.d %d files, %d %s rules, compiled mentions %d", len(p.Fapolicyd.RulesFiles), len(p.Fapolicyd.K8sRules), distro.For(ni.Dist).Name, p.Fapolicyd.CompiledK8s)
		st := "ok"
		if p.Units["fapolicyd.service"].Active && (len(p.Fapolicyd.K8sRules) == 0 || p.Fapolicyd.CompiledK8s == 0) {
			st = "crit"
		} else if !p.Units["fapolicyd.service"].Active {
			v += " (inactive)"
		}
		if p.Fapolicyd.Permissive == "1" {
			v += ", permissive"
		}
		row("fapolicyd", v, st)
		if p.DeniesProbed {
			n := 0
			for _, d := range p.Denies {
				n += d.Count
			}
			st := "ok"
			if n > 0 {
				st = "warn"
			}
			row("fapolicyd denials today", fmt.Sprint(n), st)
		}
	}
	if len(p.CSI.Drivers) > 0 {
		v := strings.Join(p.CSI.Drivers, ", ")
		st := "ok"
		if len(p.CSI.HostDirs) > 0 {
			v += "; host dirs " + strings.Join(p.CSI.HostDirs, ",")
			if p.Units["fapolicyd.service"].Active && p.Fapolicyd.Permissive != "1" {
				for _, d := range p.CSI.HostDirs {
					if _, ok := p.Fapolicyd.Covers(d); !ok && d != "/var/lib/longhorn" {
						st = "crit"
					}
				}
			}
		}
		if p.CSI.Has("longhorn") && !p.CSI.ISCSID {
			v, st = v+"; iscsid inactive", "warn"
		}
		row("csi drivers", v, st)
	}
	if len(p.Auditd) > 0 {
		var parts []string
		for _, k := range []string{"space_left_action", "admin_space_left_action", "disk_full_action", "max_log_file_action"} {
			if v := p.Auditd[k]; v != "" {
				parts = append(parts, k+"="+v)
			}
		}
		st := "ok"
		for _, k := range []string{"admin_space_left_action", "disk_full_action", "disk_error_action"} {
			a := strings.ToLower(p.Auditd[k])
			if a == "halt" || a == "single" || a == "suspend" {
				st = "warn"
			}
		}
		row("auditd disk actions", strings.Join(parts, " "), st)
	}
	dataDir := ni.DataDir
	if dataDir == "" {
		dataDir = distro.For(ni.Dist).DataDir
	}
	for _, path := range []string{dataDir, "/opt/cni", "/var/lib/kubelet"} {
		if m := p.MountOpt(path); m != nil {
			st := "ok"
			if m.Has("noexec") {
				st = "crit"
			}
			row("mount "+path, m.Mountpoint+" "+m.Type+" "+strings.Join(m.Options, ","), st)
		}
	}
	sshUser := p.SudoUser
	if sshUser == "" {
		sshUser = cfg.SSH.User
	}
	for _, a := range p.Accounts {
		if a.Name != sshUser && a.Name != "root" {
			continue
		}
		v, st := a.PW, "ok"
		if exp := a.PasswordExpiry(); exp > 0 {
			left := exp - p.Today
			v = fmt.Sprintf("%s, password expires in %dd", a.PW, left)
			if left <= 0 {
				v, st = fmt.Sprintf("%s, password EXPIRED %dd ago", a.PW, -left), "crit"
			} else if left <= 14 {
				st = "warn"
			}
		} else if a.PW == "set" {
			v = "set, no expiry"
		}
		if a.Expire > 0 && a.Expire <= p.Today {
			v, st = v+", account expired", "crit"
		}
		if n := p.Faillock[a.Name]; n > 0 {
			v += fmt.Sprintf(", %d failed logins", n)
			if p.FaillockDeny > 0 && n >= p.FaillockDeny {
				v, st = v+" (LOCKED)", "crit"
			}
		}
		label := "account " + a.Name
		if a.Name == sshUser {
			label += " (ssh)"
		}
		row(label, v, st)
	}
	if p.Virt.Vendor != "" || p.Virt.Product != "" {
		v := strings.TrimSpace(p.Virt.Vendor + " " + p.Virt.Product)
		st := "ok"
		if p.Virt.VMware() {
			if !p.Virt.VMTools {
				v, st = v+", no open-vm-tools", "warn"
			} else if !p.Units["vmtoolsd.service"].Active && !p.Units["open-vm-tools.service"].Active {
				v, st = v+", vmtoolsd inactive", "warn"
			} else {
				v += ", vmtoolsd running"
			}
		}
		row("platform", v, st)
	}
	if p.Virt.AWS() && p.Virt.IMDS != "" {
		row("aws imds", "HTTP "+p.Virt.IMDS, map[bool]string{true: "ok", false: "crit"}[p.Virt.IMDS == "200"])
	}
	if p.Virt.VMware() {
		row("vsphere disk.EnableUUID", fmt.Sprintf("%d wwn disks", p.Virt.WWNDisks), map[bool]string{true: "ok", false: "warn"}[p.Virt.WWNDisks > 0])
	}
	for _, vc := range p.VCenters {
		v := fmt.Sprintf("HTTP %d", vc.Code)
		if vc.Code == 0 {
			v = fmt.Sprintf("unreachable (curl exit %d)", vc.Exit)
		}
		row("vcenter "+vc.Host, v, map[bool]string{true: "ok", false: "crit"}[vc.Code > 0])
	}
	for _, u := range provisioningUsers(p) {
		a := p.Account(u)
		s := p.Sudo[u]
		v := fmt.Sprintf("password %s, sudo nopasswd=%v, %d keys", a.PW, s.NoPasswd, s.Keys)
		st := "ok"
		if a.PW == "set" || !s.NoPasswd {
			st = "warn"
		}
		row("provisioning user "+u, v, st)
	}
	if p.CloudInit.Installed {
		v := p.CloudInit.Datasource
		if v == "" {
			v = "installed, no datasource recorded"
		}
		st := "ok"
		if len(p.CloudInit.Errors) > 0 {
			v, st = v+", errors: "+strutil.TruncList(p.CloudInit.Errors, 1), "warn"
		} else if len(p.CloudInit.LogErrors) > 0 {
			v, st = v+", log errors", "warn"
		}
		if fu := p.CloudInit.FailedUnits(); len(fu) > 0 {
			v, st = v+", failed: "+strings.Join(fu, ","), "warn"
		}
		for _, m := range p.Modprobe {
			if (m.Module == "cdrom" || m.Module == "sr_mod" || m.Module == "isofs") && m.Disables() {
				v, st = v+", "+m.File+" "+m.Line, "crit"
				break
			}
		}
		row("cloud-init", v, st)
	}
	if len(p.Proxy) > 0 {
		var parts []string
		for _, l := range p.Proxy {
			parts = append(parts, l.Key+"="+l.Value)
		}
		row("proxy env", strutil.TruncList(parts, 3), "ok")
	}
	for _, r := range p.RegProbes {
		v := fmt.Sprintf("HTTP %d", r.Code)
		if r.Exit != 0 && r.Code == 0 {
			v = fmt.Sprintf("curl exit %d", r.Exit)
		}
		if r.TokenCode > 0 {
			v += fmt.Sprintf(", token %d", r.TokenCode)
		}
		if r.Auth {
			v += ", with credentials"
		}
		st := "ok"
		if r.Skipped == "airgap" {
			v, st = "not probed: node has airgap image tarballs, no egress attempted ("+r.URL+")", "dim"
		} else if _, _, sev, bad := regVerdict(r, distro.For(ni.Dist)); bad {
			st = "warn"
			if sev == SevCrit {
				st = "crit"
			}
		}
		row("registry "+r.Host, v, st)
	}
	for _, f := range p.RegFiles {
		if f.Missing {
			row("registry "+f.Key+" "+f.Kind, f.Path+" MISSING", "crit")
		}
	}
	if p.PullsProbed && p.CrictlMissing && len(ni.RegistryMirrors) > 0 {
		row("pull test", "no crictl on the node", "dim")
	}
	for _, r := range p.Pulls {
		img := shortRef(r.Image)
		via := "the registry itself"
		if len(r.Endpoints) > 0 {
			via = "mirror " + strings.Join(r.Endpoints, ", ")
		}
		switch {
		case r.Skipped == "airgap":
			row("pull "+r.Registry, "not tested: node has airgap image tarballs, no egress attempted", "dim")
		case r.Skipped != "":
			row("pull "+r.Registry, "not tested: "+r.Skipped, "dim")
		case r.OK && len(r.Endpoints) > 0:
			// containerd moves on to the next host on any error, so a pass
			// proves the chain (mirror, then the registry itself), not the
			// mirror alone: the curl probe rows above cover each endpoint
			row("pull "+r.Registry, "ok: containerd resolved "+img+" through "+via+" or the registry itself", "ok")
		case r.OK:
			row("pull "+r.Registry, "ok: containerd resolved "+img+" from the registry itself", "ok")
		default:
			st := "warn"
			if _, _, sev, bad := pullVerdict(r, p, len(ni.Tarballs) > 0, dataDir, distro.For(ni.Dist)); bad {
				if sev == SevCrit {
					st = "crit"
				} else if sev == SevInfo {
					st = "dim"
				}
			}
			row("pull "+r.Registry, "FAILED via "+via+": "+r.Detail, st)
		}
	}
	if p.Iptables != "" {
		row("iptables", p.Iptables, "ok")
	}
	return rows
}
