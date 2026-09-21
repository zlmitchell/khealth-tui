package nodeinfo

import (
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s-health-tui/internal/strutil"
)

// Preflight holds the facts scripts/preflight.sh collects: what stops rke2
// or k3s from (re)starting or the node from being re-provisioned although
// the OS itself is healthy. Swaps and Units are refreshed every probe; the
// rest comes with the config tier (Probed); Denies and Pulls with the
// heavy tier.
type Preflight struct {
	Swaps         []SwapDev
	Units         map[string]PFUnit // NetworkManager, nm-cloud-setup, vmtoolsd, cloud-init, multipathd, fapolicyd, auditd, firewalld
	Probed        bool
	FstabSwap     []string
	FailSwapOn    string // kubelet config failSwapOn from the drop-ins ("" when not set: upstream default true)
	SwapBehavior  string // kubelet memorySwap.swapBehavior
	MountOpts     []MountOpt
	Modprobe      []ModprobeLine  // install/blacklist lines from modprobe.d for the modules that matter
	Modules       map[string]bool // loaded kernel modules among the ones that matter
	Virt          VirtInfo
	CloudInit     CloudInit
	Fapolicyd     Fapolicyd
	Auditd        map[string]string // auditd.conf keys
	Accounts      []Account
	SudoUser      string // the ssh user (SUDO_USER on the node)
	Today         int    // days since the epoch on the node
	LoginDefs     map[string]string
	Faillock      map[string]int // user -> valid failed attempts
	FaillockDeny  int
	Proxy         []ProxyLine
	Iptables      string
	SEPkgs        []string // rpm -q rke2-selinux k3s-selinux container-selinux
	NMUnmanaged   []string
	RegProbes     []RegProbe
	RegFiles      []RegFile
	CurlMissing   bool
	Denies        []FapDeny // fapolicyd denials from the audit log (heavy)
	DeniesProbed  bool
	Pulls         []RegPull // crictl pull dry run per mirrored registry (heavy)
	PullsProbed   bool
	CrictlMissing bool // no crictl on the node: the pull dry run did not happen
	CSI           CSIInfo
	CIUsers       []string            // users cloud-init created (sudoers.d/90-cloud-init-users)
	CIDefault     string              // default_user from /etc/cloud/cloud.cfg
	Sudo          map[string]SudoInfo // ssh user and cloud-init users
	VCenters      []VCenterProbe
}

// CSIInfo is what storage drivers left on the host: the CSI node plugins
// registered with the kubelet and the directories drivers execute from
// (Longhorn engine binaries, Portworx, FlexVolume plugins).
type CSIInfo struct {
	Drivers            []string // e.g. driver.longhorn.io, csi.vsphere.vmware.com
	HostDirs           []string
	ISCSID             bool
	MultipathBlacklist int    // blacklist stanzas in /etc/multipath.conf (-1 when no file)
	FindMultipaths     string // multipath.conf find_multipaths (Trident iSCSI wants "no")
	MountNFS           bool   // mount.nfs present (NAS backends)
	// Longhorn block devices the node still presents (/dev/longhorn/<volume>)
	// and the iSCSI sessions behind them: compared with where the cluster
	// says each volume is attached, a device left on a node the cluster
	// gave up on is the split-brain case.
	LonghornDevs  []string
	ISCSISessions []ISCSISession
}

// ISCSISession is one entry of /sys/class/iscsi_session.
type ISCSISession struct {
	Target string // iqn
	State  string // LOGGED_IN, FAILED, ...
}

// LonghornVolume extracts the volume name from a Longhorn iSCSI target
// (iqn.2019-10.io.longhorn:<volume>), "" for other targets.
func (s ISCSISession) LonghornVolume() string {
	if i := strings.Index(s.Target, "io.longhorn:"); i >= 0 {
		return s.Target[i+len("io.longhorn:"):]
	}
	return ""
}

// SudoInfo is the sudo/ssh-key state of the ssh user and the cloud-init users.
type SudoInfo struct {
	NoPasswd bool
	Keys     int
}

// VCenterProbe is one curl to a vCenter SDK endpoint from the node.
type VCenterProbe struct {
	Host string
	Code int
	Exit int
}

// Has reports whether a CSI driver whose name contains s is registered.
func (c CSIInfo) Has(s string) bool {
	for _, d := range c.Drivers {
		if strings.Contains(d, s) {
			return true
		}
	}
	return false
}

// SwapDev is one /proc/swaps line.
type SwapDev struct {
	Name, Type     string
	SizeKB, UsedKB int64
}

// PFUnit is a unit's state read from /run/systemd without D-Bus.
type PFUnit struct {
	Active, Enabled bool
}

// MountOpt is a /proc/mounts entry.
type MountOpt struct {
	Mountpoint, Type string
	Options          []string
}

// Has reports whether the mount carries the option.
func (m MountOpt) Has(opt string) bool { return slices.Contains(m.Options, opt) }

// ModprobeLine is an install/blacklist directive.
type ModprobeLine struct {
	File, Directive, Module, Line string
}

// Disables reports whether the directive keeps the module from loading:
// a blacklist (no autoload) or an install line that runs /bin/false or
// /bin/true instead of modprobe. Wrappers like firewalld's
// "install nf_conntrack /sbin/modprobe --ignore-install ..." load it.
func (m ModprobeLine) Disables() bool {
	if m.Directive == "blacklist" {
		return true
	}
	f := strings.Fields(m.Line)
	if len(f) < 3 {
		return false
	}
	cmd := f[2]
	return cmd == "/bin/false" || cmd == "/bin/true" || cmd == "/usr/bin/false" || cmd == "/usr/bin/true" || cmd == "false" || cmd == "true"
}

// VirtInfo is the DMI vendor/product and the VMware tooling on the node.
type VirtInfo struct {
	Vendor, Product string
	VMTools         bool // vmtoolsd binary present
	SRDevs          []string
	CIData          string // block device labeled cidata (the NoCloud ISO)
	WWNDisks        int    // /dev/disk/by-id/wwn-* entries (vSphere disk.EnableUUID)
	IMDS            string // AWS: HTTP status of the IMDSv2 token request ("" when not probed)
}

// AWS reports whether the node is an EC2 instance.
func (v VirtInfo) AWS() bool { return strings.Contains(v.Vendor, "Amazon") }

// VMware reports whether the node is a vSphere VM.
func (v VirtInfo) VMware() bool {
	return strings.Contains(strings.ToLower(v.Vendor), "vmware") || strings.Contains(strings.ToLower(v.Product), "vmware")
}

// CloudInit is the cloud-init state on the node.
type CloudInit struct {
	Installed      bool
	Disabled       bool
	DatasourceList string
	Datasource     string   // /var/lib/cloud/instance/datasource, e.g. "DataSourceNoCloud [seed=/dev/sr0][dsmode=net]"
	Errors         []string // stage errors and recoverable ERRORs from /run/cloud-init/status.json
	Stage          string
	Units          []CloudInitUnit // cloud-init-local, cloud-init, cloud-config, cloud-final
	LogErrors      []string        // ERROR/CRITICAL/Traceback lines from /var/log/cloud-init.log (last 5)
	ResultErrors   []string        // errors from /run/cloud-init/result.json
}

// CloudInitUnit is one of the four cloud-init systemd units.
type CloudInitUnit struct {
	Name, Active, Sub, Result string
}

// FailedUnits returns the cloud-init units whose last run failed.
func (c CloudInit) FailedUnits() []string {
	var out []string
	for _, u := range c.Units {
		if u.Active == "failed" || (u.Result != "" && u.Result != "success") {
			out = append(out, u.Name+" ("+u.Result+")")
		}
	}
	return out
}

// Seed returns the device the NoCloud datasource read its data from.
func (c CloudInit) Seed() string {
	if i := strings.Index(c.Datasource, "seed="); i >= 0 {
		s := c.Datasource[i+5:]
		if j := strings.IndexAny(s, "]"); j >= 0 {
			s = s[:j]
		}
		return s
	}
	return ""
}

// Fapolicyd is the application allow-listing state.
type Fapolicyd struct {
	Present       bool
	Permissive    string
	RulesFiles    []string
	CompiledMtime int64
	RulesdMtime   int64
	DenyFile      string   // first rules.d file with a catch-all deny
	CompiledK8s   int      // rules mentioning rancher/k3s/kubelet/cni/containerd in compiled.rules
	AllowRules    []string // "file:rule" allow lines from rules.d with a dir= or path= object
	K8sRules      []string // the subset that names rke2/k3s/kubelet/cni/containerd paths
}

// Covers reports whether an allow rule's dir=/path= object contains path,
// and which rule.
func (f Fapolicyd) Covers(path string) (string, bool) {
	for _, r := range f.AllowRules {
		_, rule, _ := strings.Cut(r, ":")
		for _, key := range []string{"dir=", "path="} {
			i := strings.Index(rule, key)
			if i < 0 {
				continue
			}
			obj := rule[i+len(key):]
			if j := strings.IndexAny(obj, " 	"); j >= 0 {
				obj = obj[:j]
			}
			for _, o := range strings.Split(obj, ",") {
				o = strings.TrimSuffix(o, "/")
				if o != "" && (path == o || strings.HasPrefix(path, o+"/")) {
					return r, true
				}
			}
		}
	}
	return "", false
}

// Account is a login-capable (or otherwise relevant) user with its shadow
// ages; -1 means the field was empty. Never the hash.
type Account struct {
	Name, Shell, PW                              string // PW: set, locked, none
	UID                                          int
	LastChange, Min, Max, Warn, Inactive, Expire int
}

// PasswordExpiry returns the day (since the epoch) the password expires, or
// 0 when it does not.
func (a Account) PasswordExpiry() int {
	if a.PW != "set" || a.Max < 0 || a.Max >= 99999 || a.LastChange <= 0 {
		return 0
	}
	return a.LastChange + a.Max
}

// ProxyLine is a proxy variable from the rke2/k3s/containerd environment files.
type ProxyLine struct {
	File, Key, Value string
}

// RegProbe is one registry endpoint probed with curl.
type RegProbe struct {
	Host, URL string
	Code      int // HTTP status of GET /v2/ (0 when curl failed)
	Exit      int // curl exit code
	TokenCode int // HTTP status of the bearer token endpoint (0 when none)
	Auth, CA  bool
	Insecure  bool
	Implicit  bool   // registries.yaml only names the registry (no mirror endpoint): containerd would go to it directly
	Skipped   string // why the endpoint was not probed ("airgap": image tarballs on the node, no egress attempted)
}

// RegPull is one crictl pull dry run: an image the node already holds from
// a registry registries.yaml mirrors, pulled again by digest through
// containerd (manifest resolve only, nothing downloaded). Unlike RegProbe
// it goes through the hosts.toml rke2/k3s rendered, not registries.yaml.
type RegPull struct {
	Registry  string   // the mirrors: key
	Image     string   // the digest reference pulled ("" when skipped)
	Endpoints []string // mirror endpoint hosts registries.yaml lists (empty: containerd goes to the registry itself)
	OK        bool
	Skipped   string // why no pull was made ("airgap", "no image from this registry on the node")
	Detail    string // containerd's error when the pull failed
}

// RegFile is a TLS file registries.yaml names.
type RegFile struct {
	Key, Kind, Path string
	Missing         bool
}

// FapDeny is an aggregated fapolicyd denial.
type FapDeny struct {
	Count     int
	Last      time.Time
	Exe, Path string
}

func kvLines(s string) map[string]string {
	m := map[string]string{}
	for _, l := range nonEmpty(s) {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// parsePreflight fills info.Preflight from the PREFLIGHT sections.
func parsePreflight(info *Info, secs map[string]string) {
	p := &info.Preflight
	p.Units = map[string]PFUnit{}
	for _, l := range nonEmpty(secs["SWAPS"]) {
		f := strings.Fields(l)
		if len(f) >= 4 {
			sz, _ := strconv.ParseInt(f[2], 10, 64)
			used, _ := strconv.ParseInt(f[3], 10, 64)
			p.Swaps = append(p.Swaps, SwapDev{Name: f[0], Type: f[1], SizeKB: sz, UsedKB: used})
		}
	}
	for _, l := range nonEmpty(secs["PFUNITS"]) {
		f := strings.Split(l, "|")
		if len(f) == 3 {
			p.Units[f[0]] = PFUnit{Active: f[1] == "active", Enabled: f[2] == "enabled"}
		}
	}
	if _, ok := secs["MOUNTOPTS"]; !ok {
		parseHeavy(p, secs)
		return
	}
	p.Probed = true
	p.FstabSwap = nonEmpty(secs["FSTABSWAP"])
	for k, v := range kvLines(strings.ReplaceAll(secs["KUBELETSWAP"], ":", "=")) {
		switch k {
		case "failSwapOn":
			p.FailSwapOn = strings.Trim(v, `"`)
		case "swapBehavior":
			p.SwapBehavior = strings.Trim(v, `"`)
		}
	}
	for _, l := range nonEmpty(secs["MOUNTOPTS"]) {
		f := strings.Split(l, "|")
		if len(f) == 3 {
			p.MountOpts = append(p.MountOpts, MountOpt{Mountpoint: f[0], Type: f[1], Options: strings.Split(f[2], ",")})
		}
	}
	for _, l := range nonEmpty(secs["MODPROBE"]) {
		file, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) >= 2 {
			p.Modprobe = append(p.Modprobe, ModprobeLine{File: file, Directive: f[0], Module: strings.ReplaceAll(f[1], "-", "_"), Line: strings.TrimSpace(rest)})
		}
	}
	p.Modules = map[string]bool{}
	for _, l := range nonEmpty(secs["MODULES"]) {
		p.Modules[strings.TrimSpace(l)] = true
	}
	v := kvLines(secs["VIRT"])
	p.Virt = VirtInfo{Vendor: v["vendor"], Product: v["product"], VMTools: v["vmtoolsd"] == "yes", SRDevs: strings.Fields(v["srdev"]), CIData: strings.TrimSpace(v["cidata"]), WWNDisks: strutil.AtoiOr(v["wwn"], 0), IMDS: v["imds"]}
	p.CloudInit = CloudInit{Installed: v["cloud_init"] == "yes", Disabled: v["cloud_init_disabled"] == "yes", DatasourceList: v["datasource_list"], Datasource: strings.TrimSpace(v["datasource"])}
	if st := v["status"]; st != "" {
		var doc struct {
			V1 map[string]json.RawMessage `json:"v1"`
		}
		if json.Unmarshal([]byte(st), &doc) == nil {
			if s, ok := doc.V1["stage"]; ok {
				var stage string
				_ = json.Unmarshal(s, &stage)
				p.CloudInit.Stage = stage
			}
			if p.CloudInit.Datasource == "" {
				var ds string
				_ = json.Unmarshal(doc.V1["datasource"], &ds)
				p.CloudInit.Datasource = ds
			}
			for _, k := range []string{"init-local", "init", "modules-config", "modules-final"} {
				var stg struct {
					Errors []string `json:"errors"`
				}
				if raw, ok := doc.V1[k]; ok && json.Unmarshal(raw, &stg) == nil {
					for _, e := range stg.Errors {
						p.CloudInit.Errors = append(p.CloudInit.Errors, k+": "+e)
					}
				}
			}
			// cloud-init >= 23.4: recoverable_errors {"ERROR": [...], "WARNING": [...]}
			var rec map[string][]string
			if raw, ok := doc.V1["recoverable_errors"]; ok && json.Unmarshal(raw, &rec) == nil {
				for _, e := range rec["ERROR"] {
					p.CloudInit.Errors = append(p.CloudInit.Errors, "recoverable: "+e)
				}
			}
		}
	}
	for _, u := range info.Units {
		switch u.Name {
		case "cloud-init-local", "cloud-init", "cloud-config", "cloud-final":
			p.CloudInit.Units = append(p.CloudInit.Units, CloudInitUnit{Name: u.Name, Active: u.Active, Sub: u.Sub, Result: u.Result})
		}
	}
	for _, l := range nonEmpty(secs["CLOUDINIT"]) {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "log":
			p.CloudInit.LogErrors = append(p.CloudInit.LogErrors, v)
		case "result":
			var res struct {
				V1 struct {
					Errors []string `json:"errors"`
				} `json:"v1"`
			}
			if json.Unmarshal([]byte(v), &res) == nil {
				p.CloudInit.ResultErrors = res.V1.Errors
			}
		}
	}
	for _, l := range nonEmpty(secs["VCENTER"]) {
		f := strings.Split(l, "|")
		if len(f) == 3 {
			p.VCenters = append(p.VCenters, VCenterProbe{Host: f[0], Code: strutil.AtoiOr(f[1], 0), Exit: strutil.AtoiOr(f[2], 0)})
		}
	}
	fa := kvLines(secs["FAPOLICYD"])
	p.Fapolicyd = Fapolicyd{Present: fa["present"] == "yes", Permissive: fa["permissive"], RulesFiles: strings.Fields(fa["rules_files"]), DenyFile: fa["deny_file"], CompiledK8s: strutil.AtoiOr(fa["compiled_k8s"], 0)}
	p.Fapolicyd.CompiledMtime = int64(strutil.AtoiOr(fa["compiled_mtime"], 0))
	p.Fapolicyd.RulesdMtime = int64(strutil.AtoiOr(fa["rulesd_mtime"], 0))
	for _, l := range nonEmpty(secs["FAPOLICYD"]) {
		if r, ok := strings.CutPrefix(l, "rule="); ok {
			p.Fapolicyd.AllowRules = append(p.Fapolicyd.AllowRules, r)
			for _, k := range []string{"rancher", "k3s", "kubelet", "/opt/cni", "containerd"} {
				if strings.Contains(r, k) {
					p.Fapolicyd.K8sRules = append(p.Fapolicyd.K8sRules, r)
					break
				}
			}
		}
	}
	p.CSI.MultipathBlacklist = -1
	for _, l := range nonEmpty(secs["CSI"]) {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "driver":
			p.CSI.Drivers = append(p.CSI.Drivers, strings.TrimSuffix(strings.TrimSpace(v), "|"))
		case "dir":
			p.CSI.HostDirs = append(p.CSI.HostDirs, strings.TrimSpace(v))
		case "iscsid":
			p.CSI.ISCSID = v == "active"
		case "multipath_blacklist":
			p.CSI.MultipathBlacklist = strutil.AtoiOr(v, 0)
		case "find_multipaths":
			p.CSI.FindMultipaths = strings.TrimSpace(v)
		case "mount_nfs":
			p.CSI.MountNFS = v == "yes"
		case "lhdev":
			p.CSI.LonghornDevs = append(p.CSI.LonghornDevs, strings.TrimSpace(v))
		case "iscsi":
			t, st, _ := strings.Cut(strings.TrimSpace(v), "|")
			p.CSI.ISCSISessions = append(p.CSI.ISCSISessions, ISCSISession{Target: t, State: st})
		}
	}
	p.Auditd = kvLines(secs["AUDITD"])
	acc := kvLines(secs["ACCOUNTS"])
	p.SudoUser = acc["sudo_user"]
	p.Today = strutil.AtoiOr(acc["today"], 0)
	p.LoginDefs = map[string]string{}
	for k, v := range acc {
		if d, ok := strings.CutPrefix(k, "login_defs_"); ok {
			p.LoginDefs[d] = v
		}
	}
	if v := acc["default_inactive"]; v != "" {
		p.LoginDefs["INACTIVE"] = v
	}
	p.FaillockDeny = strutil.AtoiOr(acc["faillock_deny"], 0)
	p.Faillock = map[string]int{}
	p.CIDefault = acc["ci_default"]
	p.Sudo = map[string]SudoInfo{}
	for _, l := range nonEmpty(secs["ACCOUNTS"]) {
		f := strings.Split(l, "|")
		switch {
		case f[0] == "user" && len(f) == 11:
			a := Account{Name: f[1], UID: strutil.AtoiOr(f[2], -1), Shell: f[3], PW: f[4], LastChange: strutil.AtoiOr(f[5], -1), Min: strutil.AtoiOr(f[6], -1), Max: strutil.AtoiOr(f[7], -1), Warn: strutil.AtoiOr(f[8], -1), Inactive: strutil.AtoiOr(f[9], -1), Expire: strutil.AtoiOr(f[10], -1)}
			p.Accounts = append(p.Accounts, a)
		case f[0] == "faillock" && len(f) == 3:
			p.Faillock[f[1]] = strutil.AtoiOr(f[2], 0)
		case strings.HasPrefix(f[0], "ci_user="):
			p.CIUsers = append(p.CIUsers, strings.TrimPrefix(f[0], "ci_user="))
		case f[0] == "sudo" && len(f) == 4:
			p.Sudo[f[1]] = SudoInfo{NoPasswd: f[2] == "nopasswd=yes", Keys: strutil.AtoiOr(strings.TrimPrefix(f[3], "keys="), 0)}
		}
	}
	for _, l := range nonEmpty(secs["PROXY"]) {
		file, rest, ok := strings.Cut(l, "|")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		rest = strings.TrimPrefix(rest, "export ")
		rest = strings.TrimPrefix(rest, "Environment=")
		rest = strings.Trim(rest, `"`)
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		p.Proxy = append(p.Proxy, ProxyLine{File: file, Key: strings.ToUpper(strings.TrimSpace(k)), Value: strings.Trim(strings.TrimSpace(v), `"'`)})
	}
	p.Iptables = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(secs["IPTABLES"]), "iptables="))
	p.SEPkgs = nonEmpty(secs["SEPKG"])
	p.NMUnmanaged = nonEmpty(secs["NMCONF"])
	for _, l := range nonEmpty(secs["REGPROBE"]) {
		if l == "curl=missing" {
			p.CurlMissing = true
			continue
		}
		f := strings.Split(l, "|")
		switch {
		case f[0] == "F" && len(f) == 5:
			p.RegFiles = append(p.RegFiles, RegFile{Key: f[1], Kind: f[2], Path: f[3], Missing: f[4] == "missing"})
		case f[0] == "skipped" && len(f) == 4:
			p.RegProbes = append(p.RegProbes, RegProbe{Host: f[1], URL: f[2], Implicit: true, Skipped: f[3]})
		case len(f) == 8 || len(f) == 9:
			rp := RegProbe{Host: f[0], URL: f[1], Code: strutil.AtoiOr(f[2], 0), Exit: strutil.AtoiOr(f[3], 0), TokenCode: strutil.AtoiOr(f[4], 0), Auth: f[5] == "yes", CA: f[6] == "yes", Insecure: f[7] == "true"}
			rp.Implicit = len(f) == 9 && f[8] == "yes"
			p.RegProbes = append(p.RegProbes, rp)
		}
	}
	sort.Slice(p.RegProbes, func(i, j int) bool { return p.RegProbes[i].URL < p.RegProbes[j].URL })
	parseHeavy(p, secs)
}

// parseHeavy reads the heavy-tier sections of preflight.sh.
func parseHeavy(p *Preflight, secs map[string]string) {
	if _, ok := secs["FAPDENY"]; ok {
		parseFapDeny(p, secs["FAPDENY"])
	}
	if _, ok := secs["REGPULL"]; ok {
		parseRegPulls(p, secs["REGPULL"])
	}
}

func parseRegPulls(p *Preflight, s string) {
	p.PullsProbed = true
	for _, l := range nonEmpty(s) {
		if l == "crictl=missing" {
			p.CrictlMissing = true
			continue
		}
		f := strings.SplitN(l, "|", 5)
		if len(f) != 5 {
			continue
		}
		r := RegPull{Registry: f[0], Image: f[1], OK: f[3] == "ok"}
		for _, e := range strings.Split(f[2], ",") {
			if e != "" {
				r.Endpoints = append(r.Endpoints, e)
			}
		}
		if f[3] == "skip" {
			r.Skipped = f[4]
		} else {
			r.Detail = f[4]
		}
		p.Pulls = append(p.Pulls, r)
	}
	sort.Slice(p.Pulls, func(i, j int) bool { return p.Pulls[i].Registry < p.Pulls[j].Registry })
}

func parseFapDeny(p *Preflight, s string) {
	p.DeniesProbed = true
	for _, l := range nonEmpty(s) {
		f := strings.SplitN(l, "|", 4)
		if len(f) != 4 {
			continue
		}
		d := FapDeny{Count: strutil.AtoiOr(f[0], 0), Exe: f[2], Path: f[3]}
		if ts := strutil.AtoiOr(f[1], 0); ts > 0 {
			d.Last = time.Unix(int64(ts), 0)
		}
		p.Denies = append(p.Denies, d)
	}
}

// mergePreflight carries the config tier of the preflight facts forward from
// the previous probe (MergeConfig) and the tier facts (MergeTiers).
func (p *Preflight) mergeConfig(prev *Preflight) {
	if p.Probed || prev == nil || !prev.Probed {
		return
	}
	swaps, units := p.Swaps, p.Units
	denies, dp := p.Denies, p.DeniesProbed
	pulls, pp, cm := p.Pulls, p.PullsProbed, p.CrictlMissing
	*p = *prev
	p.Swaps, p.Units = swaps, units
	p.Denies, p.DeniesProbed = denies, dp
	p.Pulls, p.PullsProbed, p.CrictlMissing = pulls, pp, cm
}

func (p *Preflight) mergeTiers(prev *Preflight) {
	if prev == nil {
		return
	}
	if !p.DeniesProbed {
		p.Denies, p.DeniesProbed = prev.Denies, prev.DeniesProbed
	}
	if !p.PullsProbed {
		p.Pulls, p.PullsProbed, p.CrictlMissing = prev.Pulls, prev.PullsProbed, prev.CrictlMissing
	}
}

// Account returns the account entry for name.
func (p *Preflight) Account(name string) *Account {
	for i := range p.Accounts {
		if p.Accounts[i].Name == name {
			return &p.Accounts[i]
		}
	}
	return nil
}

// MountOpt returns the mount that holds path (longest matching mountpoint).
func (p *Preflight) MountOpt(path string) *MountOpt {
	var best *MountOpt
	for i := range p.MountOpts {
		m := &p.MountOpts[i]
		mp := m.Mountpoint
		if path == mp || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			if best == nil || len(mp) > len(best.Mountpoint) {
				best = m
			}
		}
	}
	return best
}
