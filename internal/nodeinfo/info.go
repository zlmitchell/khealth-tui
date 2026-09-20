package nodeinfo

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s-health-tui/internal/perf"
)

// Info is everything collected from one node.
type Info struct {
	Node      string
	Host      string
	HostKey   string // SHA256 fingerprint of the SSH host key the node presented (sshrun.Result.HostKey)
	Collected time.Time
	Duration  time.Duration
	Err       error
	Heavy     bool
	STIGRun   bool // this probe included the OS STIG sections (cost accounting)
	// ConfigProbed: the config tier (certs, sysctls, perms, slow hardening
	// facts, rke2/k3s config, manifests, registries) is present, from this
	// probe or carried forward from an earlier one by MergeConfig.
	ConfigProbed    bool
	ConfigCollected time.Time

	// Cost is what this probe cost the node (PERF section) and the session.
	Cost       perf.RemoteCost
	OutBytes   int // script output size
	ScriptSize int // script size sent

	Hostname, Kernel, Arch string
	Uptime                 time.Duration
	Load1, Load5, Load15   float64
	CPUs                   int
	CPUPct                 float64 // -1 until CPUFromPrev has a previous sample (or the probe sampled twice)
	CPUStat                CPUStat // raw /proc/stat counters of this probe, for the next one to diff against
	MemTotal, MemAvail     uint64
	SwapTotal, SwapFree    uint64
	MemPct                 float64
	Mounts                 []Mount
	PVMounts               []PVMount        // PV filesystems mounted for pods (df on kubelet volume dirs)
	PVDirs                 map[string]int64 // hostPath/local PV directory -> used KB (du, heavy mode)
	Services               []Service
	Units                  []Unit
	NTPSynced              *bool
	NTPEnabled             *bool
	ClockOffset            time.Duration
	Dist                   string
	ControlPlane           bool
	Certs                  []Cert
	// APIServerSANs: subjectAltName entries of the apiserver serving
	// certificate (DNS names and IPs); TLSSAN: tls-san from config.yaml.
	// Entries in TLSSAN missing from APIServerSANs mean the certificate has
	// not been reissued since the config changed (rke2 does that on restart).
	APIServerSANs    []string
	APIServerCert    string // path of the serving certificate
	TLSSAN           []string
	KubeletFlags     map[string]string
	KubeletPID       int
	Sysctl           map[string]string
	Perms            []Perm
	EtcdUser         bool
	SELinux          string
	OS               OSRelease
	Hardening        map[string]string // selinux, fips, apparmor, svc_*, lockdown, secureboot, reboot_required, ...
	ConfigFiles      []ConfigFile      // rke2/k3s config.yaml(.d) (secrets masked)
	ExtraFiles       []ConfigFile      // audit policy, PSS config, /etc/rancher listings
	Manifests        []ManifestFile    // rke2/k3s server/manifests (auto-deploy dir)
	StaticPods       []ManifestFile    // pod-manifests / /etc/kubernetes/manifests
	DataDir          string            // rke2/k3s data-dir
	Settings         map[string]string // merged top-level key: value from config files
	Rancher          RancherNode
	CNI              []CNIConf
	Registries       []ConfigFile
	RegistryMirrors  []string // registry hosts with mirrors in registries.yaml
	ContainerdHosts  []string // registries containerd has certs.d/hosts.toml for
	ContainerdConfig []ConfigFile
	Preflight        Preflight // what stops rke2 from (re)starting or the node from re-provisioning (preflight.go)

	// OS STIG facts (internal/stigdata templates)
	SysctlAll      map[string]string
	Packages       map[string]bool
	UnitFiles      map[string]string    // unit -> enabled/disabled/masked/static/...
	UnitStates     map[string]UnitState // unit -> load/active/sub
	Findmnt        []MountEntry
	Fstab          []string
	SSHD           map[string][]string // sshd -T keyword (lower-case) -> values
	AuditRules     []string            // auditctl -l (loaded)
	AuditRuleFiles []string            // /etc/audit/rules.d/*.rules + audit.rules
	Modprobe       []string            // install/blacklist lines from modprobe.d
	LoadedModules  map[string]bool
	GrubArgs       []string // grubby args= lines and GRUB_CMDLINE_LINUX*
	STIGStat       map[string]Perm
	STIGViol       map[string][]string // check id -> violating paths (find scans)
	STIGFiles      []ConfigFile        // config files the templates read (masked)
	STIGCmd        map[string]string   // one-line facts for the named evaluators (STIGCMD section)
	STIGSweep      map[string][]string // filesystem sweep findings by kind (WWNOSTICKY, NOUSER, HOME, INITPERM, ...)
	Passwd         []PasswdEntry
	Groups         []GroupEntry
	ShadowMeta     map[string]ShadowMeta // user -> hash type and ages (never the hash)
	SSSDConf       map[string]string     // selected sssd.conf keys
	UFWStatus      string                // ufw status verbose
	SELinuxLogins  []string              // semanage login -l
	Lsblk          []string              // NAME TYPE MOUNTPOINT
	STIGProbed     bool                  // OS STIG facts present (collected by this or a previous probe)
	STIGCollected  time.Time             // when the OS STIG facts were collected

	// heavy
	Images     []Image
	Containers []Container
	Tarballs   []Tarball
	Journal    []string
	LogFiles   []ConfigFile
	CrictlInfo string
}

// CPUStat is the first line of /proc/stat, summed: total jiffies and idle
// (idle + iowait) jiffies.
type CPUStat struct {
	Total, Idle float64
	At          time.Time
}

// CPUFromPrev computes CPUPct from the previous probe's counters when this
// probe did not sample twice itself. The window is the refresh interval,
// which is a better average than a one-second spot sample.
func (i *Info) CPUFromPrev(prev *Info) {
	if i.CPUPct >= 0 || prev == nil || prev.Err != nil || prev.CPUStat.Total == 0 || i.CPUStat.Total == 0 {
		return
	}
	dt := i.CPUStat.Total - prev.CPUStat.Total
	if dt <= 0 { // reboot or counter reset
		return
	}
	i.CPUPct = 100 * (1 - (i.CPUStat.Idle-prev.CPUStat.Idle)/dt)
}

// Mount is one filesystem from df.
type Mount struct {
	Filesystem, Type, Mountpoint string
	SizeKB, UsedKB, AvailKB      int64
	UsePct                       int
	InodePct                     int
}

// PVMount is a pod volume mount reported by df on the node.
type PVMount struct {
	PV                      string // volume/PV name from the mount path
	Mountpoint              string
	SizeKB, UsedKB, AvailKB int64
	UsePct                  int
}

// Service is a systemd unit state.
type Service struct {
	Name, Load, Active, Sub string
}

// Unit carries restart information for the important units.
type Unit struct {
	Name, Active, Sub, Result string
	NRestarts                 int
	Started                   time.Time
}

// Cert is a certificate file with its expiry.
type Cert struct {
	Path     string
	NotAfter time.Time
}

// Perm is a file mode/ownership record.
type Perm struct {
	Path, Mode, User, Group, Type string
	UID, GID                      string // numeric ids (STIG stat lines only)
}

// PasswdEntry is one /etc/passwd line.
type PasswdEntry struct {
	Name, Home, Shell string
	UID, GID          int
}

// GroupEntry is one /etc/group line.
type GroupEntry struct {
	Name    string
	GID     int
	Members []string
}

// ShadowMeta is the non-secret part of an /etc/shadow entry: the hash prefix
// ("$6$"), "locked" or "empty", and the password aging fields.
type ShadowMeta struct {
	Hash                       string
	MinDays, MaxDays, Inactive string
	Expire                     string
}

// MountEntry is one findmnt line.
type MountEntry struct {
	Target, Source, FSType string
	Options                []string
}

// UnitState is one systemctl list-units line.
type UnitState struct {
	Load, Active, Sub string
}

// ConfigFile is a (possibly masked) file dump.
type ConfigFile struct {
	Path    string
	Content string
}

// OSRelease is the parsed /etc/os-release.
type OSRelease struct {
	ID, IDLike, VersionID, Pretty string
}

// Family returns "rhel", "debian" or "" based on ID/ID_LIKE.
func (o OSRelease) Family() string {
	ids := strings.ToLower(o.ID + " " + o.IDLike)
	switch {
	case strings.Contains(ids, "rhel") || strings.Contains(ids, "fedora") || strings.Contains(ids, "centos") || strings.Contains(ids, "rocky") || strings.Contains(ids, "alma") || strings.Contains(ids, "ol") || strings.Contains(ids, "sles") || strings.Contains(ids, "suse"):
		return "rhel"
	case strings.Contains(ids, "ubuntu") || strings.Contains(ids, "debian"):
		return "debian"
	}
	return ""
}

// ManifestFile is a file from an auto-deploy or static pod manifest directory.
type ManifestFile struct {
	Path    string
	Size    int64
	ModTime time.Time
	Kinds   string // "HelmChartConfig x1,ConfigMap x2,"
	Content string
	Bundled bool // rke2-provided (content omitted)
}

// RancherNode is the node-side view of Rancher management.
type RancherNode struct {
	SystemAgent string // loaded active running
	AgentURL    string
	Provisioned bool
	Plans       int
}

// CNIConf is a parsed CNI config file.
type CNIConf struct {
	Path  string
	Name  string
	Types []string
}

// Image is a container image known to the CRI.
type Image struct {
	ID      string
	Tags    []string
	Digests []string
	Size    int64
}

// Container is a running container from the CRI.
type Container struct {
	ID, Name, Image, ImageRef, Pod string
}

// Tarball is an airgap image archive in the rke2/k3s images directory.
type Tarball struct {
	Path    string
	Size    int64
	ModTime time.Time
	Images  []string
	Parsed  bool
	Cached  bool
}

// Parse turns the script output into an Info. sentAt is when the script was
// started locally (used for clock skew).
func Parse(node, host, out string, sentAt time.Time) *Info {
	info := &Info{Node: node, Host: host, Collected: time.Now(), KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	secs := splitSections(out)
	info.OutBytes = len(out)
	info.Cost = perf.ParseSection(secs["PERF"])

	if v := strings.TrimSpace(secs["TIME"]); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSuffix(v, "N"), 64); err == nil {
			remote := time.Unix(0, int64(f*1e9))
			info.ClockOffset = remote.Sub(sentAt).Round(10 * time.Millisecond)
		}
	}
	if lines := nonEmpty(secs["HOST"]); len(lines) > 0 {
		info.Hostname = lines[0]
		if len(lines) > 1 {
			info.Kernel = lines[1]
		}
		if len(lines) > 2 {
			info.Arch = lines[2]
		}
	}
	if f := fields(secs["UPTIME"]); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			info.Uptime = time.Duration(v * float64(time.Second))
		}
	}
	if f := fields(secs["LOAD"]); len(f) >= 3 {
		info.Load1, _ = strconv.ParseFloat(f[0], 64)
		info.Load5, _ = strconv.ParseFloat(f[1], 64)
		info.Load15, _ = strconv.ParseFloat(f[2], 64)
	}
	if f := fields(secs["NPROC"]); len(f) > 0 {
		info.CPUs, _ = strconv.Atoi(f[0])
	}
	info.CPUPct = cpuPct(secs["STAT1"], secs["STAT2"])
	if t, idle, ok := cpuCounters(secs["STAT1"]); ok {
		info.CPUStat = CPUStat{Total: t, Idle: idle, At: info.Collected}
	}
	parseMem(info, secs["MEM"])
	info.Mounts = parseDF(secs["DF"])
	applyInodes(info.Mounts, secs["DFI"])
	info.PVMounts = parsePVMounts(secs["PVMOUNTS"])
	for _, l := range nonEmpty(secs["SVC"]) {
		f := strings.Fields(l)
		if len(f) >= 4 {
			info.Services = append(info.Services, Service{Name: f[0], Load: f[1], Active: f[2], Sub: f[3]})
		}
	}
	for _, l := range nonEmpty(secs["UNITS"]) {
		f := strings.Split(l, "|")
		if len(f) >= 6 {
			u := Unit{Name: f[0], Active: f[1], Sub: f[2], Result: f[5]}
			u.NRestarts, _ = strconv.Atoi(f[3])
			u.Started = parseSystemdTime(f[4])
			info.Units = append(info.Units, u)
		}
	}
	for idx, l := range nonEmpty(secs["NTP"]) {
		// "NTPSynchronized=yes" / "NTP=yes" (one timedatectl call); older
		// probes printed the bare values in that order
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			k, v = map[int]string{0: "NTPSynchronized", 1: "NTP"}[idx], l
		}
		b := strings.TrimSpace(v) == "yes"
		switch k {
		case "NTPSynchronized":
			info.NTPSynced = &b
		case "NTP":
			info.NTPEnabled = &b
		}
	}
	dist := nonEmpty(secs["DIST"])
	for _, d := range dist {
		switch {
		case strings.HasPrefix(d, "/etc/rancher/rke2") || strings.HasPrefix(d, "/var/lib/rancher/rke2"):
			info.Dist = "rke2"
		case strings.HasPrefix(d, "/etc/rancher/k3s") || strings.HasPrefix(d, "/var/lib/rancher/k3s"):
			if info.Dist == "" {
				info.Dist = "k3s"
			}
		case strings.HasPrefix(d, "/etc/kubernetes"):
			if info.Dist == "" {
				info.Dist = "kubeadm"
			}
		}
		if d == "/var/lib/rancher/rke2/server" || d == "/var/lib/rancher/k3s/server" || d == "/etc/kubernetes/manifests/kube-apiserver.yaml" || d == "/var/lib/etcd" || d == "/var/lib/rancher/rke2/server/db/etcd" {
			info.ControlPlane = true
		}
	}
	if info.Dist == "" {
		info.Dist = "unknown"
	}
	for _, l := range nonEmpty(secs["CERTS"]) {
		p, d, ok := strings.Cut(l, "|")
		if !ok {
			continue
		}
		if t, err := time.Parse("Jan 2 15:04:05 2006 MST", strings.TrimSpace(d)); err == nil {
			info.Certs = append(info.Certs, Cert{Path: p, NotAfter: t})
		}
	}
	for _, a := range nonEmpty(secs["KUBELETCMD"]) {
		if v, ok := strings.CutPrefix(a, "pid="); ok {
			info.KubeletPID, _ = strconv.Atoi(strings.TrimSpace(v))
			continue
		}
		if strings.HasPrefix(a, "--") {
			k, v, found := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			if !found {
				v = "true"
			}
			info.KubeletFlags[k] = v
		}
	}
	for _, l := range nonEmpty(secs["SYSCTL"]) {
		if k, v, ok := strings.Cut(l, "="); ok {
			info.Sysctl[k] = strings.TrimSpace(v)
		}
	}
	for _, l := range nonEmpty(secs["PERMS"]) {
		f := strings.SplitN(l, "|", 5)
		if len(f) == 5 {
			info.Perms = append(info.Perms, Perm{Mode: f[0], User: f[1], Group: f[2], Type: f[3], Path: f[4]})
		}
	}
	info.EtcdUser = strings.Contains(secs["ETCDUSER"], "uid=")
	info.SELinux = strings.TrimSpace(secs["SELINUX"])
	for _, l := range nonEmpty(secs["OSREL"]) {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "ID":
			info.OS.ID = v
		case "ID_LIKE":
			info.OS.IDLike = v
		case "VERSION_ID":
			info.OS.VersionID = v
		case "PRETTY_NAME":
			info.OS.Pretty = v
		}
	}
	for _, l := range nonEmpty(secs["HARDENING"]) {
		if k, v, ok := strings.Cut(l, "="); ok {
			if v = strings.TrimSpace(v); v != "" {
				info.Hardening[k] = v
			}
		}
	}
	if _, ok := secs["CERTS"]; ok || info.Hardening["config_probed"] == "yes" {
		info.ConfigProbed, info.ConfigCollected = true, info.Collected
		delete(info.Hardening, "config_probed")
	}
	for _, l := range nonEmpty(secs["DATADIR"]) {
		if k, v, ok := strings.Cut(l, "="); ok && v != "" {
			if (k == "rke2" && info.Dist == "rke2") || (k == "k3s" && info.Dist == "k3s") {
				info.DataDir = strings.TrimSpace(v)
			}
		}
	}
	if _, ok := secs["SYSCTLALL"]; ok {
		// the one-script probe (Options.OSStig): every stage in one answer
		parseOSStig(info, secs)
		info.STIGProbed, info.STIGCollected = true, info.Collected
	}
	parsePreflight(info, secs)
	info.ConfigFiles = parseDumps(secs["RKE2CFG"])
	info.ExtraFiles = parseDumps(secs["RKE2EXTRA"])
	info.Manifests = parseManifests(secs["MANIFESTS"])
	info.StaticPods = parseManifests(secs["STATICPODS"])
	for _, cf := range parseDumps(secs["APISERVERCERT"]) {
		if dns, ips, err := CertSANs(cf.Content); err == nil {
			info.APIServerCert = cf.Path
			info.APIServerSANs = append(append(info.APIServerSANs, dns...), ips...)
		}
	}
	for _, cf := range info.ConfigFiles {
		info.TLSSAN = append(info.TLSSAN, YAMLList(cf.Content, "tls-san")...)
	}
	for _, cf := range info.ConfigFiles {
		if !strings.HasSuffix(cf.Path, ".yaml") && !strings.HasSuffix(cf.Path, ".yml") {
			continue // kubeadm-flags.env / systemd drop-ins are not key: value files
		}
		for _, l := range strings.Split(cf.Content, "\n") {
			if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "-") {
				continue
			}
			if k, v, ok := strings.Cut(l, ":"); ok {
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				if k != "" {
					if prev, exists := info.Settings[k]; exists && v == "" {
						_ = prev
						continue
					}
					info.Settings[k] = v
				}
			}
		}
	}
	for _, l := range nonEmpty(secs["RANCHER"]) {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "system-agent":
			info.Rancher.SystemAgent = strings.TrimSpace(v)
		case "agent-url":
			info.Rancher.AgentURL = strings.TrimSpace(v)
		case "rancher-provisioned":
			info.Rancher.Provisioned = true
		case "applied-plans":
			info.Rancher.Plans, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	for _, cf := range parseDumps(secs["CNI"]) {
		info.CNI = append(info.CNI, parseCNI(cf))
	}
	info.Registries = parseDumps(secs["REGISTRIES"])
	info.RegistryMirrors = parseRegistryMirrors(info.Registries)
	for _, cf := range parseDumps(secs["CONTAINERDREG"]) {
		if strings.HasSuffix(cf.Path, "/hosts.toml") {
			parts := strings.Split(cf.Path, "/")
			if len(parts) >= 2 {
				info.ContainerdHosts = append(info.ContainerdHosts, parts[len(parts)-2])
			}
		}
		info.ContainerdConfig = append(info.ContainerdConfig, cf)
	}

	if _, ok := secs["CRICTL"]; ok {
		info.Heavy = true
		info.CrictlInfo = strings.TrimSpace(secs["CRICTL"])
		info.Images = parseImages(secs["IMAGES"])
		info.Containers = parseContainers(secs["CONTAINERS"])
		info.Tarballs = parseTarballs(secs["TARBALLS"])
		info.PVDirs = map[string]int64{}
		for _, l := range nonEmpty(secs["PVDU"]) {
			if kb, path, ok := strings.Cut(l, "|"); ok {
				if n, err := strconv.ParseInt(strings.TrimSpace(kb), 10, 64); err == nil {
					info.PVDirs[path] = n
				}
			}
		}
		info.Journal = nonEmpty(secs["JOURNAL"])
		info.LogFiles = parseDumps(secs["LOGFILES"])
	}
	return info
}

func splitSections(out string) map[string]string {
	secs := map[string]string{}
	cur := ""
	var buf strings.Builder
	flush := func() {
		if cur != "" {
			secs[cur] = buf.String()
		}
		buf.Reset()
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "===") && len(line) > 3 && !strings.ContainsAny(line[3:], " \t") {
			flush()
			cur = line[3:]
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	flush()
	return secs
}

func nonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, l)
		}
	}
	return out
}

func fields(s string) []string { return strings.Fields(s) }

func cpuPct(a, b string) float64 {
	t1, i1, ok1 := cpuCounters(a)
	t2, i2, ok2 := cpuCounters(b)
	if !ok1 || !ok2 || t2-t1 <= 0 {
		return -1
	}
	return 100 * (1 - (i2-i1)/(t2-t1))
}

// cpuCounters sums the "cpu ..." line of /proc/stat into total and idle
// (idle + iowait) jiffies.
func cpuCounters(line string) (total, idle float64, ok bool) {
	f := fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	for i := 1; i < len(f); i++ {
		v, _ := strconv.ParseFloat(f[i], 64)
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return total, idle, true
}

func parseMem(info *Info, s string) {
	vals := map[string]uint64{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(f[0], 10, 64)
		vals[k] = n * 1024
	}
	info.MemTotal = vals["MemTotal"]
	if av, ok := vals["MemAvailable"]; ok {
		info.MemAvail = av
	} else {
		info.MemAvail = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	info.SwapTotal = vals["SwapTotal"]
	info.SwapFree = vals["SwapFree"]
	if info.MemTotal > 0 {
		info.MemPct = 100 * (1 - float64(info.MemAvail)/float64(info.MemTotal))
	}
}

func parseDF(s string) []Mount {
	lines := nonEmpty(s)
	if len(lines) == 0 {
		return nil
	}
	hasType := strings.Contains(lines[0], "Type")
	var out []Mount
	seen := map[string]bool{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		var m Mount
		if hasType {
			if len(f) < 7 {
				continue
			}
			m.Filesystem, m.Type = f[0], f[1]
			m.SizeKB, _ = strconv.ParseInt(f[2], 10, 64)
			m.UsedKB, _ = strconv.ParseInt(f[3], 10, 64)
			m.AvailKB, _ = strconv.ParseInt(f[4], 10, 64)
			m.UsePct, _ = strconv.Atoi(strings.TrimSuffix(f[5], "%"))
			m.Mountpoint = strings.Join(f[6:], " ")
		} else {
			if len(f) < 6 {
				continue
			}
			m.Filesystem = f[0]
			m.SizeKB, _ = strconv.ParseInt(f[1], 10, 64)
			m.UsedKB, _ = strconv.ParseInt(f[2], 10, 64)
			m.AvailKB, _ = strconv.ParseInt(f[3], 10, 64)
			m.UsePct, _ = strconv.Atoi(strings.TrimSuffix(f[4], "%"))
			m.Mountpoint = strings.Join(f[5:], " ")
		}
		if seen[m.Mountpoint] || m.SizeKB == 0 {
			continue
		}
		seen[m.Mountpoint] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out
}

// parsePVMounts reads "size|used|avail|use%|mountpoint" lines and derives the
// PV name from paths like .../volumes/kubernetes.io~csi/pvc-1234/mount.
func parsePVMounts(s string) []PVMount {
	var out []PVMount
	seen := map[string]bool{}
	for _, l := range nonEmpty(s) {
		f := strings.SplitN(l, "|", 5)
		if len(f) != 5 {
			continue
		}
		m := PVMount{Mountpoint: f[4]}
		m.SizeKB, _ = strconv.ParseInt(f[0], 10, 64)
		m.UsedKB, _ = strconv.ParseInt(f[1], 10, 64)
		m.AvailKB, _ = strconv.ParseInt(f[2], 10, 64)
		m.UsePct, _ = strconv.Atoi(strings.TrimSuffix(f[3], "%"))
		parts := strings.Split(m.Mountpoint, "/")
		for i, seg := range parts {
			if strings.HasPrefix(seg, "kubernetes.io~") && i+1 < len(parts) {
				m.PV = parts[i+1]
			}
		}
		if m.PV == "" || seen[m.PV] {
			continue
		}
		seen[m.PV] = true
		out = append(out, m)
	}
	return out
}

func applyInodes(mounts []Mount, s string) {
	lines := nonEmpty(s)
	if len(lines) < 2 {
		return
	}
	pct := map[string]int{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		p, err := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
		if err != nil {
			continue
		}
		pct[strings.Join(f[5:], " ")] = p
	}
	for i := range mounts {
		if p, ok := pct[mounts[i].Mountpoint]; ok {
			mounts[i].InodePct = p
		}
	}
}

// MountFor returns the mount that hosts the given path (longest prefix).
func (i *Info) MountFor(path string) *Mount {
	var best *Mount
	for idx := range i.Mounts {
		m := &i.Mounts[idx]
		mp := m.Mountpoint
		if path == mp || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") {
			if best == nil || len(mp) > len(best.Mountpoint) {
				best = m
			}
		}
	}
	return best
}

// DataMount returns the mount holding the container/kubelet data.
func (i *Info) DataMount() *Mount {
	for _, p := range []string{"/var/lib/rancher", "/var/lib/kubelet", "/var/lib/containerd", "/var/lib"} {
		if m := i.MountFor(p); m != nil && m.Mountpoint != "/" {
			return m
		}
	}
	return i.MountFor("/var/lib")
}

// Service returns the service state by name.
func (i *Info) Service(name string) *Service {
	for idx := range i.Services {
		if i.Services[idx].Name == name {
			return &i.Services[idx]
		}
	}
	return nil
}

// Unit returns unit info by name.
func (i *Info) Unit(name string) *Unit {
	for idx := range i.Units {
		if i.Units[idx].Name == name {
			return &i.Units[idx]
		}
	}
	return nil
}

// Perm returns the permission record for a path.
func (i *Info) Perm(path string) *Perm {
	for idx := range i.Perms {
		if i.Perms[idx].Path == path {
			return &i.Perms[idx]
		}
	}
	return nil
}

func parseSystemdTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{"Mon 2006-01-02 15:04:05 MST", "Mon 2006-01-02 15:04:05 -07", "2006-01-02 15:04:05 MST"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// parseOSStig reads the OS STIG probe sections (see script.go osStigScript
// and stigdata.ProbeScript) that are present in secs, leaving the others
// untouched: the one-script probe carries all of them, a scan stage
// (ParseSTIGStage) only its own. STIGProbed is the caller's call - the
// facts are only complete when every stage has landed.
func parseOSStig(info *Info, secs map[string]string) {
	has := func(name string) bool { _, ok := secs[name]; return ok }
	if has("SYSCTLALL") {
		info.SysctlAll = map[string]string{}
		for _, l := range nonEmpty(secs["SYSCTLALL"]) {
			if k, v, ok := strings.Cut(l, "="); ok {
				info.SysctlAll[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	if has("PKGS") {
		info.Packages = map[string]bool{}
		for _, l := range nonEmpty(secs["PKGS"]) {
			info.Packages[strings.TrimSpace(l)] = true
		}
	}
	if has("UNITFILES") {
		info.UnitFiles = map[string]string{}
		for _, l := range nonEmpty(secs["UNITFILES"]) {
			if f := strings.Fields(l); len(f) >= 2 {
				info.UnitFiles[f[0]] = f[1]
			}
		}
	}
	if has("UNITSALL") {
		info.UnitStates = map[string]UnitState{}
		for _, l := range nonEmpty(secs["UNITSALL"]) {
			if f := strings.Fields(l); len(f) >= 4 {
				info.UnitStates[f[0]] = UnitState{Load: f[1], Active: f[2], Sub: f[3]}
			}
		}
	}
	if has("FINDMNT") {
		info.Findmnt = nil
		for _, l := range nonEmpty(secs["FINDMNT"]) {
			if f := strings.Fields(l); len(f) >= 4 {
				info.Findmnt = append(info.Findmnt, MountEntry{Target: f[0], Source: f[1], FSType: f[2], Options: strings.Split(f[3], ",")})
			}
		}
	}
	if has("FSTAB") {
		info.Fstab = nonEmpty(secs["FSTAB"])
	}
	if has("SSHD") {
		info.SSHD = map[string][]string{}
		for _, l := range nonEmpty(secs["SSHD"]) {
			if k, v, ok := strings.Cut(l, " "); ok {
				k = strings.ToLower(k)
				info.SSHD[k] = append(info.SSHD[k], strings.TrimSpace(v))
			}
		}
	}
	if has("AUDITRULES") {
		info.AuditRules = nonEmpty(secs["AUDITRULES"])
	}
	if has("AUDITRULESD") {
		info.AuditRuleFiles = nonEmpty(secs["AUDITRULESD"])
	}
	if has("MODPROBE") {
		info.Modprobe = nonEmpty(secs["MODPROBE"])
	}
	if has("LSMOD") {
		info.LoadedModules = map[string]bool{}
		for _, l := range nonEmpty(secs["LSMOD"]) {
			info.LoadedModules[strings.TrimSpace(l)] = true
		}
	}
	if has("GRUBCFG") {
		info.GrubArgs = nonEmpty(secs["GRUBCFG"])
	}
	if has("STIGSTAT") {
		info.STIGStat = map[string]Perm{}
		for _, l := range nonEmpty(secs["STIGSTAT"]) {
			if f := strings.SplitN(l, "|", 7); len(f) == 7 {
				info.STIGStat[f[6]] = Perm{Mode: f[0], User: f[1], Group: f[2], UID: f[3], GID: f[4], Type: f[5], Path: f[6]}
			}
		}
	}
	if has("STIGVIOL") {
		info.STIGViol = map[string][]string{}
		for _, l := range nonEmpty(secs["STIGVIOL"]) {
			if f := strings.SplitN(l, "|", 3); len(f) == 3 && f[0] == "VIOL" {
				info.STIGViol[f[1]] = append(info.STIGViol[f[1]], f[2])
			}
		}
	}
	if has("STIGFILES") {
		info.STIGFiles = parseDumps(secs["STIGFILES"])
	}

	// facts for the named evaluators (os_stig_facts.sh, os_stig_sweep.sh)
	if has("STIGCMD") {
		info.STIGCmd = map[string]string{}
		for _, l := range nonEmpty(secs["STIGCMD"]) {
			if k, v, ok := strings.Cut(l, "="); ok {
				info.STIGCmd[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	if has("STIGSWEEP") {
		info.STIGSweep = map[string][]string{}
		for _, l := range nonEmpty(secs["STIGSWEEP"]) {
			if k, v, ok := strings.Cut(l, "|"); ok {
				info.STIGSweep[k] = append(info.STIGSweep[k], v)
			}
		}
	}
	if has("PASSWD") {
		info.Passwd = nil
		for _, l := range nonEmpty(secs["PASSWD"]) {
			f := strings.Split(strings.TrimSpace(l), ":")
			if len(f) >= 7 {
				uid, _ := strconv.Atoi(f[2])
				gid, _ := strconv.Atoi(f[3])
				info.Passwd = append(info.Passwd, PasswdEntry{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
			}
		}
	}
	if has("GROUP") {
		info.Groups = nil
		for _, l := range nonEmpty(secs["GROUP"]) {
			f := strings.Split(strings.TrimSpace(l), ":")
			if len(f) >= 3 {
				gid, _ := strconv.Atoi(f[2])
				g := GroupEntry{Name: f[0], GID: gid}
				if len(f) >= 4 && f[3] != "" {
					g.Members = strings.Split(f[3], ",")
				}
				info.Groups = append(info.Groups, g)
			}
		}
	}
	if has("SHADOWMETA") {
		info.ShadowMeta = map[string]ShadowMeta{}
		for _, l := range nonEmpty(secs["SHADOWMETA"]) {
			f := strings.Split(strings.TrimSpace(l), ":")
			if len(f) >= 6 {
				info.ShadowMeta[f[0]] = ShadowMeta{Hash: f[1], MinDays: f[2], MaxDays: f[3], Inactive: f[4], Expire: f[5]}
			}
		}
	}
	if has("SSSD") {
		info.SSSDConf = map[string]string{}
		for _, l := range nonEmpty(secs["SSSD"]) {
			if k, v, ok := strings.Cut(l, "="); ok {
				info.SSSDConf[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	if has("UFWSTATUS") {
		info.UFWStatus = strings.TrimSpace(secs["UFWSTATUS"])
	}
	if has("SEMANAGE") {
		info.SELinuxLogins = nonEmpty(secs["SEMANAGE"])
	}
	if has("LSBLK") {
		info.Lsblk = nonEmpty(secs["LSBLK"])
	}
}

// ParseSTIGStage merges the output of one scan stage (STIGStageScript) into
// info and returns what the stage cost the node. The facts are complete
// once every stage has been merged: the caller then marks them collected
// (AdoptSTIG).
func ParseSTIGStage(info *Info, out string) perf.RemoteCost {
	secs := splitSections(out)
	parseOSStig(info, secs)
	return perf.ParseSection(secs["PERF"])
}

// STIGFile returns a dumped config file's content and whether it was present.
func (i *Info) STIGFile(path string) (string, bool) {
	for _, f := range i.STIGFiles {
		if f.Path == path {
			return f.Content, true
		}
	}
	return "", false
}

// STIGFilesGlob returns dumped files under a directory (prefix match).
func (i *Info) STIGFilesGlob(dir string) []ConfigFile {
	dir = strings.TrimRight(dir, "/") + "/"
	var out []ConfigFile
	for _, f := range i.STIGFiles {
		if strings.HasPrefix(f.Path, dir) {
			out = append(out, f)
		}
	}
	return out
}

func parseDumps(s string) []ConfigFile {
	var out []ConfigFile
	var cur *ConfigFile
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "--- ") {
			if cur != nil {
				cur.Content = strings.TrimRight(cur.Content, "\n")
				out = append(out, *cur)
			}
			cur = &ConfigFile{Path: strings.TrimPrefix(l, "--- ")}
			continue
		}
		if cur != nil {
			cur.Content += l + "\n"
		}
	}
	if cur != nil {
		cur.Content = strings.TrimRight(cur.Content, "\n")
		out = append(out, *cur)
	}
	return out
}

// parseManifests reads "--- path|size|mtime|kinds" headed dumps.
func parseManifests(s string) []ManifestFile {
	var out []ManifestFile
	for _, cf := range parseDumps(s) {
		f := strings.SplitN(cf.Path, "|", 4)
		m := ManifestFile{Path: f[0], Content: cf.Content}
		if len(f) > 1 {
			m.Size, _ = strconv.ParseInt(f[1], 10, 64)
		}
		if len(f) > 2 {
			if mt, err := strconv.ParseInt(f[2], 10, 64); err == nil {
				m.ModTime = time.Unix(mt, 0)
			}
		}
		if len(f) > 3 {
			m.Kinds = strings.TrimSuffix(f[3], ",")
		}
		if strings.HasPrefix(cf.Content, "(content omitted") {
			m.Bundled = true
			m.Content = ""
		}
		out = append(out, m)
	}
	return out
}

func parseCNI(cf ConfigFile) CNIConf {
	c := CNIConf{Path: cf.Path}
	var doc struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Plugins []struct {
			Type string `json:"type"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(cf.Content), &doc); err == nil {
		c.Name = doc.Name
		if doc.Type != "" {
			c.Types = append(c.Types, doc.Type)
		}
		for _, p := range doc.Plugins {
			c.Types = append(c.Types, p.Type)
		}
	}
	return c
}

// ContainerdSetting returns the quoted value of a `key = "value"` line in the
// node's containerd config.toml dump ("config_path", "sandbox_image", ...),
// "" when unset. The dump is grep -n output, so lines carry a "NN:" prefix.
func (i *Info) ContainerdSetting(key string) string {
	for _, cf := range i.ContainerdConfig {
		if !strings.HasSuffix(cf.Path, "config.toml") {
			continue
		}
		for _, l := range strings.Split(cf.Content, "\n") {
			if num, rest, ok := strings.Cut(l, ":"); ok && num != "" && strings.Trim(num, "0123456789") == "" {
				l = rest
			}
			k, v, ok := strings.Cut(l, "=")
			if !ok || strings.TrimSpace(k) != key {
				continue
			}
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

func parseRegistryMirrors(files []ConfigFile) []string {
	var out []string
	for _, cf := range files {
		inMirrors := false
		for _, l := range strings.Split(cf.Content, "\n") {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
				inMirrors = strings.HasPrefix(t, "mirrors:")
				continue
			}
			if inMirrors {
				indent := len(l) - len(strings.TrimLeft(l, " \t"))
				if indent <= 2 && strings.HasSuffix(t, ":") {
					out = append(out, strings.Trim(strings.TrimSuffix(t, ":"), `"'`))
				}
			}
		}
	}
	return out
}

func parseImages(s string) []Image {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var doc struct {
		Images []struct {
			ID          string   `json:"id"`
			RepoTags    []string `json:"repoTags"`
			RepoDigests []string `json:"repoDigests"`
			Size        string   `json:"size"`
		} `json:"images"`
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return nil
	}
	out := make([]Image, 0, len(doc.Images))
	for _, im := range doc.Images {
		sz, _ := strconv.ParseInt(im.Size, 10, 64)
		out = append(out, Image{ID: im.ID, Tags: im.RepoTags, Digests: im.RepoDigests, Size: sz})
	}
	return out
}

func parseContainers(s string) []Container {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var doc struct {
		Containers []struct {
			ID       string `json:"id"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Image struct {
				Image string `json:"image"`
			} `json:"image"`
			ImageRef string            `json:"imageRef"`
			Labels   map[string]string `json:"labels"`
		} `json:"containers"`
	}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		return nil
	}
	out := make([]Container, 0, len(doc.Containers))
	for _, c := range doc.Containers {
		out = append(out, Container{ID: c.ID, Name: c.Metadata.Name, Image: c.Image.Image, ImageRef: c.ImageRef, Pod: c.Labels["io.kubernetes.pod.namespace"] + "/" + c.Labels["io.kubernetes.pod.name"]})
	}
	return out
}

func parseTarballs(s string) []Tarball {
	var out []Tarball
	var cur *Tarball
	var body strings.Builder
	finish := func() {
		if cur == nil {
			return
		}
		content := strings.TrimSpace(body.String())
		if content == "(cached)" {
			cur.Cached = true
		} else if content != "" {
			cur.Images = tarballImages(cur.Path, content)
			cur.Parsed = true
		}
		out = append(out, *cur)
		body.Reset()
	}
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "--- ") {
			finish()
			f := strings.Split(strings.TrimPrefix(l, "--- "), "|")
			cur = &Tarball{Path: f[0]}
			if len(f) > 1 {
				cur.Size, _ = strconv.ParseInt(f[1], 10, 64)
			}
			if len(f) > 2 {
				if mt, err := strconv.ParseInt(f[2], 10, 64); err == nil {
					cur.ModTime = time.Unix(mt, 0)
				}
			}
			continue
		}
		body.WriteString(l)
		body.WriteByte('\n')
	}
	finish()
	return out
}

func tarballImages(path, content string) []string {
	if strings.HasSuffix(path, ".txt") {
		var imgs []string
		for _, l := range nonEmpty(content) {
			t := strings.TrimSpace(l)
			if !strings.HasPrefix(t, "#") {
				imgs = append(imgs, t)
			}
		}
		return imgs
	}
	var manifest []struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal([]byte(content), &manifest); err != nil {
		return nil
	}
	var imgs []string
	for _, m := range manifest {
		imgs = append(imgs, m.RepoTags...)
	}
	return imgs
}

// FIPS reports whether the kernel runs in FIPS mode.
func (i *Info) FIPS() bool { return i.Hardening["fips"] == "1" }

// ServiceState returns "active"/"inactive"/"" for a hardening service key.
func (i *Info) ServiceState(name string) string {
	f := strings.Fields(i.Hardening["svc_"+name])
	if len(f) >= 2 {
		return f[1]
	}
	return ""
}

// ServiceEnabled returns the unit file state (enabled/disabled/masked/static).
func (i *Info) ServiceEnabled(name string) string {
	f := strings.Fields(i.Hardening["svc_"+name])
	if len(f) >= 3 {
		return f[2]
	}
	return ""
}

// HardeningItem is one runtime-vs-boot fact.
type HardeningItem struct {
	Name     string
	Runtime  string // what is in effect now
	Boot     string // what the configuration says for the next boot
	OK       bool   // runtime state is the desired one
	Mismatch bool   // runtime and boot config disagree
	Detail   string
}

// HardeningItems derives the at-a-glance table (runtime vs boot config).
func (i *Info) HardeningItems() []HardeningItem {
	h := i.Hardening
	var out []HardeningItem
	cmdline := h["cmdline"]
	has := func(k string) bool { return strings.Contains(" "+cmdline+" ", " "+k+" ") }

	// MAC
	switch {
	case h["selinux"] != "":
		rt := h["selinux"]
		cfg := h["selinux_config"]
		if cfg == "" {
			cfg = "?"
		}
		out = append(out, HardeningItem{Name: "SELinux", Runtime: rt, Boot: cfg, OK: strings.EqualFold(rt, "Enforcing"), Mismatch: !strings.EqualFold(rt, cfg)})
	case h["apparmor"] != "" || h["apparmor_installed"] != "":
		rt := "disabled"
		if h["apparmor"] == "Y" {
			rt = "enabled"
			if n := h["apparmor_enforced"]; n != "" {
				rt += " (" + n + " enforced)"
			}
		}
		boot := "enabled"
		if has("apparmor=0") || strings.Contains(cmdline, "security=selinux") || i.ServiceEnabled("apparmor") == "disabled" || i.ServiceEnabled("apparmor") == "masked" {
			boot = "disabled"
		}
		out = append(out, HardeningItem{Name: "AppArmor", Runtime: rt, Boot: boot, OK: h["apparmor"] == "Y" && h["apparmor_enforced"] != "0", Mismatch: (h["apparmor"] == "Y") != (boot == "enabled")})
	default:
		out = append(out, HardeningItem{Name: "MAC", Runtime: "none", Boot: "none", OK: false})
	}

	// FIPS
	rt := map[string]string{"1": "on", "0": "off"}[h["fips"]]
	if rt == "" {
		rt = "?"
	}
	boot := "?"
	switch {
	case h["fips_boot"] == "yes" || has("fips=1"):
		boot = "on"
	case h["fips_boot"] == "no":
		boot = "off"
	}
	if strings.Contains(strings.ToLower(h["ubuntu_pro"]), "fips") && strings.Contains(strings.ToLower(h["ubuntu_pro"]), "enabled") {
		boot = "on (ubuntu pro)"
	}
	out = append(out, HardeningItem{Name: "FIPS", Runtime: rt, Boot: boot, OK: rt == "on", Mismatch: rt != "?" && boot != "?" && strings.HasPrefix(boot, "on") != (rt == "on"), Detail: h["fips_setup"]})

	svc := func(label, unit string, wantActive bool) {
		act := i.ServiceState(unit)
		en := i.ServiceEnabled(unit)
		if act == "" {
			out = append(out, HardeningItem{Name: label, Runtime: "not installed", Boot: "-", OK: !wantActive})
			return
		}
		bootOn := en == "enabled" || en == "static" || en == "enabled-runtime" || en == "alias" || en == "indirect"
		out = append(out, HardeningItem{Name: label, Runtime: act, Boot: en, OK: (act == "active") == wantActive, Mismatch: (act == "active") != bootOn})
	}
	svc("fapolicyd", "fapolicyd", true)
	svc("auditd", "auditd", true)
	if i.ServiceState("firewalld") != "" {
		svc("firewalld", "firewalld", true)
	}
	if i.ServiceState("ufw") != "" || h["ufw"] != "" {
		rt := h["ufw"]
		if rt == "" {
			rt = i.ServiceState("ufw")
		}
		boot := "?"
		switch h["ufw_config"] {
		case "yes":
			boot = "enabled"
		case "no":
			boot = "disabled"
		}
		out = append(out, HardeningItem{Name: "ufw", Runtime: rt, Boot: boot, OK: strings.HasPrefix(rt, "active"), Mismatch: boot != "?" && strings.HasPrefix(rt, "active") != (boot == "enabled")})
	}
	if i.ServiceState("firewalld") == "" && i.ServiceState("ufw") == "" && h["ufw"] == "" {
		out = append(out, HardeningItem{Name: "firewall", Runtime: "none found", Boot: "-", OK: false})
	}
	if v := h["secureboot"]; v != "" {
		out = append(out, HardeningItem{Name: "Secure Boot", Runtime: strings.TrimPrefix(v, "SecureBoot "), Boot: "-", OK: strings.Contains(v, "enabled")})
	}
	if v := h["lockdown"]; v != "" {
		cur := v
		if a := strings.Index(v, "["); a >= 0 {
			if b := strings.Index(v[a:], "]"); b > 0 {
				cur = v[a+1 : a+b]
			}
		}
		boot := "none"
		for _, m := range []string{"integrity", "confidentiality"} {
			if has("lockdown=" + m) {
				boot = m
			}
		}
		out = append(out, HardeningItem{Name: "Kernel lockdown", Runtime: cur, Boot: boot, OK: cur != "none", Mismatch: cur != boot && boot != "none"})
	}
	if v := h["crypto_policy"]; v != "" {
		out = append(out, HardeningItem{Name: "Crypto policy", Runtime: v, Boot: v, OK: strings.HasPrefix(v, "FIPS") || strings.HasPrefix(v, "DEFAULT") || strings.HasPrefix(v, "FUTURE")})
	}
	rb := "no"
	if h["reboot_required"] == "yes" {
		rb = "yes"
	}
	out = append(out, HardeningItem{Name: "Reboot required", Runtime: rb, Boot: "-", OK: rb == "no"})
	return out
}

// UnusedImages returns images not referenced by any running container.
func (i *Info) UnusedImages() (unused []Image, unusedBytes int64) {
	used := map[string]bool{}
	for _, c := range i.Containers {
		used[c.Image] = true
		used[c.ImageRef] = true
	}
	for _, im := range i.Images {
		inUse := used[im.ID]
		if !inUse {
			for _, t := range im.Tags {
				if used[t] {
					inUse = true
				}
			}
		}
		if !inUse {
			for _, d := range im.Digests {
				if used[d] {
					inUse = true
				}
			}
		}
		if !inUse {
			unused = append(unused, im)
			unusedBytes += im.Size
		}
	}
	return
}

// TarballKeys returns "path|size|mtime" cache keys for parsed tarballs.
func (i *Info) TarballKeys() []string {
	var keys []string
	for _, t := range i.Tarballs {
		if t.Parsed || t.Cached {
			keys = append(keys, t.Path+"|"+strconv.FormatInt(t.Size, 10)+"|"+strconv.FormatInt(t.ModTime.Unix(), 10))
		}
	}
	return keys
}

// MergeSTIG carries the OS STIG facts of a previous collection into this
// one when the probe did not re-collect them (they are gathered on demand,
// not every cycle).
func (i *Info) MergeSTIG(prev *Info) {
	if i.STIGProbed || prev == nil || !prev.STIGProbed {
		return
	}
	i.AdoptSTIG(prev, prev.STIGCollected)
}

// AdoptSTIG takes the OS STIG facts of src (a finished staged collection or
// a previous probe) as this node's, collected at the given time.
func (i *Info) AdoptSTIG(src *Info, at time.Time) {
	i.STIGProbed, i.STIGCollected = true, at
	i.SysctlAll, i.Packages, i.UnitFiles, i.UnitStates = src.SysctlAll, src.Packages, src.UnitFiles, src.UnitStates
	i.Findmnt, i.Fstab, i.SSHD = src.Findmnt, src.Fstab, src.SSHD
	i.AuditRules, i.AuditRuleFiles, i.Modprobe, i.LoadedModules, i.GrubArgs = src.AuditRules, src.AuditRuleFiles, src.Modprobe, src.LoadedModules, src.GrubArgs
	i.STIGStat, i.STIGViol, i.STIGFiles = src.STIGStat, src.STIGViol, src.STIGFiles
	i.STIGCmd, i.STIGSweep, i.Passwd, i.Groups, i.ShadowMeta = src.STIGCmd, src.STIGSweep, src.Passwd, src.Groups, src.ShadowMeta
	i.SSSDConf, i.UFWStatus, i.SELinuxLogins, i.Lsblk = src.SSSDConf, src.UFWStatus, src.SELinuxLogins, src.Lsblk
}

// MergeConfig carries the config tier forward from the previous probe when
// this one ran without it (light cycle). Hardening keys the live part
// printed win; the slow ones (fips_setup, secureboot, audit_rules, ...) are
// copied.
func (i *Info) MergeConfig(prev *Info) {
	if i.ConfigProbed || prev == nil || !prev.ConfigProbed {
		return
	}
	i.ConfigProbed, i.ConfigCollected = true, prev.ConfigCollected
	i.Certs, i.Sysctl, i.Perms = prev.Certs, prev.Sysctl, prev.Perms
	i.APIServerSANs, i.APIServerCert, i.TLSSAN = prev.APIServerSANs, prev.APIServerCert, prev.TLSSAN
	if i.NTPSynced == nil { // timedatectl only runs on config cycles when chrony/timesyncd are not there
		i.NTPSynced, i.NTPEnabled = prev.NTPSynced, prev.NTPEnabled
	}
	i.ConfigFiles, i.ExtraFiles, i.Manifests, i.StaticPods, i.Settings = prev.ConfigFiles, prev.ExtraFiles, prev.Manifests, prev.StaticPods, prev.Settings
	i.CNI, i.Registries, i.RegistryMirrors, i.ContainerdHosts, i.ContainerdConfig = prev.CNI, prev.Registries, prev.RegistryMirrors, prev.ContainerdHosts, prev.ContainerdConfig
	i.Preflight.mergeConfig(&prev.Preflight)
	if i.Hardening == nil {
		i.Hardening = map[string]string{}
	}
	for k, v := range prev.Hardening {
		if _, ok := i.Hardening[k]; !ok {
			i.Hardening[k] = v
		}
	}
}

// MergeHeavy copies heavy-mode results from a previous collection when the
// current one did not include them.
func (i *Info) MergeHeavy(prev *Info) {
	if prev == nil || i.Heavy {
		if prev != nil && i.Heavy {
			// keep cached tarball manifests
			byPath := map[string]Tarball{}
			for _, t := range prev.Tarballs {
				byPath[t.Path] = t
			}
			for idx := range i.Tarballs {
				if i.Tarballs[idx].Cached {
					if p, ok := byPath[i.Tarballs[idx].Path]; ok {
						i.Tarballs[idx].Images = p.Images
						i.Tarballs[idx].Parsed = p.Parsed
					}
				}
			}
		}
		return
	}
	i.Images = prev.Images
	i.PVDirs = prev.PVDirs
	i.Containers = prev.Containers
	i.Tarballs = prev.Tarballs
	i.Journal = prev.Journal
	i.LogFiles = prev.LogFiles
	i.CrictlInfo = prev.CrictlInfo
	i.Preflight.mergeHeavy(&prev.Preflight)
}
