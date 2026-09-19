package nodeinfo

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Info is everything collected from one node.
type Info struct {
	Node      string
	Host      string
	Collected time.Time
	Duration  time.Duration
	Err       error
	Heavy     bool

	Hostname, Kernel, Arch string
	Uptime                 time.Duration
	Load1, Load5, Load15   float64
	CPUs                   int
	CPUPct                 float64
	MemTotal, MemAvail     uint64
	SwapTotal, SwapFree    uint64
	MemPct                 float64
	Mounts                 []Mount
	Services               []Service
	Units                  []Unit
	NTPSynced              *bool
	NTPEnabled             *bool
	ClockOffset            time.Duration
	Dist                   string
	ControlPlane           bool
	Certs                  []Cert
	KubeletFlags           map[string]string
	Sysctl                 map[string]string
	Perms                  []Perm
	EtcdUser               bool
	SELinux                string
	ConfigFiles            []ConfigFile      // rke2/k3s config.yaml(.d) (secrets masked)
	Settings               map[string]string // merged top-level key: value from config files
	Rancher                RancherNode
	CNI                    []CNIConf
	Registries             []ConfigFile
	RegistryMirrors        []string // registry hosts with mirrors in registries.yaml
	ContainerdHosts        []string // registries containerd has certs.d/hosts.toml for
	ContainerdConfig       []ConfigFile

	// heavy
	Images     []Image
	Containers []Container
	Tarballs   []Tarball
	Journal    []string
	LogFiles   []ConfigFile
	CrictlInfo string
}

// Mount is one filesystem from df.
type Mount struct {
	Filesystem, Type, Mountpoint string
	SizeKB, UsedKB, AvailKB      int64
	UsePct                       int
	InodePct                     int
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
}

// ConfigFile is a (possibly masked) file dump.
type ConfigFile struct {
	Path    string
	Content string
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
	info := &Info{Node: node, Host: host, Collected: time.Now(), KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}}
	secs := splitSections(out)

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
	parseMem(info, secs["MEM"])
	info.Mounts = parseDF(secs["DF"])
	applyInodes(info.Mounts, secs["DFI"])
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
	if lines := nonEmpty(secs["NTP"]); len(lines) > 0 {
		b := lines[0] == "yes"
		info.NTPSynced = &b
		if len(lines) > 1 {
			e := lines[1] == "yes"
			info.NTPEnabled = &e
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
		if d == "/var/lib/rancher/rke2/server" || d == "/var/lib/rancher/k3s/server" || d == "/etc/kubernetes/manifests" || d == "/var/lib/etcd" || d == "/var/lib/rancher/rke2/server/db/etcd" {
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
	info.ConfigFiles = parseDumps(secs["RKE2CFG"])
	for _, cf := range info.ConfigFiles {
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
	pa, pb := fields(a), fields(b)
	if len(pa) < 5 || len(pb) < 5 || pa[0] != "cpu" || pb[0] != "cpu" {
		return -1
	}
	sum := func(f []string) (total, idle float64) {
		for i := 1; i < len(f); i++ {
			v, _ := strconv.ParseFloat(f[i], 64)
			total += v
			if i == 4 || i == 5 { // idle + iowait
				idle += v
			}
		}
		return
	}
	t1, i1 := sum(pa)
	t2, i2 := sum(pb)
	if t2-t1 <= 0 {
		return -1
	}
	return 100 * (1 - (i2-i1)/(t2-t1))
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
	i.Containers = prev.Containers
	i.Tarballs = prev.Tarballs
	i.Journal = prev.Journal
	i.LogFiles = prev.LogFiles
	i.CrictlInfo = prev.CrictlInfo
}
