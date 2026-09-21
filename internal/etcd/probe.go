// Package etcd probes etcd on control-plane nodes over SSH: it detects how
// etcd is configured (rke2 config.yaml / generated config / static pod /
// kubeadm manifest / systemd unit), checks health and metrics with the right
// client certificates, runs etcdctl (directly or through crictl) and finds
// snapshot/backup evidence.
package etcd

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s-health-tui/internal/config"
	"k8s-health-tui/internal/perf"
)

// Probe is the result of probing etcd on one node.
type Probe struct {
	Node      string
	Collected time.Time
	Duration  time.Duration
	Err       error

	// Cost is what this probe cost the node (PERF section) and the session.
	Cost       perf.RemoteCost
	OutBytes   int
	ScriptSize int

	Dist       string
	Hostname   string
	Endpoint   string
	CA, Cert   string
	Key        string
	DataDir    string
	Sources    []string     // where etcd's configuration comes from
	ConfigDump []ConfigFile // masked config file excerpts
	RKE2Config map[string]string

	// Encryption at rest: the apiserver's provider configuration (token
	// names only) and a sampled Secret from etcd proving what is stored.
	Encryption *Encryption

	Health         *Health
	Metrics        *Metrics
	EtcdctlVia     string
	EtcdctlDiag    string
	Stderr         string
	Missing        []string // cert/tool paths that were expected but not readable
	Members        []Member
	Statuses       []EndpointStatus
	Alarms         []Alarm
	EndpointHealth []EndpointHealth
	EtcdctlOut     string

	DataDirUsedKB int64
	DataDirFS     *FS

	// on-disk raft evidence, readable even when etcd is down (power outage)
	LocalMemberID    string        // this node's member id from its own etcd log
	LeaderEvents     []LeaderEvent // leader elections seen in the local etcd log, oldest first
	LeaderLogSkipped bool          // the log scan was skipped this cycle (healthy member, not a full cycle)
	FullSkipped      bool          // config sources/dumps, snapshots, backup hints not collected (light cycle)
	EtcdctlSkipped   bool          // etcdctl queries skipped (API exec probe covers them)
	Raft             *RaftOnDisk

	SnapshotDirs []SnapshotDir
	BackupHints  []string
	Raw          string

	// Peers is the cluster membership as this node's disk knows it (members
	// bucket of the bbolt db, initial-cluster of the generated config or
	// manifest): readable with etcd down, which is when the rescue needs it.
	Peers        []Peer
	SelfName     string // this member's name (data dir "name" file)
	PeersSkipped bool   // not scanned this cycle (healthy member, light cycle)
}

// Peer is one member seen on disk, keyed by its peer address.
type Peer struct {
	Host    string // peer URL host (the address the rescue reaches it on)
	PeerURL string
	Name    string // member name (rke2: <hostname>-<8 hex>)
	ID      string // member id, hex ("" when only the config knew it)
	Source  string // db | config | db+config
}

// NodeName is the Kubernetes node name a member name most likely belongs
// to: rke2/k3s append "-<8 hex>" to the hostname, kubeadm uses the node
// name as is.
func (pr Peer) NodeName() string {
	return memberNodeName(pr.Name)
}

var memberSuffixRe = regexp.MustCompile(`-[0-9a-f]{8}$`)

func memberNodeName(member string) string {
	return memberSuffixRe.ReplaceAllString(member, "")
}

// LeaderEvent is one "X became/elected leader at term N" line from the etcd log.
type LeaderEvent struct {
	Time   time.Time
	Term   uint64
	Leader string // member id, hex
	Line   string
}

// RaftOnDisk is what the data dir says about the member's raft state:
// snapshot file names are <term>-<index>.snap, WAL names <seq>-<first index>.wal.
type RaftOnDisk struct {
	SnapTerm, SnapIndex uint64
	WALSeq, WALIndex    uint64
	WALLastWrite        time.Time
}

// ConfigFile is a masked config excerpt.
type ConfigFile struct {
	Path, Content string
}

// Health is the /health response.
type Health struct {
	Healthy bool
	Reason  string
	Raw     string
}

// Metrics are the interesting values from /metrics.
type Metrics struct {
	HasLeader, IsLeader     bool
	LeaderChanges           float64
	DBSize, DBSizeInUse     float64
	Quota                   float64
	WalFsyncAvgMs           float64
	WalFsyncCount           float64
	BackendCommitAvgMs      float64
	ProposalsFailed         float64
	ProposalsPending        float64
	SlowApply, SlowReadIdx  float64
	ServerVersion           string
	ClusterVersion          string
	Keys                    float64
	PeerRTTAvgMs            float64
	HealthFailures          float64
	ReadIndexesFailed       float64
	SnapshotApplyInProgress float64
}

// Member is an etcd cluster member.
type Member struct {
	ID         string
	Name       string
	PeerURLs   []string
	ClientURLs []string
	IsLearner  bool
}

// EndpointStatus is etcdctl endpoint status for one member.
type EndpointStatus struct {
	Endpoint    string
	Version     string
	DBSize      int64
	DBSizeInUse int64
	Leader      string
	MemberID    string
	RaftTerm    uint64
	RaftIndex   uint64
	IsLearner   bool
	Errors      []string
}

// Alarm is an active etcd alarm.
type Alarm struct {
	MemberID string
	Type     string
}

// FS is filesystem usage of the data dir.
type FS struct {
	SizeKB, UsedKB, AvailKB int64
	UsePct                  int
	Mount                   string
}

// SnapshotDir is a directory scanned for snapshot files.
type SnapshotDir struct {
	Path  string
	Files []SnapshotFile
}

// Encryption is the evidence behind "secrets encrypted at rest".
type Encryption struct {
	ConfigFile   string   // --encryption-provider-config of the running apiserver
	Tokens       []string // provider / resource tokens in file order (aescbc, identity, secrets, ...)
	SampleKey    string   // etcd key of the sampled Secret
	SamplePrefix string   // first 24 printable bytes of its stored value
}

var providerNames = map[string]bool{"aescbc": true, "aesgcm": true, "secretbox": true, "kms": true, "identity": true}

// Providers lists the providers in configuration order.
func (e *Encryption) Providers() []string {
	if e == nil {
		return nil
	}
	var out []string
	for _, t := range e.Tokens {
		if providerNames[t] {
			out = append(out, t)
		}
	}
	return out
}

// Sampled reports whether a Secret was read from etcd and whether it was
// stored encrypted; Provider is the provider named in the stored prefix.
func (e *Encryption) Sampled() (sampled, encrypted bool, provider string) {
	if e == nil || e.SamplePrefix == "" {
		return false, false, ""
	}
	if !strings.HasPrefix(e.SamplePrefix, "k8s:enc:") {
		return true, false, ""
	}
	f := strings.Split(e.SamplePrefix, ":")
	if len(f) >= 3 {
		provider = f[2]
	}
	return true, true, provider
}

// SnapshotFile is one snapshot on disk.
type SnapshotFile struct {
	Name    string
	Size    int64
	ModTime time.Time
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9_./:@%=+,-]`)

// Clean strips every character outside the set safe to substitute into a
// shell script.
func Clean(s string) string { return unsafeChars.ReplaceAllString(s, "") }

// Script renders the probe script with config overrides. full=true also
// runs the rarely-changing sections (config sources/dumps, snapshot
// listings, backup hints) and scans the etcd container log for leader
// elections on healthy members (done every cycle on unhealthy ones).
// etcdctl=false skips the etcdctl / crictl exec queries because the API-side
// exec probe already answered; Probe.Merge carries the previous values.
func Script(cfg config.Etcd, full, etcdctl bool) string {
	dirs := make([]string, 0, len(cfg.BackupDirs))
	for _, d := range cfg.BackupDirs {
		if c := Clean(d); c != "" {
			dirs = append(dirs, c)
		}
	}
	s := script
	s = strings.ReplaceAll(s, "__EXTRA_DIRS__", strings.Join(dirs, " "))
	s = strings.ReplaceAll(s, "__EP__", Clean(cfg.Endpoint))
	s = strings.ReplaceAll(s, "__CA__", Clean(cfg.CACert))
	s = strings.ReplaceAll(s, "__CERT__", Clean(cfg.ClientCert))
	s = strings.ReplaceAll(s, "__KEY__", Clean(cfg.ClientKey))
	s = strings.ReplaceAll(s, "__FULL__", map[bool]string{true: "1", false: "0"}[full])
	s = strings.ReplaceAll(s, "__CTL__", map[bool]string{true: "1", false: "0"}[etcdctl])
	// PERF footer goes before the END marker the parsers look for
	s = strings.Replace(s, "\nsec END\n", perf.Footer+"sec END\n", 1)
	return s
}

//go:embed scripts/probe.sh
var script string

// Parse converts the script output into a Probe.
func Parse(node, out string) *Probe {
	p := &Probe{Node: node, Collected: time.Now(), RKE2Config: map[string]string{}, Raw: out}
	secs := splitSections(out)
	p.OutBytes = len(out)
	p.Cost = perf.ParseSection(secs["PERF"])
	p.Dist = strings.TrimSpace(secs["DIST"])
	p.Hostname = strings.TrimSpace(secs["HOST"])
	for _, l := range lines(secs["PATHS"]) {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "ca":
			p.CA = v
		case "cert":
			p.Cert = v
		case "key":
			p.Key = v
		case "endpoint":
			p.Endpoint = v
		case "datadir":
			p.DataDir = v
		case "missing":
			p.Missing = append(p.Missing, v)
		}
	}
	_, hasSource := secs["SOURCE"]
	p.FullSkipped = !hasSource
	p.Sources = lines(secs["SOURCE"])
	for _, l := range lines(secs["RKE2CONFIG"]) {
		// "<file>: key: value"
		_, rest, ok := strings.Cut(l, ": ")
		if !ok {
			continue
		}
		k, v, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		p.RKE2Config[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	p.ConfigDump = parseDumps(secs["CONFIGDUMP"])
	if h := strings.TrimSpace(secs["HEALTH"]); h != "" {
		p.Health = parseHealth(h)
	}
	if m := strings.TrimSpace(secs["METRICS"]); m != "" {
		p.Metrics = parseMetrics(m)
	}
	for _, l := range lines(secs["ENCCONFIG"]) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		if p.Encryption == nil {
			p.Encryption = &Encryption{}
		}
		switch k {
		case "file":
			p.Encryption.ConfigFile = v
		case "tokens":
			p.Encryption.Tokens = strings.Fields(v)
		}
	}
	parseEtcdctl(p, secs["ETCDCTL"])
	parseLeaderLog(p, secs["LEADERLOG"])
	parsePeers(p, secs["PEERS"])
	p.Raft = parseRaft(secs["RAFT"])
	dd := lines(secs["DATADIR"])
	if len(dd) > 1 {
		p.DataDirUsedKB, _ = strconv.ParseInt(strings.TrimSpace(dd[1]), 10, 64)
	}
	if len(dd) > 2 {
		f := strings.Fields(dd[2])
		if len(f) >= 6 {
			fs := &FS{}
			fs.SizeKB, _ = strconv.ParseInt(f[1], 10, 64)
			fs.UsedKB, _ = strconv.ParseInt(f[2], 10, 64)
			fs.AvailKB, _ = strconv.ParseInt(f[3], 10, 64)
			fs.UsePct, _ = strconv.Atoi(strings.TrimSuffix(f[4], "%"))
			fs.Mount = strings.Join(f[5:], " ")
			p.DataDirFS = fs
		}
	}
	seen := map[string]bool{}
	for _, d := range parseDumps(secs["SNAPSHOTS"]) {
		if seen[d.Path] {
			continue
		}
		seen[d.Path] = true
		sd := SnapshotDir{Path: d.Path}
		for _, l := range lines(d.Content) {
			f := strings.SplitN(l, "|", 3)
			if len(f) != 3 {
				continue
			}
			sf := SnapshotFile{Name: f[2]}
			sf.Size, _ = strconv.ParseInt(f[0], 10, 64)
			if mt, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				sf.ModTime = time.Unix(mt, 0)
			}
			if i := strings.LastIndex(sf.Name, "/"); i >= 0 {
				sf.Name = sf.Name[i+1:]
			}
			sd.Files = append(sd.Files, sf)
		}
		sort.Slice(sd.Files, func(i, j int) bool { return sd.Files[i].ModTime.After(sd.Files[j].ModTime) })
		p.SnapshotDirs = append(p.SnapshotDirs, sd)
	}
	p.BackupHints = lines(secs["BACKUPHINTS"])
	return p
}

var (
	leaderRe     = regexp.MustCompile(`(?:elected leader|changed leader from [0-9a-f]+ to) ([0-9a-f]{8,16}) at term (\d+)|([0-9a-f]{8,16}) became leader at term (\d+)`)
	logTimeRe    = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})`)
	snapNameRe   = regexp.MustCompile(`([0-9a-f]{16})-([0-9a-f]{16})\.snap$`)
	walNameRe    = regexp.MustCompile(`^(\d+) .*?([0-9a-f]{16})-([0-9a-f]{16})\.wal$`)
	raftTsLayout = []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05.000Z0700"}
)

func parseLeaderLog(p *Probe, raw string) {
	for _, l := range lines(raw) {
		if strings.HasPrefix(l, "source=") {
			continue
		}
		if l == "skipped=healthy" {
			p.LeaderLogSkipped = true
			return
		}
		if strings.HasPrefix(l, "local-member-id=") {
			p.LocalMemberID = strings.TrimPrefix(l, "local-member-id=")
			continue
		}
		g := leaderRe.FindStringSubmatch(l)
		if g == nil {
			continue
		}
		ev := LeaderEvent{Line: l}
		if g[1] != "" {
			ev.Leader = g[1]
			ev.Term, _ = strconv.ParseUint(g[2], 10, 64)
		} else {
			ev.Leader = g[3]
			ev.Term, _ = strconv.ParseUint(g[4], 10, 64)
		}
		if ts := logTimeRe.FindString(l); ts != "" {
			for _, layout := range raftTsLayout {
				if t, err := time.Parse(layout, ts); err == nil {
					ev.Time = t
					break
				}
			}
		}
		p.LeaderEvents = append(p.LeaderEvents, ev)
	}
}

var (
	peerJSONRe    = regexp.MustCompile(`\{"id":(\d+),"peerURLs":\[([^\]]*)\],"name":"([^"]*)"`)
	peerURLHostRe = regexp.MustCompile(`^https?://(\[[^\]]+\]|[^:/]+)`)
)

// parsePeers merges the db and config evidence into Probe.Peers, one entry
// per peer address (a freed bbolt page may still hold a member removed
// since; the config line is the freshest name for an address).
func parsePeers(p *Probe, raw string) {
	byHost := map[string]*Peer{}
	var order []string
	add := func(host, url, name, id, src string) {
		if host == "" {
			return
		}
		pr, ok := byHost[host]
		if !ok {
			pr = &Peer{Host: host, PeerURL: url}
			byHost[host] = pr
			order = append(order, host)
		}
		if pr.PeerURL == "" {
			pr.PeerURL = url
		}
		switch src {
		case "config":
			pr.Name = name // the config is the freshest name for the address
		case "db":
			if pr.Name == "" {
				pr.Name = name
			}
			if id != "" {
				pr.ID = id
			}
		}
		if pr.Source == "" || pr.Source == src {
			pr.Source = src
		} else {
			pr.Source = "db+config"
		}
	}
	for _, l := range lines(raw) {
		switch {
		case l == "skipped=healthy":
			p.PeersSkipped = true
			return
		case strings.HasPrefix(l, "self: "):
			p.SelfName = strings.TrimPrefix(l, "self: ")
		case strings.HasPrefix(l, "db: "):
			g := peerJSONRe.FindStringSubmatch(l)
			if g == nil {
				continue
			}
			for _, u := range strings.Split(g[2], ",") {
				u = strings.Trim(strings.TrimSpace(u), `"`)
				add(peerURLHost(u), u, g[3], hexID(g[1]), "db")
			}
		case strings.HasPrefix(l, "config: initial-cluster:"):
			list := strings.TrimSpace(strings.TrimPrefix(l, "config: initial-cluster:"))
			for _, ent := range strings.Split(list, ",") {
				name, u, ok := strings.Cut(strings.TrimSpace(ent), "=")
				if !ok {
					continue
				}
				add(peerURLHost(u), u, name, "", "config")
			}
		}
	}
	for _, h := range order {
		p.Peers = append(p.Peers, *byHost[h])
	}
}

func peerURLHost(u string) string {
	g := peerURLHostRe.FindStringSubmatch(u)
	if g == nil {
		return ""
	}
	return strings.Trim(g[1], "[]")
}

func parseRaft(raw string) *RaftOnDisk {
	var r *RaftOnDisk
	for _, l := range lines(raw) {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		if r == nil {
			r = &RaftOnDisk{}
		}
		switch k {
		case "snap":
			if g := snapNameRe.FindStringSubmatch(v); g != nil {
				r.SnapTerm, _ = strconv.ParseUint(g[1], 16, 64)
				r.SnapIndex, _ = strconv.ParseUint(g[2], 16, 64)
			}
		case "wal":
			if g := walNameRe.FindStringSubmatch(v); g != nil {
				if mt, err := strconv.ParseInt(g[1], 10, 64); err == nil {
					r.WALLastWrite = time.Unix(mt, 0)
				}
				r.WALSeq, _ = strconv.ParseUint(g[2], 16, 64)
				r.WALIndex, _ = strconv.ParseUint(g[3], 16, 64)
			}
		}
	}
	return r
}

// Merge carries forward what this probe deliberately skipped: the
// leader-log scan (healthy member on a light cycle), the full-cycle sections
// (config sources/dumps, snapshots, backup hints) and the etcdctl queries
// (API exec probe covered them).
func (p *Probe) Merge(prev *Probe) {
	if prev == nil {
		return
	}
	if p.LeaderLogSkipped {
		if p.LocalMemberID == "" {
			p.LocalMemberID = prev.LocalMemberID
		}
		if len(p.LeaderEvents) == 0 {
			p.LeaderEvents = prev.LeaderEvents
		}
	}
	if p.PeersSkipped && !prev.PeersSkipped {
		p.Peers, p.SelfName, p.PeersSkipped = prev.Peers, prev.SelfName, false
	}
	if p.FullSkipped && !prev.FullSkipped {
		p.Sources, p.ConfigDump, p.SnapshotDirs, p.BackupHints = prev.Sources, prev.ConfigDump, prev.SnapshotDirs, prev.BackupHints
		if prev.Encryption != nil {
			if p.Encryption == nil {
				p.Encryption = &Encryption{}
			}
			if p.Encryption.ConfigFile == "" {
				p.Encryption.ConfigFile, p.Encryption.Tokens = prev.Encryption.ConfigFile, prev.Encryption.Tokens
			}
		}
		if len(p.RKE2Config) == 0 {
			p.RKE2Config = prev.RKE2Config
		}
		p.FullSkipped = false
	}
	if p.EtcdctlSkipped && !prev.EtcdctlSkipped {
		p.EtcdctlVia, p.EtcdctlDiag, p.EtcdctlOut = prev.EtcdctlVia, prev.EtcdctlDiag, prev.EtcdctlOut
		p.Members, p.Statuses, p.Alarms, p.EndpointHealth = prev.Members, prev.Statuses, prev.Alarms, prev.EndpointHealth
		p.EtcdctlSkipped = false
		if prev.Encryption != nil && (p.Encryption == nil || p.Encryption.SamplePrefix == "") {
			if p.Encryption == nil {
				p.Encryption = &Encryption{}
			}
			p.Encryption.SampleKey, p.Encryption.SamplePrefix = prev.Encryption.SampleKey, prev.Encryption.SamplePrefix
		}
	}
}

// LastLeader returns the most recent leader election this node's log knows
// about: highest term wins, then latest timestamp.
func (p *Probe) LastLeader() (LeaderEvent, bool) {
	var best LeaderEvent
	found := false
	for _, ev := range p.LeaderEvents {
		if !found || ev.Term > best.Term || (ev.Term == best.Term && ev.Time.After(best.Time)) {
			best, found = ev, true
		}
	}
	return best, found
}

// LatestSnapshot returns the most recent snapshot file across all dirs.
func (p *Probe) LatestSnapshot() (SnapshotFile, string, bool) {
	var best SnapshotFile
	dir := ""
	found := false
	for _, d := range p.SnapshotDirs {
		for _, f := range d.Files {
			if !found || f.ModTime.After(best.ModTime) {
				best, dir, found = f, d.Path, true
			}
		}
	}
	return best, dir, found
}

// SnapshotCount returns the number of snapshot files found on the node.
func (p *Probe) SnapshotCount() int {
	n := 0
	for _, d := range p.SnapshotDirs {
		n += len(d.Files)
	}
	return n
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
		if strings.HasPrefix(line, "===") && len(line) > 3 && !strings.ContainsAny(line[3:], " \t{") {
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

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
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
		out = append(out, *cur)
	}
	for i := range out {
		out[i].Content = strings.TrimRight(out[i].Content, "\n")
	}
	return out
}

func parseHealth(raw string) *Health {
	h := &Health{Raw: raw}
	var doc struct {
		Health string `json:"health"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err == nil {
		h.Healthy = doc.Health == "true"
		h.Reason = doc.Reason
		return h
	}
	if raw == "curl-missing" {
		h.Reason = "curl not installed on node"
	} else {
		h.Reason = raw
	}
	return h
}

var metricLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)`)

func parseMetrics(raw string) *Metrics {
	m := &Metrics{}
	vals := map[string]float64{}
	for _, l := range strings.Split(raw, "\n") {
		g := metricLine.FindStringSubmatch(l)
		if g == nil {
			continue
		}
		name, labels, val := g[1], g[2], g[3]
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			continue
		}
		switch name {
		case "etcd_server_version":
			m.ServerVersion = labelValue(labels, "server_version")
			continue
		case "etcd_cluster_version":
			m.ClusterVersion = labelValue(labels, "cluster_version")
			continue
		}
		vals[name] += f
	}
	m.HasLeader = vals["etcd_server_has_leader"] > 0
	m.IsLeader = vals["etcd_server_is_leader"] > 0
	m.LeaderChanges = vals["etcd_server_leader_changes_seen_total"]
	m.DBSize = vals["etcd_mvcc_db_total_size_in_bytes"]
	m.DBSizeInUse = vals["etcd_mvcc_db_total_size_in_use_in_bytes"]
	m.Quota = vals["etcd_server_quota_backend_bytes"]
	if c := vals["etcd_disk_wal_fsync_duration_seconds_count"]; c > 0 {
		m.WalFsyncAvgMs = vals["etcd_disk_wal_fsync_duration_seconds_sum"] / c * 1000
		m.WalFsyncCount = c
	}
	if c := vals["etcd_disk_backend_commit_duration_seconds_count"]; c > 0 {
		m.BackendCommitAvgMs = vals["etcd_disk_backend_commit_duration_seconds_sum"] / c * 1000
	}
	if c := vals["etcd_network_peer_round_trip_time_seconds_count"]; c > 0 {
		m.PeerRTTAvgMs = vals["etcd_network_peer_round_trip_time_seconds_sum"] / c * 1000
	}
	m.ProposalsFailed = vals["etcd_server_proposals_failed_total"]
	m.ProposalsPending = vals["etcd_server_proposals_pending"]
	m.SlowApply = vals["etcd_server_slow_apply_total"]
	m.SlowReadIdx = vals["etcd_server_slow_read_indexes_total"]
	m.Keys = vals["etcd_debugging_mvcc_keys_total"]
	m.HealthFailures = vals["etcd_server_health_failures"]
	m.ReadIndexesFailed = vals["etcd_server_read_indexes_failed_total"]
	m.SnapshotApplyInProgress = vals["etcd_server_snapshot_apply_in_progress_total"]
	return m
}

func labelValue(labels, key string) string {
	labels = strings.Trim(labels, "{}")
	for _, kv := range strings.Split(labels, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func parseEtcdctl(p *Probe, raw string) {
	p.EtcdctlOut = strings.TrimSpace(raw)
	if p.EtcdctlOut == "skipped=api" {
		p.EtcdctlSkipped = true
		return
	}
	parts := map[string]string{}
	cur := ""
	for _, l := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "via=") {
			p.EtcdctlVia = strings.TrimPrefix(t, "via=")
			continue
		}
		if strings.HasPrefix(t, "diag=") {
			p.EtcdctlDiag = strings.TrimPrefix(t, "diag=")
			continue
		}
		if strings.HasPrefix(t, "---") {
			cur = strings.TrimPrefix(t, "---")
			continue
		}
		if cur != "" {
			parts[cur] += l + "\n"
		}
	}
	if s := strings.TrimSpace(parts["MEMBERS"]); s != "" {
		var doc map[string]any
		if err := decodeNumbers(s, &doc); err == nil {
			if list, ok := doc["members"].([]any); ok {
				for _, it := range list {
					m, _ := it.(map[string]any)
					p.Members = append(p.Members, Member{ID: hexID(numStr(m["ID"])), Name: str(m["name"]), PeerURLs: strList(m["peerURLs"]), ClientURLs: strList(m["clientURLs"]), IsLearner: boolOf(m["isLearner"])})
				}
				sort.Slice(p.Members, func(i, j int) bool { return p.Members[i].Name < p.Members[j].Name })
			}
		} else if p.EtcdctlDiag == "" {
			p.EtcdctlDiag = firstLine(s)
		}
	}
	if s := jsonArray(parts["STATUS"]); s != "" {
		var doc []map[string]any
		if err := decodeNumbers(s, &doc); err == nil {
			for _, e := range doc {
				st, _ := e["Status"].(map[string]any)
				es := statusFrom(st)
				es.Endpoint = str(e["Endpoint"])
				p.Statuses = append(p.Statuses, es)
			}
		}
	}
	if s := strings.TrimSpace(parts["GWSTATUS"]); s != "" {
		var st map[string]any
		if err := decodeNumbers(s, &st); err == nil && st["version"] != nil {
			es := statusFrom(st)
			es.Endpoint = p.Endpoint
			p.Statuses = append(p.Statuses, es)
		}
	}
	for _, key := range []string{"ALARMS", "GWALARMS"} {
		s := strings.TrimSpace(parts[key])
		if s == "" {
			continue
		}
		var doc map[string]any
		if err := decodeNumbers(s, &doc); err != nil {
			continue
		}
		list, _ := doc["alarms"].([]any)
		for _, it := range list {
			m, _ := it.(map[string]any)
			t := numStr(m["alarm"])
			switch t {
			case "1":
				t = "NOSPACE"
			case "2":
				t = "CORRUPT"
			case "0", "NONE":
				continue
			}
			p.Alarms = append(p.Alarms, Alarm{MemberID: hexID(numStr(m["memberID"])), Type: t})
		}
	}
	if s := strings.TrimSpace(parts["HEALTH"]); s != "" {
		p.EndpointHealth = parseEndpointHealth(s)
	}
	if enc := strings.TrimSpace(parts["ENCSAMPLE"]); enc != "" {
		if p.Encryption == nil {
			p.Encryption = &Encryption{}
		}
		for _, l := range strings.Split(enc, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
				switch k {
				case "key":
					p.Encryption.SampleKey = v
				case "prefix":
					p.Encryption.SamplePrefix = v
				}
			}
		}
	}
}

// ParseCtl parses etcdctl output in the probe's sectioned form
// (---MEMBERS / ---HEALTH / ---STATUS / ---ALARMS, each followed by the
// `-w json` output of the matching etcdctl command) into a Probe carrying
// only the cluster-state fields. Used by the etcd rescue between its steps.
func ParseCtl(node, raw string) *Probe {
	p := &Probe{Node: node, Collected: time.Now(), RKE2Config: map[string]string{}}
	parseEtcdctl(p, raw)
	return p
}

// Leader returns the member id every endpoint status agrees is the leader,
// or "" when there is none or they disagree.
func (p *Probe) Leader() string {
	leader := ""
	for _, st := range p.Statuses {
		if st.Leader == "" {
			return ""
		}
		if leader == "" {
			leader = st.Leader
		} else if st.Leader != leader {
			return ""
		}
	}
	return leader
}

// statusFrom converts an etcdctl or gRPC-gateway status object (numbers may
// be JSON numbers or strings) into an EndpointStatus.
func statusFrom(st map[string]any) EndpointStatus {
	es := EndpointStatus{Version: str(st["version"]), IsLearner: boolOf(st["isLearner"])}
	es.DBSize, _ = strconv.ParseInt(numStr(st["dbSize"]), 10, 64)
	es.DBSizeInUse, _ = strconv.ParseInt(numStr(st["dbSizeInUse"]), 10, 64)
	es.Leader = hexID(numStr(st["leader"]))
	es.RaftIndex, _ = strconv.ParseUint(numStr(st["raftIndex"]), 10, 64)
	es.RaftTerm, _ = strconv.ParseUint(numStr(st["raftTerm"]), 10, 64)
	if h, ok := st["header"].(map[string]any); ok {
		es.MemberID = hexID(numStr(h["member_id"]))
	}
	es.Errors = strList(st["errors"])
	return es
}

// jsonArray cuts an etcdctl `-w json` output down to its JSON array: with a
// member down, `endpoint health/status --cluster` prints client warnings
// before the array and "Error: unhealthy cluster" after it, on the same
// stream, and the array in between is the answer for the members that are
// up.
func jsonArray(raw string) string {
	i := strings.Index(raw, "[")
	j := strings.LastIndex(raw, "]")
	if i < 0 || j <= i {
		return ""
	}
	return raw[i : j+1]
}

// decodeNumbers unmarshals JSON keeping integers exact (etcd IDs are uint64).
func decodeNumbers(s string, v any) error {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	return d.Decode(v)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// numStr renders a JSON number or numeric string without float formatting.
func numStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatUint(uint64(t), 10)
	case json.Number:
		return t.String()
	}
	return ""
}

func boolOf(v any) bool {
	b, _ := v.(bool)
	return b
}

func strList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func hexID(s string) string {
	if s == "" {
		return ""
	}
	if n, err := strconv.ParseUint(s, 10, 64); err == nil {
		return fmt.Sprintf("%x", n)
	}
	return s
}

// Status returns the endpoint status for the given member id.
func (p *Probe) Status(memberID string) *EndpointStatus {
	for i := range p.Statuses {
		if p.Statuses[i].MemberID == memberID {
			return &p.Statuses[i]
		}
	}
	return nil
}
