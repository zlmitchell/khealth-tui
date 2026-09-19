// Package etcd probes etcd on control-plane nodes over SSH: it detects how
// etcd is configured (rke2 config.yaml / generated config / static pod /
// kubeadm manifest / systemd unit), checks health and metrics with the right
// client certificates, runs etcdctl (directly or through crictl) and finds
// snapshot/backup evidence.
package etcd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s-health-tui/internal/config"
)

// Probe is the result of probing etcd on one node.
type Probe struct {
	Node      string
	Collected time.Time
	Duration  time.Duration
	Err       error

	Dist       string
	Hostname   string
	Endpoint   string
	CA, Cert   string
	Key        string
	DataDir    string
	Sources    []string     // where etcd's configuration comes from
	ConfigDump []ConfigFile // masked config file excerpts
	RKE2Config map[string]string

	Health     *Health
	Metrics    *Metrics
	EtcdctlVia string
	Members    []Member
	Statuses   []EndpointStatus
	Alarms     []Alarm
	EtcdctlOut string

	DataDirUsedKB int64
	DataDirFS     *FS

	SnapshotDirs []SnapshotDir
	BackupHints  []string
	Raw          string
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

// SnapshotFile is one snapshot on disk.
type SnapshotFile struct {
	Name    string
	Size    int64
	ModTime time.Time
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9_./:@%=+,-]`)

func clean(s string) string { return unsafeChars.ReplaceAllString(s, "") }

// Script renders the probe script with config overrides.
func Script(cfg config.Etcd) string {
	dirs := make([]string, 0, len(cfg.BackupDirs))
	for _, d := range cfg.BackupDirs {
		if c := clean(d); c != "" {
			dirs = append(dirs, c)
		}
	}
	s := script
	s = strings.ReplaceAll(s, "__EXTRA_DIRS__", strings.Join(dirs, " "))
	s = strings.ReplaceAll(s, "__EP__", clean(cfg.Endpoint))
	s = strings.ReplaceAll(s, "__CA__", clean(cfg.CACert))
	s = strings.ReplaceAll(s, "__CERT__", clean(cfg.ClientCert))
	s = strings.ReplaceAll(s, "__KEY__", clean(cfg.ClientKey))
	return s
}

const script = `
sec() { printf '\n===%s\n' "$1"; }
export LC_ALL=C
EXTRA_DIRS='__EXTRA_DIRS__'
EP_OVERRIDE='__EP__'; CA_OVERRIDE='__CA__'; CERT_OVERRIDE='__CERT__'; KEY_OVERRIDE='__KEY__'
DIST=unknown; CA=; CERT=; KEY=; EP=https://127.0.0.1:2379; CRICTL=; CRI_EP=; DATADIR=; SNAPDIR=; ETCDCTL=
H=$(hostname)
if [ -d /var/lib/rancher/rke2/server/tls/etcd ]; then
  DIST=rke2
  CA=/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt
  CERT=/var/lib/rancher/rke2/server/tls/etcd/server-client.crt
  KEY=/var/lib/rancher/rke2/server/tls/etcd/server-client.key
  CRICTL=/var/lib/rancher/rke2/bin/crictl
  CRI_EP=unix:///run/k3s/containerd/containerd.sock
  DATADIR=/var/lib/rancher/rke2/server/db/etcd
  SNAPDIR=/var/lib/rancher/rke2/server/db/snapshots
elif [ -d /var/lib/rancher/k3s/server/tls/etcd ]; then
  DIST=k3s
  CA=/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt
  CERT=/var/lib/rancher/k3s/server/tls/etcd/server-client.crt
  KEY=/var/lib/rancher/k3s/server/tls/etcd/server-client.key
  DATADIR=/var/lib/rancher/k3s/server/db/etcd
  SNAPDIR=/var/lib/rancher/k3s/server/db/snapshots
elif [ -d /etc/kubernetes/pki/etcd ]; then
  DIST=kubeadm
  CA=/etc/kubernetes/pki/etcd/ca.crt
  if [ -f /etc/kubernetes/pki/etcd/healthcheck-client.crt ]; then
    CERT=/etc/kubernetes/pki/etcd/healthcheck-client.crt; KEY=/etc/kubernetes/pki/etcd/healthcheck-client.key
  elif [ -f /etc/kubernetes/pki/apiserver-etcd-client.crt ]; then
    CERT=/etc/kubernetes/pki/apiserver-etcd-client.crt; KEY=/etc/kubernetes/pki/apiserver-etcd-client.key
  fi
  CRICTL=$(command -v crictl 2>/dev/null)
  for s in /run/containerd/containerd.sock /var/run/crio/crio.sock /run/cri-dockerd.sock; do [ -S "$s" ] && { CRI_EP="unix://$s"; break; }; done
  DATADIR=/var/lib/etcd
  DD=$(grep -o -- '--data-dir=[^ "]*' /etc/kubernetes/manifests/etcd.yaml 2>/dev/null | head -1 | cut -d= -f2)
  [ -n "$DD" ] && DATADIR=$DD
elif [ -f /etc/ssl/etcd/ssl/ca.pem ]; then
  DIST=kubespray
  CA=/etc/ssl/etcd/ssl/ca.pem
  for n in "admin-$H" "node-$H" "member-$H"; do
    if [ -f "/etc/ssl/etcd/ssl/$n.pem" ]; then CERT="/etc/ssl/etcd/ssl/$n.pem"; KEY="/etc/ssl/etcd/ssl/$n-key.pem"; break; fi
  done
  DATADIR=/var/lib/etcd
fi
[ -n "$EP_OVERRIDE" ] && EP=$EP_OVERRIDE
[ -n "$CA_OVERRIDE" ] && CA=$CA_OVERRIDE
[ -n "$CERT_OVERRIDE" ] && CERT=$CERT_OVERRIDE
[ -n "$KEY_OVERRIDE" ] && KEY=$KEY_OVERRIDE
command -v etcdctl >/dev/null 2>&1 && ETCDCTL=$(command -v etcdctl)

sec DIST; echo "$DIST"
sec HOST; echo "$H"
sec PATHS
echo "ca=$CA"; echo "cert=$CERT"; echo "key=$KEY"; echo "endpoint=$EP"; echo "datadir=$DATADIR"
sec SOURCE
[ -f /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml ] && echo "static-pod /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml"
[ -f /etc/kubernetes/manifests/etcd.yaml ] && echo "static-pod /etc/kubernetes/manifests/etcd.yaml"
if [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then echo "systemd etcd.service ($(systemctl is-active etcd 2>/dev/null))"; fi
[ "$DIST" = k3s ] && echo "embedded k3s etcd (in-process)"
for m in /etc/kubernetes/manifests/kube-apiserver.yaml /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml; do
  [ -f "$m" ] && grep -o -- '--etcd-servers=[^ "]*' "$m" 2>/dev/null | head -1 | sed "s|^|apiserver $m: |"
done
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then
  for f in /etc/rancher/$DIST/config.yaml /etc/rancher/$DIST/config.yaml.d/*.yaml; do [ -f "$f" ] && echo "$DIST-config $f"; done
  [ -f /var/lib/rancher/$DIST/server/db/etcd/config ] && echo "etcd-config /var/lib/rancher/$DIST/server/db/etcd/config (generated by $DIST)"
fi
for f in /etc/etcd/etcd.conf /etc/etcd/etcd.conf.yml /etc/etcd/etcd.conf.yaml /etc/etcd.env /etc/default/etcd /etc/sysconfig/etcd; do [ -f "$f" ] && echo "etcd-config $f"; done
sec RKE2CONFIG
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then
  for f in /etc/rancher/$DIST/config.yaml /etc/rancher/$DIST/config.yaml.d/*.yaml; do
    [ -f "$f" ] || continue
    grep -E '^[[:space:]]*(etcd-|cluster-init|disable-etcd|server:|profile:|secrets-encryption)' "$f" 2>/dev/null | grep -viE 'access-key|secret-key|token' | sed "s|^|$f: |"
  done
fi
sec CONFIGDUMP
dump() { [ -f "$1" ] || return; echo "--- $1"; grep -viE 'token|password|secret-key|access-key' "$1" 2>/dev/null | head -200; }
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then dump /var/lib/rancher/$DIST/server/db/etcd/config; fi
if [ -f /etc/kubernetes/manifests/etcd.yaml ]; then echo "--- /etc/kubernetes/manifests/etcd.yaml (args)"; grep -E '^[[:space:]]*- --|image:' /etc/kubernetes/manifests/etcd.yaml; fi
if [ -f /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml ]; then echo "--- /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml (args)"; grep -E '^[[:space:]]*- --|image:' /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml; fi
for f in /etc/etcd/etcd.conf /etc/etcd/etcd.conf.yml /etc/etcd/etcd.conf.yaml /etc/etcd.env /etc/default/etcd /etc/sysconfig/etcd; do dump "$f"; done
if [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then echo "--- systemctl cat etcd"; systemctl cat etcd 2>/dev/null | grep -E '^(ExecStart|Environment|EnvironmentFile|User|WorkingDirectory)'; fi
CURL="curl -sS -m 8"
[ -n "$CA" ] && CURL="$CURL --cacert $CA"
[ -n "$CERT" ] && CURL="$CURL --cert $CERT --key $KEY"
sec HEALTH
if command -v curl >/dev/null 2>&1; then $CURL "$EP/health" 2>&1; else echo "curl-missing"; fi
sec METRICS
command -v curl >/dev/null 2>&1 && $CURL "$EP/metrics" 2>/dev/null | grep -E '^(etcd_server_has_leader|etcd_server_is_leader|etcd_server_leader_changes_seen_total|etcd_mvcc_db_total_size_in_bytes|etcd_mvcc_db_total_size_in_use_in_bytes|etcd_server_quota_backend_bytes|etcd_disk_wal_fsync_duration_seconds_(sum|count)|etcd_disk_backend_commit_duration_seconds_(sum|count)|etcd_server_proposals_failed_total|etcd_server_proposals_pending|etcd_server_slow_apply_total|etcd_server_slow_read_indexes_total|etcd_server_version|etcd_cluster_version|etcd_debugging_mvcc_keys_total|etcd_server_snapshot_apply_in_progress_total|etcd_network_peer_round_trip_time_seconds_(sum|count)|etcd_server_health_failures|etcd_server_read_indexes_failed_total)'
sec ETCDCTL
CID=
if [ -z "$ETCDCTL" ] && [ -n "$CRICTL" ] && [ -x "$CRICTL" ] && [ -n "$CRI_EP" ]; then
  CID=$("$CRICTL" -r "$CRI_EP" ps -q --name '^etcd$' 2>/dev/null | head -1)
fi
run_ctl() {
  if [ -n "$ETCDCTL" ]; then ETCDCTL_API=3 "$ETCDCTL" --endpoints="$EP" --cacert="$CA" --cert="$CERT" --key="$KEY" "$@" 2>&1
  elif [ -n "$CID" ]; then "$CRICTL" -r "$CRI_EP" exec "$CID" etcdctl --endpoints="$EP" --cacert="$CA" --cert="$CERT" --key="$KEY" "$@" 2>&1
  fi
}
if [ -n "$ETCDCTL" ]; then echo "via=host $ETCDCTL"; elif [ -n "$CID" ]; then echo "via=crictl $CID"; else echo "via=none"; fi
if [ -n "$ETCDCTL" ] || [ -n "$CID" ]; then
  echo "---MEMBERS"; run_ctl member list -w json
  echo; echo "---STATUS"; run_ctl endpoint status --cluster -w json
  echo; echo "---ALARMS"; run_ctl alarm list -w json
  echo
fi
sec DATADIR
echo "$DATADIR"
[ -d "$DATADIR" ] && du -sk "$DATADIR" 2>/dev/null | cut -f1
[ -d "$DATADIR" ] && df -Pk "$DATADIR" 2>/dev/null | tail -1
sec SNAPSHOTS
for d in $SNAPDIR $EXTRA_DIRS /var/lib/etcd-backup /var/lib/etcd/backup /var/backups/etcd /opt/etcd-backup /opt/etcd/backup /backup/etcd /var/lib/rancher/rke2/server/db/snapshots /var/lib/rancher/k3s/server/db/snapshots; do
  [ -d "$d" ] || continue
  echo "--- $d"
  for f in "$d"/*; do [ -f "$f" ] && stat -c '%s|%Y|%n' "$f" 2>/dev/null; done
done
sec BACKUPHINTS
systemctl list-timers --all --no-pager --no-legend 2>/dev/null | grep -i etcd | sed 's/^/timer: /'
grep -rlisE 'etcd' /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/crontab /var/spool/cron 2>/dev/null | sed 's/^/cron: /'
sec END
`

// Parse converts the script output into a Probe.
func Parse(node, out string) *Probe {
	p := &Probe{Node: node, Collected: time.Now(), RKE2Config: map[string]string{}, Raw: out}
	secs := splitSections(out)
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
		}
	}
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
	parseEtcdctl(p, secs["ETCDCTL"])
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
	parts := map[string]string{}
	cur := ""
	for _, l := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "via=") {
			p.EtcdctlVia = strings.TrimPrefix(t, "via=")
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
		var doc struct {
			Members []struct {
				ID         json.Number `json:"ID"`
				Name       string      `json:"name"`
				PeerURLs   []string    `json:"peerURLs"`
				ClientURLs []string    `json:"clientURLs"`
				IsLearner  bool        `json:"isLearner"`
			} `json:"members"`
		}
		if err := json.Unmarshal([]byte(s), &doc); err == nil {
			for _, m := range doc.Members {
				p.Members = append(p.Members, Member{ID: hexID(m.ID.String()), Name: m.Name, PeerURLs: m.PeerURLs, ClientURLs: m.ClientURLs, IsLearner: m.IsLearner})
			}
			sort.Slice(p.Members, func(i, j int) bool { return p.Members[i].Name < p.Members[j].Name })
		}
	}
	if s := strings.TrimSpace(parts["STATUS"]); s != "" {
		var doc []struct {
			Endpoint string `json:"Endpoint"`
			Status   struct {
				Header struct {
					MemberID json.Number `json:"member_id"`
					RaftTerm json.Number `json:"raft_term"`
				} `json:"header"`
				Version     string      `json:"version"`
				DBSize      int64       `json:"dbSize"`
				DBSizeInUse int64       `json:"dbSizeInUse"`
				Leader      json.Number `json:"leader"`
				RaftIndex   json.Number `json:"raftIndex"`
				RaftTerm    json.Number `json:"raftTerm"`
				IsLearner   bool        `json:"isLearner"`
				Errors      []string    `json:"errors"`
			} `json:"Status"`
		}
		if err := json.Unmarshal([]byte(s), &doc); err == nil {
			for _, e := range doc {
				st := EndpointStatus{Endpoint: e.Endpoint, Version: e.Status.Version, DBSize: e.Status.DBSize, DBSizeInUse: e.Status.DBSizeInUse, IsLearner: e.Status.IsLearner, Errors: e.Status.Errors}
				st.Leader = hexID(e.Status.Leader.String())
				st.MemberID = hexID(e.Status.Header.MemberID.String())
				st.RaftIndex, _ = strconv.ParseUint(e.Status.RaftIndex.String(), 10, 64)
				st.RaftTerm, _ = strconv.ParseUint(e.Status.RaftTerm.String(), 10, 64)
				p.Statuses = append(p.Statuses, st)
			}
		}
	}
	if s := strings.TrimSpace(parts["ALARMS"]); s != "" {
		var doc struct {
			Alarms []struct {
				MemberID json.Number `json:"memberID"`
				Alarm    any         `json:"alarm"`
			} `json:"alarms"`
		}
		if err := json.Unmarshal([]byte(s), &doc); err == nil {
			for _, a := range doc.Alarms {
				t := fmt.Sprint(a.Alarm)
				switch t {
				case "1":
					t = "NOSPACE"
				case "2":
					t = "CORRUPT"
				}
				p.Alarms = append(p.Alarms, Alarm{MemberID: hexID(a.MemberID.String()), Type: t})
			}
		}
	}
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
