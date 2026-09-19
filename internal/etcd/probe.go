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
	LocalMemberID string        // this node's member id from its own etcd log
	LeaderEvents  []LeaderEvent // leader elections seen in the local etcd log, oldest first
	Raft          *RaftOnDisk

	SnapshotDirs []SnapshotDir
	BackupHints  []string
	Raw          string
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
# rke2/k3s data-dir may be customised in config.yaml
RKE2_DD=/var/lib/rancher/rke2; K3S_DD=/var/lib/rancher/k3s
for f in /etc/rancher/rke2/config.yaml /etc/rancher/rke2/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  v=$(sed -nE 's/^[[:space:]]*data-dir:[[:space:]]*"?([^"#]+)"?.*/\1/p' "$f" | tail -1 | sed 's/[[:space:]]*$//')
  [ -n "$v" ] && RKE2_DD=$v
done
for f in /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  v=$(sed -nE 's/^[[:space:]]*data-dir:[[:space:]]*"?([^"#]+)"?.*/\1/p' "$f" | tail -1 | sed 's/[[:space:]]*$//')
  [ -n "$v" ] && K3S_DD=$v
done
if [ -d "$RKE2_DD/server/tls/etcd" ]; then
  DIST=rke2
  CA=$RKE2_DD/server/tls/etcd/server-ca.crt
  CERT=$RKE2_DD/server/tls/etcd/server-client.crt
  KEY=$RKE2_DD/server/tls/etcd/server-client.key
  CRICTL=$RKE2_DD/bin/crictl
  CRI_EP=unix:///run/k3s/containerd/containerd.sock
  DATADIR=$RKE2_DD/server/db/etcd
  SNAPDIR=$RKE2_DD/server/db/snapshots
elif [ -d "$K3S_DD/server/tls/etcd" ]; then
  DIST=k3s
  CA=$K3S_DD/server/tls/etcd/server-ca.crt
  CERT=$K3S_DD/server/tls/etcd/server-client.crt
  KEY=$K3S_DD/server/tls/etcd/server-client.key
  DATADIR=$K3S_DD/server/db/etcd
  SNAPDIR=$K3S_DD/server/db/snapshots
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
for f in "$CA" "$CERT" "$KEY"; do [ -n "$f" ] && [ ! -r "$f" ] && echo "missing=$f"; done
[ -n "$CRICTL" ] && [ ! -x "$CRICTL" ] && echo "missing=$CRICTL"
sec SOURCE
[ -f "$RKE2_DD/agent/pod-manifests/etcd.yaml" ] && echo "static-pod $RKE2_DD/agent/pod-manifests/etcd.yaml"
[ -f /etc/kubernetes/manifests/etcd.yaml ] && echo "static-pod /etc/kubernetes/manifests/etcd.yaml"
if [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then echo "systemd etcd.service ($(systemctl is-active etcd 2>/dev/null))"; fi
[ "$DIST" = k3s ] && echo "embedded k3s etcd (in-process)"
for m in /etc/kubernetes/manifests/kube-apiserver.yaml "$RKE2_DD/agent/pod-manifests/kube-apiserver.yaml"; do
  [ -f "$m" ] && grep -o -- '--etcd-servers=[^ "]*' "$m" 2>/dev/null | head -1 | sed "s|^|apiserver $m: |"
done
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then
  for f in /etc/rancher/$DIST/config.yaml /etc/rancher/$DIST/config.yaml.d/*.yaml; do [ -f "$f" ] && echo "$DIST-config $f"; done
  [ -f "$DATADIR/config" ] && echo "etcd-config $DATADIR/config (generated by $DIST)"
fi
for f in /etc/etcd/etcd.conf /etc/etcd/etcd.conf.yml /etc/etcd/etcd.conf.yaml /etc/etcd.env /etc/default/etcd /etc/sysconfig/etcd; do [ -f "$f" ] && echo "etcd-config $f"; done
sec RKE2CONFIG
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then
  for f in /etc/rancher/$DIST/config.yaml /etc/rancher/$DIST/config.yaml.d/*.yaml; do
    [ -f "$f" ] || continue
    grep -E '^[[:space:]]*(etcd-|cluster-init|disable-etcd|server:|profile:|secrets-encryption)' "$f" 2>/dev/null | grep -viE 'token' | sed -E -e "s/^([[:space:]]*[^:]*(access-key|secret-key)[^:]*:)[[:space:]]*(\"\"|'')[[:space:]]*$/\1/" -e 's/^([[:space:]]*[^:]*(access-key|secret-key)[^:]*:)[[:space:]]*[^[:space:]#].*/\1 <set>/' | sed "s|^|$f: |"
  done
fi
sec CONFIGDUMP
dump() { [ -f "$1" ] || return; echo "--- $1"; grep -viE 'token|password|secret-key|access-key' "$1" 2>/dev/null | head -200; }
if [ "$DIST" = rke2 ] || [ "$DIST" = k3s ]; then dump "$DATADIR/config"; fi
if [ -f /etc/kubernetes/manifests/etcd.yaml ]; then echo "--- /etc/kubernetes/manifests/etcd.yaml (args)"; grep -E '^[[:space:]]*- --|image:' /etc/kubernetes/manifests/etcd.yaml; fi
if [ -f "$RKE2_DD/agent/pod-manifests/etcd.yaml" ]; then echo "--- $RKE2_DD/agent/pod-manifests/etcd.yaml (args)"; grep -E '^[[:space:]]*- --|image:' "$RKE2_DD/agent/pod-manifests/etcd.yaml"; fi
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
CID=; DIAG=
if [ -z "$ETCDCTL" ] && [ -n "$CRICTL" ] && [ -x "$CRICTL" ] && [ -n "$CRI_EP" ]; then
  CID=$("$CRICTL" -r "$CRI_EP" ps -q --name '^etcd$' 2>/dev/null | head -1)
  if [ -z "$CID" ]; then
    PID=$("$CRICTL" -r "$CRI_EP" pods -q --name '^etcd-' 2>/dev/null | head -1)
    [ -n "$PID" ] && CID=$("$CRICTL" -r "$CRI_EP" ps -q --pod "$PID" 2>/dev/null | head -1)
  fi
  [ -z "$CID" ] && DIAG="no running etcd container found via $CRICTL -r $CRI_EP"
elif [ -z "$ETCDCTL" ]; then
  DIAG="no etcdctl on host and no usable crictl (crictl=$CRICTL cri=$CRI_EP)"
fi
run_ctl() {
  if [ -n "$ETCDCTL" ]; then ETCDCTL_API=3 "$ETCDCTL" --endpoints="$EP" --cacert="$CA" --cert="$CERT" --key="$KEY" "$@" 2>&1
  elif [ -n "$CID" ]; then "$CRICTL" -r "$CRI_EP" exec "$CID" etcdctl --endpoints="$EP" --cacert="$CA" --cert="$CERT" --key="$KEY" "$@" 2>&1
  fi
}
GW=
if [ -n "$ETCDCTL" ]; then echo "via=host $ETCDCTL"; elif [ -n "$CID" ]; then echo "via=crictl $CID"; else echo "via=grpc-gateway"; GW=1; fi
[ -n "$DIAG" ] && echo "diag=$DIAG"
if [ -z "$GW" ]; then
  echo "---MEMBERS"; run_ctl member list -w json
  echo; echo "---STATUS"; run_ctl endpoint status --cluster -w json
  echo; echo "---ALARMS"; run_ctl alarm list -w json
  echo
fi
if [ -n "$GW" ] && command -v curl >/dev/null 2>&1; then
  # etcd gRPC gateway: same certs as /health, no etcdctl needed
  echo "---MEMBERS"; $CURL -X POST "$EP/v3/cluster/member/list" -H 'Content-Type: application/json' -d '{}' 2>&1
  echo; echo "---GWSTATUS"; $CURL -X POST "$EP/v3/maintenance/status" -H 'Content-Type: application/json' -d '{}' 2>&1
  echo; echo "---GWALARMS"; $CURL -X POST "$EP/v3/maintenance/alarm" -H 'Content-Type: application/json' -d '{"action":"GET"}' 2>&1
  echo
fi
sec LEADERLOG
LOGRE='became leader at term|elected leader|changed leader from'
ETCDLOGS=$(ls -tr /var/log/pods/kube-system_etcd-*/etcd/* 2>/dev/null)
if [ -n "$ETCDLOGS" ]; then
  echo "source=/var/log/pods/kube-system_etcd-*/etcd"
  cat $ETCDLOGS 2>/dev/null | grep -oE '"local-member-id":"[0-9a-f]+"' | tail -1 | cut -d'"' -f4 | sed 's/^/local-member-id=/'
  cat $ETCDLOGS 2>/dev/null | grep -E "$LOGRE" | tail -30
elif [ "$DIST" = k3s ]; then
  echo "source=journalctl -u k3s"
  journalctl -u k3s -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -oE '"local-member-id":"[0-9a-f]+"|local-member-id=[0-9a-f]+' | tail -1 | grep -oE '[0-9a-f]{16}' | sed 's/^/local-member-id=/'
  journalctl -u k3s -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -E "$LOGRE" | tail -30
elif [ "$(systemctl show -p LoadState --value etcd 2>/dev/null)" = loaded ]; then
  echo "source=journalctl -u etcd"
  journalctl -u etcd -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -oE '"local-member-id":"[0-9a-f]+"' | tail -1 | cut -d'"' -f4 | sed 's/^/local-member-id=/'
  journalctl -u etcd -q --no-pager -n 50000 -o short-iso 2>/dev/null | grep -E "$LOGRE" | tail -30
fi
sec RAFT
[ -d "$DATADIR/member/snap" ] && ls "$DATADIR/member/snap"/*.snap 2>/dev/null | sort | tail -1 | sed 's|^|snap=|'
[ -d "$DATADIR/member/wal" ] && stat -c '%Y %n' "$DATADIR/member/wal"/*.wal 2>/dev/null | sort -n | tail -1 | sed 's|^|wal=|'
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
		case "missing":
			p.Missing = append(p.Missing, v)
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
	parseLeaderLog(p, secs["LEADERLOG"])
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
	if s := strings.TrimSpace(parts["STATUS"]); s != "" {
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
