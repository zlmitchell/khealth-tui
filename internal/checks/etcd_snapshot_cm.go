package checks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// evalSnapshotConfigMap watches the rke2/k3s-etcd-snapshots ConfigMap
// against its ceiling. A ConfigMap's data may not exceed 1 MiB, every
// server rewrites the whole map after each snapshot, and once the rewrite
// is refused ("must have at most 1048576 bytes") the records stop while
// the snapshots on disk keep happening unseen. It fills for two reasons
// that need different fixes: the retention is too large for the number of
// servers (the steady state, servers x retention x targets, does not fit),
// or the cleanup stopped and records pile up past that steady state -
// entries above what retention allows on a node, or records of nodes that
// are no longer in the cluster.
func evalSnapshotConfigMap(in Input, add func(Severity, string, string, string, string)) {
	s := in.Snap
	cm := s.SnapshotCM
	if cm == nil || cm.Entries == 0 {
		return
	}
	per := cm.Bytes / cm.Entries
	servers := 0
	current := map[string]bool{}
	for i := range s.Nodes {
		if k8s.IsEtcdNode(s.Nodes, &s.Nodes[i]) {
			servers++
			current[s.Nodes[i].Name] = true
		}
	}
	servers = max(servers, 1)
	// retention and targets from the servers' config.yaml (probes), else
	// the rke2 defaults: 5 local, S3 doubles it
	retention, s3 := 5, false
	for _, ni := range in.Nodes {
		if ni == nil || ni.Err != nil || !ni.ControlPlane {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(ni.Settings["etcd-snapshot-retention"])); err == nil && v > 0 {
			retention = v
		}
		if ni.Settings["etcd-s3"] == "true" {
			s3 = true
		}
	}
	for i := range s.RKE2Snapshots {
		if s.RKE2Snapshots[i].S3 {
			s3 = true
		}
	}
	targets := 1
	if s3 {
		targets = 2
	}
	steady := servers * retention * targets

	// what is piling up: per node, and for nodes that are gone
	perNode := map[string]int{}
	for i := range s.RKE2Snapshots {
		perNode[s.RKE2Snapshots[i].Node]++
	}
	var over, gone []string
	for _, n := range strutil.SortedKeys(perNode) {
		c := perNode[n]
		switch {
		case n != "" && !current[n]:
			gone = append(gone, fmt.Sprintf("%s (%d)", n, c))
		case c > retention*targets+1:
			over = append(over, fmt.Sprintf("%s (%d, retention allows %d)", n, c, retention*targets))
		}
	}
	sort.Strings(over)
	piling := len(gone) > 0 || len(over) > 0 || cm.Entries > steady*3/2+2

	pct := cm.Pct()
	if pct < 70 && !piling {
		return
	}
	use := fmt.Sprintf("kube-system/%s holds %d snapshot records, %d KiB of the 1 MiB a ConfigMap may hold (%d%%, ~%d bytes each)", cm.Name, cm.Entries, cm.Bytes/1024, pct, per)
	var cause, hint string
	if piling {
		why := []string{}
		if len(over) > 0 {
			why = append(why, "more records than retention allows on "+strutil.TruncList(over, 3))
		}
		if len(gone) > 0 {
			why = append(why, "records of servers no longer in the cluster: "+strutil.TruncList(gone, 3))
		}
		if len(why) == 0 {
			why = append(why, fmt.Sprintf("%d records where %d servers x retention %d x %d target(s) = %d is the steady state", cm.Entries, servers, retention, targets, steady))
		}
		cause = "the cleanup is not happening - " + strings.Join(why, "; ")
		hint = "on every server: `rke2 etcd-snapshot prune` (applies the retention to what is on disk and in the map) and `rke2 etcd-snapshot delete <name>` for records whose file is gone; records of removed servers only go with `kubectl -n kube-system edit configmap " + cm.Name + "`; the rke2-server journal shows why the reconcile fails (S3 errors keep the S3 records)"
	} else {
		fit := k8s.SnapshotConfigMapLimit * 7 / 10 / max(per*servers*targets, 1)
		cause = fmt.Sprintf("the retention is too large for %d servers: %d servers x retention %d x %d target(s) = %d records at ~%d bytes is the steady state", servers, servers, retention, targets, steady, per)
		hint = fmt.Sprintf("set etcd-snapshot-retention to %d or less (keeps the map under 70%%), or move to a release that keeps the records in ETCDSnapshotFile CRs only, which have no such ceiling", max(fit, 1))
	}
	switch {
	case pct >= 90:
		add(SevCrit, "etcd", "backups", use+": the next rewrite may be refused (\"must have at most 1048576 bytes\") and the records stop; "+cause, hint)
	case pct >= 70:
		add(SevWarn, "etcd", "backups", use+"; "+cause, hint)
	default:
		add(SevWarn, "etcd", "backups", use+"; "+cause, hint)
	}
}
