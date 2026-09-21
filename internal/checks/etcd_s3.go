package checks

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s-health-tui/internal/etcd"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/strutil"
)

// S3Config is the effective etcd snapshot S3 configuration of one server:
// rke2/k3s read etcd-s3-* keys from config.yaml, or from the secret named by
// etcd-s3-config-secret (whose values win). Every server uploads its own
// snapshots, so this must be complete and identical on all of them.
type S3Config struct {
	Enabled        bool
	Source         string // "secret <name>" | "config.yaml" | ""
	SecretName     string
	SecretFound    bool
	Endpoint       string
	Bucket         string
	Folder         string
	Region         string
	HasCredentials bool
	CAFile         string // etcd-s3-endpoint-ca path on the node (inline config)
	CAPEM          string // CA content from the secret
	SkipSSLVerify  bool
	Insecure       bool
}

// URL is the endpoint as the node would dial it.
func (c S3Config) URL() string { return etcd.S3URL(c.Endpoint, c.Insecure) }

// Missing lists what an enabled configuration still lacks.
func (c S3Config) Missing() []string {
	var m []string
	if c.SecretName != "" && !c.SecretFound {
		m = append(m, "secret "+c.SecretName)
	}
	if c.Bucket == "" {
		m = append(m, "bucket")
	}
	if !c.HasCredentials {
		m = append(m, "credentials")
	}
	return m
}

// Key identifies the destination for drift comparison.
func (c S3Config) Key() string {
	if !c.Enabled {
		return "off"
	}
	return c.URL() + "/" + c.Bucket + "/" + c.Folder
}

// S3ConfigFor merges a node's config.yaml keys with the secret (when the node
// names one and it was read).
func S3ConfigFor(p *etcd.Probe, sec *k8s.S3SecretInfo) S3Config {
	c := S3Config{}
	if p == nil {
		return c
	}
	get := func(k string) string { return strings.Trim(strings.TrimSpace(p.RKE2Config[k]), `"'`) }
	c.Enabled = get("etcd-s3") == "true"
	c.Endpoint = get("etcd-s3-endpoint")
	c.Bucket = get("etcd-s3-bucket")
	c.Folder = get("etcd-s3-folder")
	c.Region = get("etcd-s3-region")
	c.CAFile = get("etcd-s3-endpoint-ca")
	c.SkipSSLVerify = get("etcd-s3-skip-ssl-verify") == "true"
	c.Insecure = get("etcd-s3-insecure") == "true"
	c.HasCredentials = get("etcd-s3-access-key") == "<set>" && get("etcd-s3-secret-key") == "<set>"
	if c.Enabled {
		c.Source = "config.yaml"
	}
	c.SecretName = get("etcd-s3-config-secret")
	if c.SecretName != "" {
		c.Source = "secret " + c.SecretName
		if sec != nil && sec.Name == c.SecretName && sec.Found {
			c.SecretFound = true
			// the secret's values override the inline ones
			if sec.Endpoint != "" {
				c.Endpoint = sec.Endpoint
			}
			if sec.Bucket != "" {
				c.Bucket = sec.Bucket
			}
			if sec.Folder != "" {
				c.Folder = sec.Folder
			}
			if sec.Region != "" {
				c.Region = sec.Region
			}
			if sec.HasCredentials {
				c.HasCredentials = true
			}
			if sec.EndpointCA != "" {
				c.CAPEM, c.CAFile = sec.EndpointCA, ""
			}
			c.SkipSSLVerify = c.SkipSSLVerify || sec.SkipSSLVerify
			c.Insecure = c.Insecure || sec.Insecure
		}
	}
	return c
}

// evalS3 checks the S3 snapshot destination: consistency across servers,
// completeness, whether uploads still succeed, and reachability from the nodes.
func evalS3(in Input, add func(Severity, string, string, string, string)) {
	nodes := strutil.SortedKeys(in.Etcd)
	cfgs := map[string]S3Config{}
	var enabled, disabled []string
	for _, n := range nodes {
		p := in.Etcd[n]
		if p == nil || p.Err != nil || (p.Dist != "rke2" && p.Dist != "k3s") {
			continue
		}
		c := S3ConfigFor(p, in.S3)
		cfgs[n] = c
		if c.Enabled {
			enabled = append(enabled, n)
		} else {
			disabled = append(disabled, n)
		}
	}
	if len(enabled) == 0 {
		return
	}
	obj := "backups"

	// every server must upload: partial enablement or different destinations
	if len(disabled) > 0 {
		add(SevWarn, "etcd", obj, fmt.Sprintf("S3 snapshots enabled on %s but not on %s (each server uploads its own snapshots)", strings.Join(enabled, ","), strings.Join(disabled, ",")), "put the same etcd-s3-* settings on every server")
	}
	dest := map[string][]string{}
	for _, n := range enabled {
		k := cfgs[n].Key()
		dest[k] = append(dest[k], n)
	}
	if len(dest) > 1 {
		var parts []string
		for _, k := range strutil.SortedKeys(dest) {
			parts = append(parts, fmt.Sprintf("%s -> %s", strings.Join(dest[k], ","), k))
		}
		add(SevWarn, "etcd", obj, "servers upload snapshots to different S3 destinations: "+strings.Join(parts, "; "), "align etcd-s3-endpoint/bucket/folder on every server")
	}

	// completeness (first enabled server is representative once drift is reported)
	seenMissing := map[string]bool{}
	for _, n := range enabled {
		c := cfgs[n]
		if c.SecretName != "" && in.S3 != nil && in.S3.Name == c.SecretName && !in.S3.Found {
			key := "secret " + c.SecretName
			if !seenMissing[key] {
				seenMissing[key] = true
				add(SevWarn, "etcd", obj, "etcd-s3-config-secret "+c.SecretName+" not found in kube-system: "+strutil.FirstLine(in.S3.Err), "create the secret or fix the name")
			}
			continue
		}
		if c.SecretName != "" && !c.SecretFound {
			continue // secret not read yet
		}
		if m := c.Missing(); len(m) > 0 {
			key := n + strings.Join(m, ",")
			if seenMissing[key] {
				continue
			}
			seenMissing[key] = true
			sev := SevWarn
			hint := "set etcd-s3-bucket / etcd-s3-access-key / etcd-s3-secret-key (config.yaml or the config secret)"
			if len(m) == 1 && m[0] == "credentials" {
				sev = SevInfo
				hint = "fine only if the node has an IAM instance role with access to the bucket"
			}
			add(sev, "etcd", n, "S3 snapshots enabled but "+strings.Join(m, ", ")+" not configured ("+c.Source+")", hint)
		}
		if c.SkipSSLVerify {
			add(SevInfo, "etcd", n, "etcd-s3-skip-ssl-verify is on: uploads do not verify the endpoint certificate", "set etcd-s3-endpoint-ca instead")
		}
	}

	// are uploads still happening: newest S3 record vs the age limit
	var latestS3 time.Time
	failedS3 := 0
	lastFail := ""
	total := 0
	for i := range in.Snap.RKE2Snapshots {
		r := &in.Snap.RKE2Snapshots[i]
		if !r.S3 {
			continue
		}
		total++
		if r.Status == "failed" {
			failedS3++
			if lastFail == "" {
				lastFail = strutil.FirstLine(r.Message)
			}
			continue
		}
		if r.Created.After(latestS3) {
			latestS3 = r.Created
		}
	}
	switch {
	case len(in.Snap.RKE2Snapshots) > 0 && total == 0:
		add(SevWarn, "etcd", obj, "S3 snapshots enabled but no snapshot record is marked as uploaded to S3", "check S3 credentials/endpoint in rke2-server logs")
	case !latestS3.IsZero() && in.Now.Sub(latestS3) > in.Cfg.Etcd.MaxBackupAge:
		add(SevWarn, "etcd", obj, fmt.Sprintf("latest S3 snapshot upload is %s old (local snapshots may still be fresh)", strutil.HumanDur(in.Now.Sub(latestS3))), "uploads have stopped: check credentials, bucket policy, endpoint reachability")
	}
	if failedS3 > 0 {
		add(SevWarn, "etcd", obj, fmt.Sprintf("%d snapshot record(s) failed to upload to S3: %s", failedS3, lastFail), "kubectl get etcdsnapshotfile -o yaml | grep -A3 error")
	}
	for _, n := range enabled {
		if lg := in.Logs[n]; lg != nil && lg.ByName["s3-upload-fail"] > 0 {
			add(SevWarn, "etcd", n, fmt.Sprintf("%d S3 upload error(s) in the journal", lg.ByName["s3-upload-fail"]), "see the Logs tab (pattern s3-upload-fail)")
		}
	}

	// reachability from each server
	for _, n := range enabled {
		r, ok := in.S3Reach[n]
		if !ok || r.OK {
			continue
		}
		hint := "DNS / firewall / proxy from the control-plane nodes to the endpoint"
		if strings.Contains(r.Detail, "certificate") || strings.Contains(r.Detail, "SSL") {
			hint = "set etcd-s3-endpoint-ca to the endpoint's CA (or fix the endpoint certificate)"
		}
		add(SevCrit, "etcd", n, "S3 endpoint "+r.URL+" unreachable from the node: "+r.Detail, hint)
	}
}

// S3Rows renders one row per server for the etcd tab.
func S3Rows(in Input) [][]string {
	var rows [][]string
	nodes := strutil.SortedKeys(in.Etcd)
	sort.Strings(nodes)
	for _, n := range nodes {
		p := in.Etcd[n]
		if p == nil || p.Err != nil || (p.Dist != "rke2" && p.Dist != "k3s") {
			continue
		}
		c := S3ConfigFor(p, in.S3)
		if !c.Enabled {
			rows = append(rows, []string{n, "off", "", "", "", "", ""})
			continue
		}
		creds := "missing"
		if c.HasCredentials {
			creds = "set"
		}
		reach := "-"
		if r, ok := in.S3Reach[n]; ok {
			if r.OK {
				reach = "ok " + r.Detail
			} else {
				reach = "FAIL " + r.Detail
			}
		}
		bucket := c.Bucket
		if c.Folder != "" {
			bucket += "/" + c.Folder
		}
		if c.SecretName != "" && !c.SecretFound {
			bucket = "(secret not read)"
		}
		rows = append(rows, []string{n, "on", c.Source, c.URL(), bucket, creds, reach})
	}
	return rows
}
