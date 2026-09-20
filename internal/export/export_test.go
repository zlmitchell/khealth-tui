package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s-health-tui/internal/checks"
	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/stig"
)

func sampleInput() Input {
	now := time.Date(2026, 9, 20, 15, 4, 5, 0, time.UTC)
	snap := &k8s.Snapshot{Distribution: "rke2", Version: "v1.35.8+rke2r1",
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": "true", "node-role.kubernetes.io/etcd": "true"}},
				Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.8+rke2r1", OSImage: "Rocky Linux 9.6", KernelVersion: "5.14"}, Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "w-1"}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.35.8+rke2r1"}}},
		},
		Pods: make([]corev1.Pod, 7), Namespaces: make([]corev1.Namespace, 3),
	}
	nodes := map[string]*nodeinfo.Info{"cp-1": nodeinfo.Parse("cp-1", "10.0.0.1", "===HOST\ncp-1\n5.14.0\nx86_64\n===SELINUX\nEnforcing\n===END\n", now)}
	first := now.Add(-40 * time.Minute)
	return Input{
		Snap: snap, Nodes: nodes, Context: "prod/cluster:a", Server: "https://10.0.0.1:6443", Version: "v1.2.3", Now: now,
		Findings: []checks.Finding{
			{Severity: checks.SevInfo, Area: "node", Object: "w-1", Message: "cordoned (unschedulable)", Hint: "kubectl uncordon"},
			{Severity: checks.SevCrit, Area: "etcd", Object: "cp-1", Message: "db size 90% of quota", Hint: "defrag", Steps: []string{"etcdctl defrag", "compact"}},
			{Severity: checks.SevWarn, Area: "images", Object: "cp-1", Message: "registry harbor.corp unreachable"},
		},
		FirstSeen: func(f checks.Finding) time.Time {
			if f.Area == "etcd" {
				return first
			}
			return time.Time{}
		},
		Resolved: []ResolvedFinding{{Finding: checks.Finding{Severity: checks.SevWarn, Area: "node", Object: "cp-1", Message: "NTP not synchronized"}, First: first, Resolved: now.Add(-2 * time.Minute)}},
		StigRun:  true,
		Stig: []stig.Result{
			{ID: "V-242376", Title: "TLS on the controller manager", Cat: "II", Group: "controller-manager", Status: stig.Pass, Detail: "--tls-min-version=VersionTLS12"},
			{ID: "V-242378", Title: "TLS on the API server", Cat: "II", Group: "apiserver", Status: stig.Fail, Detail: "flag missing", Fix: "set --tls-min-version"},
			{ID: "CIS-1.2.1", Title: "anonymous auth", Cat: "", Group: "apiserver", Status: stig.Manual, Detail: "review"},
			{ID: "V-254555", Title: "rke2 profile", Cat: "I", Group: "cluster", Status: stig.NA},
			{ID: "RHEL-09-211010", RuleID: "SV-257777r1", Ref: "DISA RHEL 9 STIG V2R9 (01 Jul 2026)", Title: "RHEL 9 must be a vendor-supported release", Cat: "I", Group: "os", Status: stig.Fail, Check: "cat /etc/redhat-release", PerNode: map[string]stig.Status{"cp-1": stig.Fail, "w-1": stig.Pass}},
			{ID: "RHEL-09-211015", RuleID: "SV-257778r1", Ref: "DISA RHEL 9 STIG V2R9 (01 Jul 2026)", Title: "RHEL 9 vendor packaged system security patches", Cat: "II", Group: "os", Status: stig.Pass, PerNode: map[string]stig.Status{"cp-1": stig.Pass, "w-1": stig.Pass}},
		},
	}
}

func TestBuildReport(t *testing.T) {
	r := Build(sampleInput())
	if r.Cluster.Distribution != "rke2" || r.Cluster.Nodes != 2 || r.Cluster.Pods != 7 || r.Cluster.Namespaces != 3 || r.Cluster.Context != "prod/cluster:a" {
		t.Errorf("cluster: %+v", r.Cluster)
	}
	if r.Summary.Crit != 1 || r.Summary.Warn != 1 || r.Summary.Info != 1 || r.Summary.Findings["CRIT"] != 1 {
		t.Errorf("summary: %+v", r.Summary)
	}
	// sorted by severity, first-seen carried, steps kept
	if len(r.Findings) != 3 || r.Findings[0].Severity != "CRIT" || r.Findings[0].FirstSeen == nil || len(r.Findings[0].Steps) != 2 || r.Findings[2].FirstSeen != nil {
		t.Errorf("findings: %+v", r.Findings)
	}
	if len(r.Resolved) != 1 || r.Resolved[0].Resolved == nil || r.Resolved[0].FirstSeen == nil {
		t.Errorf("resolved: %+v", r.Resolved)
	}
	if r.Security == nil || len(r.Security.Benchmarks) != 4 {
		t.Fatalf("benchmarks: %+v", r.Security)
	}
	names := []string{}
	for _, b := range r.Security.Benchmarks {
		names = append(names, b.Sheet)
	}
	// cluster benchmarks in stig.Benchmarks order, the OS STIG last
	if strings.Join(names, "|") != "Kubernetes STIG|RKE2 STIG|CIS Kubernetes|RHEL 9 STIG" {
		t.Errorf("sheet order: %v", names)
	}
	k8sB := r.Security.Benchmarks[0]
	if k8sB.Counts["PASS"] != 1 || k8sB.Counts["FAIL"] != 1 || k8sB.Score == nil || *k8sB.Score != 50 {
		t.Errorf("kubernetes benchmark: %+v", k8sB)
	}
	rhel := r.Security.Benchmarks[3]
	if !rhel.PerNode || len(rhel.nodes) != 2 || rhel.NodeScores["cp-1"] != 50 || rhel.NodeScores["w-1"] != 100 || rhel.Rules[0].PerNode["cp-1"] != "FAIL" || rhel.Rules[0].RuleID != "SV-257777r1" {
		t.Errorf("rhel benchmark: %+v nodes=%v", rhel, rhel.nodes)
	}
	if r.Summary.Security["FAIL"] != 2 || r.Summary.Security["PASS"] != 2 {
		t.Errorf("security summary: %v", r.Summary.Security)
	}
	if len(r.Nodes) != 2 || r.Nodes[0].SSH != "ok" || strings.Join(r.Nodes[0].Roles, ",") != "control-plane,etcd" || !r.Nodes[0].Ready || r.Nodes[1].SSH != "off" || len(r.Nodes[0].Hardening) == 0 {
		t.Errorf("nodes: %+v", r.Nodes)
	}
	if FileBase(r) != "khealth-prod-cluster-a-20260920-150405" {
		t.Errorf("file base: %q", FileBase(r))
	}
}

func TestSheetName(t *testing.T) {
	for in, want := range map[string]string{
		"DISA Kubernetes STIG V2R6 (01 Apr 2026)":                                     "Kubernetes STIG",
		"DISA Rancher Government RKE2 STIG V2R7 (01 Jul 2026)":                        "RKE2 STIG",
		"DISA Rancher Government MCM STIG V2R2 (05 Jan 2026)":                         "MCM STIG",
		"CIS Kubernetes Benchmark v2.0.1 (Jun 2026) / rke2 CIS self-assessment v1.12": "CIS Kubernetes",
		"Generic OS checks (no STIG ID)":                                              "Generic OS checks",
		"DISA Ubuntu 22.04 LTS STIG V2R9 (01 Jul 2026)":                               "Ubuntu 22.04 LTS STIG",
		"custom": "custom",
		"weird/name:with*chars[]?\\ that is far too long for a sheet tab name": "weird name with chars     that",
	} {
		if got := sheetName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Build(sampleInput())); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back["tool"] != "khealth" || back["security"] == nil || len(back["findings"].([]any)) != 3 {
		t.Errorf("json: %v", back)
	}
	sec := back["security"].(map[string]any)["benchmarks"].([]any)[3].(map[string]any)
	if sec["name"] != "DISA RHEL 9 STIG V2R9 (01 Jul 2026)" || sec["node_scores"].(map[string]any)["w-1"] != 100.0 {
		t.Errorf("rhel json: %v", sec)
	}
	if _, ok := sec["sheet"]; ok {
		t.Error("sheet name leaked into the JSON")
	}
}

func TestWriteFiles(t *testing.T) {
	dir := t.TempDir()
	jsonPath, xlsxPath, err := WriteFiles(filepath.Join(dir, "out"), Build(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(jsonPath) != "khealth-prod-cluster-a-20260920-150405.json" || filepath.Base(xlsxPath) != "khealth-prod-cluster-a-20260920-150405.xlsx" {
		t.Errorf("paths: %s %s", jsonPath, xlsxPath)
	}
	if st, err := os.Stat(jsonPath); err != nil || st.Size() == 0 {
		t.Errorf("json file: %v", err)
	}
	f, err := excelize.OpenFile(xlsxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := strings.Join(f.GetSheetList(), "|"); got != "Summary|Findings|Kubernetes STIG|RKE2 STIG|CIS Kubernetes|RHEL 9 STIG|Nodes" {
		t.Errorf("sheets: %s", got)
	}
	rows, _ := f.GetRows("Findings")
	if len(rows) != 5 || rows[0][0] != "severity" || rows[1][0] != "CRIT" || rows[1][1] != "ongoing" || rows[4][1] != "resolved" || rows[1][6] != "etcdctl defrag\ncompact" {
		t.Errorf("findings rows: %v", rows)
	}
	rows, _ = f.GetRows("RHEL 9 STIG")
	if len(rows) != 3 || rows[0][9] != "cp-1" || rows[0][10] != "w-1" || rows[1][9] != "FAIL" || rows[1][10] != "PASS" || rows[1][3] != "SV-257777r1" || rows[1][8] != "cat /etc/redhat-release" {
		t.Errorf("rhel rows: %v", rows)
	}
	rows, _ = f.GetRows("Kubernetes STIG")
	if len(rows) != 3 || len(rows[0]) != 9 || rows[2][0] != "FAIL" || rows[2][7] != "set --tls-min-version" {
		t.Errorf("k8s rows: %v", rows)
	}
	rows, _ = f.GetRows("Nodes")
	if len(rows) != 3 || rows[1][0] != "cp-1" || rows[1][6] != "ok" || rows[2][6] != "off" || len(rows[0]) <= 7 {
		t.Errorf("node rows: %v", rows)
	}
	rows, _ = f.GetRows("Summary")
	joined := ""
	for _, r := range rows {
		joined += strings.Join(r, " ") + "\n"
	}
	for _, want := range []string{"khealth report", "prod/cluster:a", "rke2", "CRIT 1", "DISA RHEL 9 STIG V2R9 (01 Jul 2026) RHEL 9 STIG 50 1 1", "Kubernetes STIG 50 1 1 0 0 0 2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary lacks %q:\n%s", want, joined)
		}
	}
	// the severity cell carries the crit style, the header is frozen
	style, _ := f.GetCellStyle("Findings", "A2")
	if style == 0 {
		t.Error("severity cell has no style")
	}
	if panes, err := f.GetPanes("Findings"); err != nil || !panes.Freeze || panes.YSplit != 1 {
		t.Errorf("panes: %+v %v", panes, err)
	}
}

func TestWriteFilesNoScan(t *testing.T) {
	in := sampleInput()
	in.StigRun, in.Stig = false, nil
	dir := t.TempDir()
	_, xlsxPath, err := WriteFiles(dir, Build(in))
	if err != nil {
		t.Fatal(err)
	}
	f, err := excelize.OpenFile(xlsxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := strings.Join(f.GetSheetList(), "|"); got != "Summary|Findings|Nodes" {
		t.Errorf("sheets without a scan: %s", got)
	}
	rows, _ := f.GetRows("Summary")
	found := false
	for _, r := range rows {
		if len(r) > 0 && strings.HasPrefix(r[0], "not run") {
			found = true
		}
	}
	if !found {
		t.Error("summary should say the scan was not run")
	}
}
