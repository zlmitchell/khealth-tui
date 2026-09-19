package ui

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"k8s-health-tui/internal/etcd"
)

// TestEtcdSummaryFallsBackToExec: with no usable SSH probe the tiles must be
// filled from the kubectl-exec probe and, failing that, say why they are empty.
func TestEtcdSummaryFallsBackToExec(t *testing.T) {
	a := testApp()
	a.etcd = map[string]*etcd.Probe{}
	a.etcdExec = nil
	if s := a.etcdSummarise(); s.probed != 0 || s.noProbeReason != "no etcd nodes probed" {
		t.Errorf("empty: probed=%d reason=%q", s.probed, s.noProbeReason)
	}

	a.etcd["cp-1"] = &etcd.Probe{Node: "cp-1", Err: errors.New("sudo requires a password")}
	if s := a.etcdSummarise(); s.noProbeReason != "1 probe error" {
		t.Errorf("errored probe: reason=%q", s.noProbeReason)
	}
	a.etcdExec = &etcd.Probe{Err: errors.New("pods/exec forbidden")}
	if s := a.etcdSummarise(); s.noProbeReason != "1 probe error, exec failed" {
		t.Errorf("errored probe + exec: reason=%q", s.noProbeReason)
	}

	a.etcdExec = &etcd.Probe{
		EtcdctlVia: "kubectl exec etcd-cp-1",
		Members: []etcd.Member{
			{ID: "a1", Name: "cp-1", ClientURLs: []string{"https://10.0.0.1:2379"}},
			{ID: "b2", Name: "cp-2", ClientURLs: []string{"https://10.0.0.2:2379"}, IsLearner: true},
		},
		Statuses: []etcd.EndpointStatus{
			{Endpoint: "https://10.0.0.1:2379", MemberID: "a1", Leader: "a1", DBSize: 1000, DBSizeInUse: 250},
			{Endpoint: "https://10.0.0.2:2379", MemberID: "b2", Leader: "a1", DBSize: 800, DBSizeInUse: 800},
		},
		EndpointHealth: []etcd.EndpointHealth{
			{Endpoint: "https://10.0.0.1:2379", Healthy: true},
			{Endpoint: "https://10.0.0.2:2379", Healthy: false, Error: "context deadline exceeded"},
		},
	}
	s := a.etcdSummarise()
	if s.memberInfo != "2 members, 1 learner" || s.leader != "cp-1" || s.source != "exec" {
		t.Errorf("members from exec: info=%q leader=%q source=%q", s.memberInfo, s.leader, s.source)
	}
	if s.probed != 2 || s.healthy != 1 || s.noProbeReason != "" {
		t.Errorf("health from exec: %d/%d reason=%q", s.healthy, s.probed, s.noProbeReason)
	}
	if s.dbSize != 1000 || s.dbNode != "cp-1" || math.Abs(s.frag-75) > 0.01 || !math.IsNaN(s.dbPct) {
		t.Errorf("db from exec status: size=%v node=%q frag=%v pct=%v", s.dbSize, s.dbNode, s.frag, s.dbPct)
	}

	a.width, a.height = 160, 50
	v := ansi.Strip(strings.Join(a.etcdTiles(), "\n"))
	for _, want := range []string{"2 members, 1 learner", "leader: cp-1 via exec", "healthy: 1/2", "1000B on cp-1 (no quota)"} {
		if !strings.Contains(v, want) {
			t.Errorf("tiles missing %q:\n%s", want, v)
		}
	}

	// SSH metrics win over exec sizes once a probe succeeds
	a.etcd["cp-1"] = &etcd.Probe{Node: "cp-1", Health: &etcd.Health{Healthy: true}, Metrics: &etcd.Metrics{DBSize: 2000, DBSizeInUse: 1000, Quota: 4000, WalFsyncAvgMs: 3}}
	s = a.etcdSummarise()
	if s.probed != 1 || s.healthy != 1 || s.dbSize != 2000 || math.Abs(s.dbPct-50) > 0.01 || math.Abs(s.frag-50) > 0.01 {
		t.Errorf("ssh wins: %+v", s)
	}
	if s.memberInfo != "2 members, 1 learner" || s.source != "exec" {
		t.Errorf("members still from exec: info=%q source=%q", s.memberInfo, s.source)
	}
}
