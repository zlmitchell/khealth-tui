package ui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/rca"
)

func sshIncidents(a *App) []rca.Incident {
	a.incRefresh()
	var out []rca.Incident
	for _, in := range a.inc.list {
		if in.Kind == rca.KindSSH {
			out = append(out, in)
		}
	}
	return out
}

// A node the cluster lists whose probe cannot get through over SSH is an
// incident until a probe answers again; one the cluster does not list is
// not, and with SSH off there is nothing to report.
func TestSSHFailureIncident(t *testing.T) {
	a := testApp()
	first := time.Now().Add(-5 * time.Minute)
	a.Update(nodeMsg{gen: a.gen, info: &nodeinfo.Info{Node: "w-1", Collected: first, Err: errors.New("dial tcp 10.0.0.2:22: i/o timeout")}})
	a.Update(nodeMsg{gen: a.gen, info: &nodeinfo.Info{Node: "w-1", Collected: time.Now(), Err: errors.New("dial tcp 10.0.0.2:22: connection refused")}})
	a.Update(nodeMsg{gen: a.gen, info: &nodeinfo.Info{Node: "ghost", Collected: first, Err: errors.New("no route to host")}})
	got := sshIncidents(a)
	if len(got) != 1 || got[0].Node != "w-1" || !got[0].Time.Equal(first) || got[0].Summary != "SSH to the node failed: dial tcp 10.0.0.2:22: connection refused" {
		t.Fatalf("ssh incidents %+v", got)
	}

	a.sshEnabled = false
	a.snap.Taken = a.snap.Taken.Add(time.Second)
	if got := sshIncidents(a); len(got) != 0 {
		t.Errorf("SSH off still reports %+v", got)
	}
	a.sshEnabled = true

	a.Update(nodeMsg{gen: a.gen, info: nodeinfo.Parse("w-1", "10.0.0.2", nodeSample, time.Now())})
	a.snap.Taken = a.snap.Taken.Add(time.Second)
	if got := sshIncidents(a); len(got) != 0 {
		t.Errorf("a probe that answered still reports %+v", got)
	}
}

// The API not answering is an incident from the first snapshot that could
// not list the nodes; it names the nodes SSH still reaches, and goes away
// with the first snapshot that answers.
func TestAPIUnavailableIncident(t *testing.T) {
	a := testApp()
	good := a.snap
	down := time.Now().Add(-2 * time.Minute)
	refused := `nodes: Get "https://10.0.0.1:6443/api/v1/nodes": dial tcp 10.0.0.1:6443: connect: connection refused`
	a.Update(snapshotMsg{seq: a.seq, snap: &k8s.Snapshot{Taken: down, Errors: []string{refused}}})
	a.Update(snapshotMsg{seq: a.seq, snap: &k8s.Snapshot{Taken: time.Now(), Errors: []string{refused}}})
	a.incRefresh()
	var api []rca.Incident
	for _, in := range a.inc.list {
		if in.Kind == rca.KindAPI {
			api = append(api, in)
		}
	}
	if len(api) != 1 || api[0].Object() != "apiserver" || !api[0].Time.Equal(down) || !strings.Contains(api[0].Summary, "connection refused") || !strings.Contains(api[0].Summary, "SSH still reaches cp-1") {
		t.Fatalf("API incidents %+v", api)
	}

	// RBAC refusing the list is an answer, not an outage
	a.Update(snapshotMsg{seq: a.seq, snap: &k8s.Snapshot{Taken: time.Now(), Errors: []string{`nodes: nodes is forbidden: User "x" cannot list resource "nodes"`}}})
	if a.apiDown != nil {
		t.Errorf("forbidden counted as down: %+v", a.apiDown)
	}
	good.Taken = time.Now()
	a.Update(snapshotMsg{seq: a.seq, snap: good})
	a.incRefresh()
	for _, in := range a.inc.list {
		if in.Kind == rca.KindAPI {
			t.Errorf("API answered, still reported: %+v", in)
		}
	}
}
