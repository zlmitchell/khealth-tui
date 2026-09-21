package etcd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// defragExec answers per endpoint: health and status by endpoint, defrag
// failure for one, and records the order the members were defragmented in.
type defragExec struct {
	unhealthy map[string]bool
	failOn    map[string]bool
	order     []string
	timeouts  []string
}

func (d *defragExec) ExecInPod(_ context.Context, _, _, _ string, cmd []string) (string, string, error) {
	ep, verb := "", ""
	for _, c := range cmd[1:] {
		switch {
		case strings.HasPrefix(c, "--endpoints="):
			ep = strings.TrimPrefix(c, "--endpoints=")
		case strings.HasPrefix(c, "--command-timeout="):
			d.timeouts = append(d.timeouts, strings.TrimPrefix(c, "--command-timeout="))
		case strings.HasPrefix(c, "--") || c == "-w" || c == "json":
		default:
			verb += c + " "
		}
	}
	switch strings.TrimSpace(verb) {
	case "defrag":
		d.order = append(d.order, ep)
		if d.failOn[ep] {
			return "", "Error: context deadline exceeded", errors.New("exit status 1")
		}
		return "Finished defragmenting etcd member[" + ep + "]", "", nil
	case "endpoint health":
		if d.unhealthy[ep] {
			return `[{"endpoint":"` + ep + `","health":false,"error":"context deadline exceeded"}]`, "", errors.New("exit status 1")
		}
		return `[{"endpoint":"` + ep + `","health":true,"took":"2ms"}]`, "", nil
	case "endpoint status":
		size := "4000000"
		if len(d.order) > 0 && d.order[len(d.order)-1] == ep {
			size = "1000000" // after its defrag
		}
		return `[{"Endpoint":"` + ep + `","Status":{"header":{"member_id":1},"version":"3.5.9","dbSize":` + size + `,"dbSizeInUse":900000,"leader":1}}]`, "", nil
	}
	return "", "", errors.New("unexpected verb " + verb)
}

var threeMembers = []Member{
	{ID: "1", Name: "cp-1", ClientURLs: []string{"https://10.0.0.1:2379"}},
	{ID: "2", Name: "cp-2", ClientURLs: []string{"https://10.0.0.2:2379"}},
	{ID: "3", Name: "cp-3", ClientURLs: []string{"https://10.0.0.3:2379"}},
	{ID: "4", Name: "cp-4", ClientURLs: []string{"https://10.0.0.4:2379"}, IsLearner: true},
}

func TestDefragOrderAndReport(t *testing.T) {
	ex := &defragExec{}
	rep := Defrag(context.Background(), ex, "etcd-cp-1", "rke2", threeMembers, "1")
	if strings.Join(ex.order, ",") != "https://10.0.0.2:2379,https://10.0.0.3:2379,https://10.0.0.1:2379" {
		t.Errorf("leader must go last, learner skipped: %v", ex.order)
	}
	if len(rep.Steps) != 4 || rep.Aborted != "" {
		t.Fatalf("report: %+v", rep)
	}
	if s := rep.Steps[3]; !s.Leader || s.Before != 4000000 || s.After != 1000000 || !s.Healthy || s.Err != nil {
		t.Errorf("leader step: %+v", s)
	}
	if s := rep.Steps[2]; s.Skipped == "" {
		t.Errorf("learner should be skipped: %+v", s)
	}
	text := rep.String()
	if !strings.Contains(text, "cp-1 (leader, last): defragmented") || !strings.Contains(text, "3.8 MiB -> 976.6 KiB") && !strings.Contains(text, "->") {
		t.Errorf("report text:\n%s", text)
	}
	// defrag itself must not run under etcdctl's 5 s default timeout
	for _, to := range ex.timeouts {
		if to == "5s" {
			t.Errorf("timeouts: %v", ex.timeouts)
		}
	}
}

func TestDefragStopsAtUnhealthyMember(t *testing.T) {
	prev := defragHealthWait
	defragHealthWait = 0
	defer func() { defragHealthWait = prev }()
	ex := &defragExec{unhealthy: map[string]bool{"https://10.0.0.2:2379": true}}
	rep := Defrag(context.Background(), ex, "etcd-cp-1", "rke2", threeMembers[:3], "1")
	if len(ex.order) != 1 || ex.order[0] != "https://10.0.0.2:2379" {
		t.Errorf("only the first follower should have been touched: %v", ex.order)
	}
	if rep.Aborted == "" || !strings.Contains(rep.String(), "skipped - an earlier member is unhealthy") {
		t.Errorf("run should abort and skip the rest:\n%s", rep.String())
	}

	ex = &defragExec{failOn: map[string]bool{"https://10.0.0.2:2379": true}}
	rep = Defrag(context.Background(), ex, "etcd-cp-1", "rke2", threeMembers[:3], "1")
	if len(ex.order) != 1 || rep.Steps[0].Err == nil || !strings.Contains(rep.Aborted, "failed to defragment") {
		t.Errorf("a failed defrag must stop the run: %v / %+v", ex.order, rep)
	}
}
