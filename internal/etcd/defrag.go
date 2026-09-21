package etcd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// defragHealthWait is the pause between health checks after a member's
// defrag (shortened by tests).
var defragHealthWait = 2 * time.Second

// DefragStep is the outcome for one member.
type DefragStep struct {
	Member   string
	Endpoint string
	Leader   bool
	Before   int64 // db size (bytes) before, 0 when unknown
	After    int64
	Took     time.Duration
	Err      error
	Healthy  bool
	Skipped  string // why the member was not touched
}

// DefragReport is the result of a cluster-wide, one-member-at-a-time
// defragmentation.
type DefragReport struct {
	Steps   []DefragStep
	Aborted string // set when a member came back unhealthy and the rest was skipped
}

func (r DefragReport) String() string {
	var b strings.Builder
	for _, s := range r.Steps {
		role := ""
		if s.Leader {
			role = " (leader, last)"
		}
		switch {
		case s.Skipped != "":
			fmt.Fprintf(&b, "%s%s: skipped - %s\n", s.Member, role, s.Skipped)
		case s.Err != nil:
			fmt.Fprintf(&b, "%s%s: FAILED after %s: %v\n", s.Member, role, s.Took.Round(time.Millisecond), s.Err)
		default:
			size := ""
			if s.Before > 0 && s.After > 0 {
				size = fmt.Sprintf(", db %s -> %s", strutil.HumanBytes(float64(s.Before)), strutil.HumanBytes(float64(s.After)))
			}
			health := "healthy"
			if !s.Healthy {
				health = "UNHEALTHY afterwards"
			}
			fmt.Fprintf(&b, "%s%s: defragmented in %s%s, %s\n", s.Member, role, s.Took.Round(time.Millisecond), size, health)
		}
	}
	if r.Aborted != "" {
		fmt.Fprintf(&b, "aborted: %s\n", r.Aborted)
	}
	return b.String()
}

// Defrag runs `etcdctl defrag` against every member of the cluster, one at a
// time through the etcd static pod: followers first, the leader last, with
// an endpoint health check after each. A member that does not come back
// healthy stops the run so at most one member is ever degraded. A defrag
// blocks that member for its duration (seconds per GB), which is why it is
// never done cluster-wide in one call.
func Defrag(ctx context.Context, ex Execer, pod, dist string, members []Member, leaderID string) DefragReport {
	ca, cert, key := CertPaths(dist)
	base := []string{"etcdctl", "--cacert=" + ca, "--cert=" + cert, "--key=" + key}
	run := func(timeout string, args ...string) (string, error) {
		argv := append(append([]string{}, base...), "--command-timeout="+timeout, "--dial-timeout=5s")
		argv = append(argv, args...)
		out, errOut, err := ex.ExecInPod(ctx, "kube-system", pod, "etcd", argv)
		if err != nil {
			return out, fmt.Errorf("%v: %s", err, strutil.FirstLine(strings.TrimSpace(errOut+"\n"+out)))
		}
		return out, nil
	}
	// followers first, then the leader: a leader defrag stalls every write
	// in the cluster, so it goes last and only once the others are healthy
	ordered := make([]Member, 0, len(members))
	var leader *Member
	for i := range members {
		if members[i].ID == leaderID {
			m := members[i]
			leader = &m
			continue
		}
		ordered = append(ordered, members[i])
	}
	if leader != nil {
		ordered = append(ordered, *leader)
	}
	var rep DefragReport
	for _, m := range ordered {
		step := DefragStep{Member: m.Name, Leader: m.ID == leaderID}
		if step.Member == "" {
			step.Member = m.ID
		}
		if rep.Aborted != "" {
			step.Skipped = "an earlier member is unhealthy"
			rep.Steps = append(rep.Steps, step)
			continue
		}
		if m.IsLearner {
			step.Skipped = "learner (not serving reads or writes yet)"
			rep.Steps = append(rep.Steps, step)
			continue
		}
		if len(m.ClientURLs) == 0 {
			step.Skipped = "no client URL"
			rep.Steps = append(rep.Steps, step)
			continue
		}
		step.Endpoint = m.ClientURLs[0]
		ep := "--endpoints=" + step.Endpoint
		step.Before = dbSize(run, ep)
		start := time.Now()
		_, err := run("10m", ep, "defrag")
		step.Took = time.Since(start)
		if err != nil {
			step.Err = err
			rep.Steps = append(rep.Steps, step)
			rep.Aborted = step.Member + " failed to defragment; the remaining members were left alone"
			continue
		}
		step.After = dbSize(run, ep)
		// give the member a moment to serve again, then check it
		for i := 0; i < 5 && !step.Healthy; i++ {
			if out, herr := run("10s", ep, "endpoint", "health", "-w", "json"); herr == nil {
				for _, h := range parseEndpointHealth(out) {
					if h.Healthy {
						step.Healthy = true
					}
				}
			}
			if !step.Healthy {
				select {
				case <-ctx.Done():
					i = 5
				case <-time.After(defragHealthWait):
				}
			}
		}
		rep.Steps = append(rep.Steps, step)
		if !step.Healthy {
			rep.Aborted = step.Member + " is not healthy after its defrag; the remaining members were left alone"
		}
	}
	return rep
}

// dbSize reads one endpoint's db size through endpoint status; 0 if that
// fails (the run continues, the report just lacks the sizes).
func dbSize(run func(string, ...string) (string, error), ep string) int64 {
	out, err := run("10s", ep, "endpoint", "status", "-w", "json")
	if err != nil {
		return 0
	}
	p := &Probe{}
	parseEtcdctl(p, "---STATUS\n"+out+"\n")
	if len(p.Statuses) == 0 {
		return 0
	}
	return p.Statuses[0].DBSize
}
