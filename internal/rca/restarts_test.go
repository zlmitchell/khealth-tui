package rca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
)

var edt = time.FixedZone("-0400", -4*3600)

func at(h, m, s int) time.Time { return time.Date(2026, 9, 27, h, m, s, 0, edt) }

// The Rancher node's /var/log/messages around a hypervisor reboot whose
// shutdown hung: rsyslog lost the kernel's "Linux version" line, so the
// boot is its next lines.
const hungMessages = `Sep 27 20:31:00 rancher rke2[1020]: time="2026-09-27T20:31:00-04:00" level=error msg="before the reboot"
Sep 27 20:32:29 rancher qemu-ga[940]: info: guest-shutdown called, mode: reboot
Sep 27 20:32:29 rancher systemd-logind[941]: System is rebooting (hypervisor initiated shutdown).
Sep 27 20:32:29 rancher systemd[1]: Stopping libcontainer container 3138f99183466164d86327e61b36b45912eeecaa692410b34c9d31d8da0e4ee5...
Sep 27 21:58:48 rancher kernel: The list of certified hardware and cloud instances for Enterprise Linux 9 can be viewed at the Red Hat Ecosystem Catalog
Sep 27 21:58:48 rancher kernel: Command line: BOOT_IMAGE=(hd0,gpt2)/vmlinuz-5.14.0-611.24.1.el9_7.x86_64 root=/dev/mapper/rl-root ro
Sep 27 22:10:00 rancher rke2[1020]: time="2026-09-27T22:10:00-04:00" level=error msg="after the boot"
`

func hungSyslog(t *testing.T) []Entry {
	t.Helper()
	p := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(p, []byte(hungMessages), 0o644); err != nil {
		t.Fatal(err)
	}
	es, n := syslogEntries(p, "nodes/rancher/files/messages", "rancher", at(23, 27, 0), true)
	if n != 7 {
		t.Fatalf("lines read: %d", n)
	}
	return es
}

func TestSyslogBootsAndShutdowns(t *testing.T) {
	byPattern := map[string][]Entry{}
	for _, e := range hungSyslog(t) {
		byPattern[e.Pattern] = append(byPattern[e.Pattern], e)
	}
	if b := byPattern["kernel-boot"]; len(b) != 1 || !b[0].Time.Equal(at(21, 58, 48)) {
		t.Errorf("one boot at 21:58:48: %+v", b)
	}
	if l := byPattern["boot-last-line"]; len(l) != 1 || !l[0].Time.Equal(at(20, 32, 29)) || !strings.HasPrefix(l[0].Text, "systemd[1]: Stopping libcontainer container") || l[0].Ref.Line != 4 {
		t.Errorf("the old boot's last line: %+v", l)
	}
	if r := byPattern["shutdown-requested"]; len(r) != 2 || r[0].Unit != "qemu-ga" {
		t.Errorf("requests: %+v", r)
	}
	// the old boot's errors are kept, the current boot is the journal's
	if g := byPattern["generic-error"]; len(g) != 1 || !strings.Contains(g[0].Text, "before the reboot") {
		t.Errorf("old-boot errors: %+v", g)
	}
}

func lostCtr(ns, pod, ctr string, started, ended, ready time.Time, isReady bool) corev1.Pod {
	st := corev1.ConditionTrue
	if !isReady {
		st = corev1.ConditionFalse
	}
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pod}, Spec: corev1.PodSpec{NodeName: "rancher"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, StartTime: &metav1.Time{Time: started},
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: st, LastTransitionTime: metav1.NewTime(ready)}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: ctr, RestartCount: 3, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Unknown", ExitCode: 255, FinishedAt: metav1.NewTime(ended)}}}}}}
}

// The hypervisor asked for a reboot, the shutdown hung for 86 minutes, the
// node booted, rke2 came up and the pods came back - one restart, told in
// its phases, and one incident that holds the containers it ended.
func TestHungReboot(t *testing.T) {
	boot, lost := at(21, 58, 48), at(21, 58, 56)
	month := boot.AddDate(0, -1, 0)
	snap := &k8s.Snapshot{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "rancher", CreationTimestamp: metav1.NewTime(month)}}},
		Pods: []corev1.Pod{
			lostCtr("harbor", "harbor-db-0", "db", month, lost, at(22, 3, 10), true),
			lostCtr("harbor", "harbor-core-0", "core", month, lost, at(22, 4, 25), true),
			lostCtr("dev", "image-seeder-txss4", "seed", month, lost, at(21, 59, 30), false),
		},
	}
	tl := newTimeline()
	tl.Boots["rancher"] = at(21, 58, 53) // the probe's uptime: the same boot
	tl.Entries = append(hungSyslog(t),
		Entry{Time: at(22, 2, 4), Node: "rancher", Kind: "journal", Class: logs.ClassInfo, Pattern: "rke2-up", Text: `rke2[1020]: level=info msg="rke2 is up and running"`})
	tl.Entries = append(tl.Entries, snapshotEntries(snap)...)

	rs := Restarts(tl, snap)
	if len(rs) != 1 {
		t.Fatalf("restarts: %+v", rs)
	}
	r := rs[0]
	if r.How != "reboot" || !r.Boot.Equal(boot) || !r.Requested.Equal(at(20, 32, 29)) || !strings.Contains(r.By, "QEMU guest agent (mode reboot)") || r.Clean || !r.Hung() {
		t.Errorf("request and hang: %+v", r)
	}
	if !r.Up.Equal(at(22, 2, 4)) || !r.Settled.Equal(at(22, 4, 25)) || len(r.Waiting) != 1 || r.Waiting[0] != "dev/image-seeder-txss4" || len(r.Lost) != 3 {
		t.Errorf("coming back: up %v settled %v waiting %v lost %v", r.Up, r.Settled, r.Waiting, r.Lost)
	}
	if !r.Start().Equal(at(20, 32, 29)) || !r.End().Equal(at(22, 4, 25)) || !r.Covers(at(22, 1, 0)) || r.Covers(at(22, 30, 0)) {
		t.Errorf("span %v to %v", r.Start(), r.End())
	}
	if h := r.Headline(); !strings.Contains(h, "the shutdown hung - nothing logged for 1h26m until the boot") {
		t.Errorf("headline %q", h)
	}
	ps := strings.Join(r.Phases(), " | ")
	for _, want := range []string{"requested ", "last line ", "the shutdown never finished", "booted ", "rke2/k3s up ", "settled ", "1 pod(s) never Ready again: dev/image-seeder-txss4"} {
		if !strings.Contains(ps, want) {
			t.Errorf("phases lack %q: %s", want, ps)
		}
	}

	got := kinds(Extract(tl, snap))
	if rb := got[KindReboot]; len(rb) != 1 || rb[0].Node != "rancher" || len(rb[0].Pods) != 3 || !rb[0].Time.Equal(r.Start()) {
		t.Errorf("reboot incident: %+v", rb)
	}
	if n := len(got[KindRestart]); n != 0 {
		t.Errorf("the containers it ended are the reboot's, not %d restart incidents", n)
	}
}

func marks(es ...Entry) *Timeline {
	tl := newTimeline()
	tl.Entries = es
	return tl
}

func mark(pattern, text string, t time.Time) Entry {
	return Entry{Time: t, Node: "n1", Kind: "file", Class: logs.ClassInfo, Pattern: pattern, Text: text}
}

func TestPlannedAndUnplannedReboots(t *testing.T) {
	empty := &k8s.Snapshot{}
	planned := Restarts(marks(
		mark("shutdown-requested", "systemd-logind[900]: System is rebooting.", at(10, 0, 0)),
		mark("shutdown-clean", `rsyslogd[994]: [origin software="rsyslogd"] exiting on signal 15.`, at(10, 0, 20)),
		mark("boot-last-line", `rsyslogd[994]: [origin software="rsyslogd"] exiting on signal 15.`, at(10, 0, 20)),
		mark("kernel-boot", "kernel: Command line: BOOT_IMAGE=/vmlinuz", at(10, 1, 30)),
	), empty)
	if len(planned) != 1 || planned[0].Hung() || !planned[0].Clean || !strings.HasPrefix(planned[0].Headline(), "planned: a reboot command asked for it at") {
		t.Errorf("planned: %+v %q", planned, planned[0].Headline())
	}
	crash := Restarts(marks(
		mark("boot-last-line", "kernel: NMI watchdog: BUG: soft lockup - CPU#2 stuck for 22s!", at(9, 0, 0)),
		mark("kernel-boot", "kernel: Linux version 5.14.0", at(9, 5, 0)),
	), empty)
	if len(crash) != 1 || !strings.HasPrefix(crash[0].Headline(), "unplanned: nothing asked for a shutdown - the old boot's last line is at") || !crash[0].Start().Equal(at(9, 0, 0)) {
		t.Errorf("unplanned: %+v", crash)
	}
}
