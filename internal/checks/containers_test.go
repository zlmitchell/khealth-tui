package checks

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// Each container's own state decides, init containers included, and a
// crash loop is one whether the check lands in a back-off or between two.
func TestContainerTrouble(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	ended := func(reason string, code int32, ago time.Duration) corev1.ContainerState {
		return corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: code, FinishedAt: metav1.NewTime(now.Add(-ago))}}
	}
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(now.Add(-30 * time.Second))}}
	waiting := func(reason, msg string) corev1.ContainerState {
		return corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg}}
	}
	pod := func(name string, init, ctrs []corev1.ContainerStatus) corev1.Pod {
		p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, CreationTimestamp: metav1.NewTime(now.Add(-24 * time.Hour))},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, InitContainerStatuses: init, ContainerStatuses: ctrs}}
		for _, cs := range append(append([]corev1.ContainerStatus{}, init...), ctrs...) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: cs.Name, Image: "harbor.corp/app/" + cs.Name + ":1.0"})
		}
		return p
	}
	cs := func(name string, restarts int32, state, last corev1.ContainerState) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: name, RestartCount: restarts, State: state, LastTerminationState: last}
	}
	snap := &k8s.Snapshot{Pods: []corev1.Pod{
		// the image-seeder on the Rancher node: its init container cannot pull
		pod("seeder", []corev1.ContainerStatus{cs("seed", 0, waiting("ImagePullBackOff", `Back-off pulling image "ghcr.io/x/ansible:latest"`), corev1.ContainerState{})}, nil),
		// running again between two back-offs
		pod("between", nil, []corev1.ContainerStatus{cs("app", 6, running, ended("Error", 1, 2*time.Minute))}),
		// just exited, the kubelet has not started the back-off yet
		pod("exited", nil, []corev1.ContainerStatus{cs("app", 4, ended("Error", 2, 0), ended("Error", 2, 90*time.Second))}),
		// the sidecar is fine, the second container loops
		pod("second", nil, []corev1.ContainerStatus{cs("proxy", 0, running, corev1.ContainerState{}), cs("app", 9, waiting("CrashLoopBackOff", "back-off 5m0s"), ended("Error", 1, 4*time.Minute))}),
		// an init container that loops
		pod("initloop", []corev1.ContainerStatus{cs("migrate", 5, waiting("CrashLoopBackOff", ""), ended("Error", 1, time.Minute))}, nil),
		// not crash loops: a node restart ended it; failures long ago
		pod("rebooted", nil, []corev1.ContainerStatus{cs("app", 3, running, ended("Unknown", 255, 5*time.Minute))}),
		pod("old", nil, []corev1.ContainerStatus{cs("app", 3, running, ended("Error", 1, 3*time.Hour))}),
	}}
	f := Evaluate(Input{Snap: snap, Cfg: config.Default(), Now: now})
	find := func(obj string) []Finding {
		var out []Finding
		for _, x := range f {
			if x.Area == "workload" && x.Object == "app/"+obj {
				out = append(out, x)
			}
		}
		return out
	}
	for obj, want := range map[string]string{
		"seeder":   `ImagePullBackOff: init container seed cannot pull harbor.corp/app/seed:1.0: Back-off pulling image "ghcr.io/x/ansible:latest"`,
		"between":  "CrashLoopBackOff: container app keeps failing, 6 restarts, last exit 1 (Error) 2m ago",
		"exited":   "CrashLoopBackOff: container app keeps failing, 4 restarts",
		"second":   "CrashLoopBackOff: container app, 9 restarts, last exit 1 (Error) 4m ago",
		"initloop": "CrashLoopBackOff: init container migrate, 5 restarts",
	} {
		fs := find(obj)
		if len(fs) != 1 || fs[0].Severity != SevCrit || !strings.HasPrefix(fs[0].Message, want) {
			t.Errorf("%s: want one CRIT %q, got %+v", obj, want, fs)
		}
	}
	for _, obj := range []string{"rebooted", "old"} {
		for _, x := range find(obj) {
			if x.Severity == SevCrit || strings.Contains(x.Message, "CrashLoop") {
				t.Errorf("%s is not crash-looping: %+v", obj, x)
			}
		}
	}
}
