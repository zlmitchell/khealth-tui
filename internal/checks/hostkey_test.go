package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Nodes presenting the same SSH host key (clones never re-keyed) are flagged,
// each naming the others; a node with its own key, or no key yet, is not.
func TestSharedHostKey(t *testing.T) {
	node := func(name, key string) *nodeinfo.Info {
		return &nodeinfo.Info{Node: name, HostKey: key, KubeletFlags: map[string]string{}, Sysctl: map[string]string{}, Settings: map[string]string{}, Hardening: map[string]string{}}
	}
	in := Input{Snap: &k8s.Snapshot{}, Cfg: config.Default(), Now: time.Now(), SSHEnabled: true, Nodes: map[string]*nodeinfo.Info{
		"cp-1":    node("cp-1", "SHA256:aaa"),
		"cp-2":    node("cp-2", "SHA256:aaa"),
		"cp-3":    node("cp-3", "SHA256:aaa"),
		"worker":  node("worker", "SHA256:bbb"),
		"pending": node("pending", ""),
	}}
	got := map[string]string{}
	for _, f := range Evaluate(in) {
		if strings.HasPrefix(f.Message, "SSH host key is shared with ") {
			got[f.Object] = f.Message
		}
	}
	want := map[string]string{
		"cp-1": "SSH host key is shared with cp-2, cp-3 (cloned image not re-keyed)",
		"cp-2": "SSH host key is shared with cp-1, cp-3 (cloned image not re-keyed)",
		"cp-3": "SSH host key is shared with cp-1, cp-2 (cloned image not re-keyed)",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for obj, msg := range want {
		if got[obj] != msg {
			t.Errorf("%s: %q, want %q", obj, got[obj], msg)
		}
	}
}
