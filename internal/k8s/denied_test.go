package k8s

import (
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestDeniedGate(t *testing.T) {
	c := &Client{Opts: Options{DeniedTTL: time.Minute}}
	gr := schema.GroupResource{Resource: "pods"}
	forbidden := apierrors.NewForbidden(gr, "", errors.New("User \"x\" cannot list resource \"pods\""))
	notFound := apierrors.NewNotFound(gr, "")

	if _, ok := c.Denied("pods"); ok {
		t.Fatal("nothing denied yet")
	}
	if !c.NoteDenied("pods", forbidden, false) {
		t.Fatal("403 must be remembered")
	}
	if err, ok := c.Denied("pods"); !ok || err != forbidden {
		t.Fatalf("denied not returned: %v %v", err, ok)
	}
	// 404 only counts when the caller says a missing resource type is stable (lists)
	if c.NoteDenied("events", notFound, false) {
		t.Fatal("404 on a non-list must not be remembered")
	}
	if !c.NoteDenied("etcdsnapshotfiles", notFound, true) {
		t.Fatal("404 on a list must be remembered")
	}
	// other errors are never remembered
	if c.NoteDenied("nodes", errors.New("dial tcp: i/o timeout"), true) {
		t.Fatal("transport error remembered")
	}
	// string-only forbidden (exec errors are flattened to text)
	if !c.NoteDenied("pods/exec", errors.New(`pods "etcd-a" is forbidden: User "x" cannot create resource "pods/exec"`), false) {
		t.Fatal("textual forbidden not remembered")
	}
	if got := c.DeniedList(); len(got) != 3 || got[0] != "etcdsnapshotfiles" || got[1] != "pods" || got[2] != "pods/exec" {
		t.Fatalf("list %v", got)
	}
	// TTL expiry
	c.cacheMu.Lock()
	c.denied["pods"] = deniedEntry{err: forbidden, at: time.Now().Add(-2 * time.Minute)}
	c.cacheMu.Unlock()
	if _, ok := c.Denied("pods"); ok {
		t.Fatal("expired entry still denied")
	}
	c.ResetDenied()
	if len(c.DeniedList()) != 0 {
		t.Fatal("reset did not clear")
	}
	// disabled
	off := &Client{}
	if off.NoteDenied("pods", forbidden, false) {
		t.Fatal("gate active with DeniedTTL 0")
	}
}
