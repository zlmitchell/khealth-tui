package ui

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// v decodes a Secret in place; leaving the level forgets it, so the next
// visit starts masked again rather than the reveal following you around.
func TestInspectRevealSecret(t *testing.T) {
	a := testApp()
	sec := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "creds", "namespace": "default"},
		"data":     map[string]any{"password": base64.StdEncoding.EncodeToString([]byte("s3cret-value"))},
	}}
	a.inspect = []inspectLevel{levelFromObject(sec, a.snap)}
	a.overlay = ovInspect

	if v := ansi.Strip(a.View()); strings.Contains(v, "s3cret-value") {
		t.Fatalf("a secret must start masked:\n%s", v)
	}
	a.handleInspectKey("v")
	v := ansi.Strip(a.View())
	if !strings.Contains(v, "s3cret-value") || !strings.Contains(v, "stringData") {
		t.Errorf("v should decode into stringData:\n%s", v)
	}
	if !strings.Contains(a.status, "esc hides them again") {
		t.Errorf("the reveal should say how to undo it: %q", a.status)
	}
	// toggles back
	a.handleInspectKey("v")
	if v := ansi.Strip(a.View()); strings.Contains(v, "s3cret-value") {
		t.Errorf("v again should mask:\n%s", v)
	}

	// revealed, then left: coming back is masked
	a.handleInspectKey("v")
	a.handleInspectKey("esc")
	a.inspect = []inspectLevel{levelFromObject(sec, a.snap)}
	a.overlay = ovInspect
	if v := ansi.Strip(a.View()); strings.Contains(v, "s3cret-value") {
		t.Errorf("reveal must not survive leaving the object:\n%s", v)
	}
}

// v on something with nothing hidden says so instead of doing nothing.
func TestInspectRevealNonSecret(t *testing.T) {
	a := testApp()
	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "app-1", "namespace": "default"},
	}}
	a.inspect = []inspectLevel{levelFromObject(pod, a.snap)}
	a.overlay = ovInspect
	a.handleInspectKey("v")
	if !strings.Contains(a.status, "has neither") {
		t.Errorf("v on a pod should explain itself: %q", a.status)
	}
	if a.inspect[0].reveal {
		t.Errorf("reveal should stay off for an object with nothing to decode")
	}
}
