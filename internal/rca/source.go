package rca

import (
	"os"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/zlmitchell/khealth-tui/internal/gather"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Source is what the incident context reads beyond the timeline: a log
// bundle, or the live TUI's state and API client.
type Source interface {
	Snap() *k8s.Snapshot
	// Objects lists one resource type ("replicasets.apps",
	// "pods.metrics.k8s.io", "httproutes.gateway.networking.k8s.io"), nil
	// when it is not available.
	Objects(resource string) []unstructured.Unstructured
	// PodLog is a container's log with timestamps (previous: the run
	// before the last restart) and where it came from; nil when absent.
	PodLog(ns, pod, container string, previous bool) ([]string, string)
	// Node is the node probe's view of a node, nil when not probed.
	Node(name string) *nodeinfo.Info
}

// BundleSource reads a log bundle.
type BundleSource struct {
	B *gather.Bundle
	R *gather.Replayed

	mu   sync.Mutex
	objs map[string][]unstructured.Unstructured
}

// NewBundleSource wraps an opened, replayed bundle.
func NewBundleSource(b *gather.Bundle, r *gather.Replayed) *BundleSource {
	return &BundleSource{B: b, R: r, objs: map[string][]unstructured.Unstructured{}}
}

func (s *BundleSource) Snap() *k8s.Snapshot { return s.R.Snap }

func (s *BundleSource) Node(name string) *nodeinfo.Info { return s.R.Input.Nodes[name] }

// SSHStatus is how the node's log gather went ("ok" or the error).
func (s *BundleSource) SSHStatus(node string) string {
	for _, n := range s.B.Manifest.Nodes {
		if n.Name == node {
			return n.Logs
		}
	}
	return ""
}

func (s *BundleSource) Objects(resource string) []unstructured.Unstructured {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.objs[resource]; ok {
		return l
	}
	var out []unstructured.Unstructured
	if raw, err := os.ReadFile(s.B.Path("cluster/resources/" + resource + ".yaml")); err == nil {
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if yaml.Unmarshal(raw, &list) == nil {
			for _, it := range list.Items {
				out = append(out, unstructured.Unstructured{Object: it})
			}
		}
	}
	s.objs[resource] = out
	return out
}

func (s *BundleSource) PodLog(ns, pod, container string, previous bool) ([]string, string) {
	name := container
	if previous {
		name += ".previous"
	}
	rel := "cluster/pods/" + ns + "/" + pod + "/" + name + ".log"
	if ls := readLines(s.B.Path(rel)); ls != nil {
		return ls, rel
	}
	// the node's copy (CRI format, rewritten to "<time> <message>")
	for _, n := range s.B.Manifest.Nodes {
		dir := "nodes/" + safe(n.Name) + "/pods"
		ents, _ := os.ReadDir(s.B.Path(dir))
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), ns+"_"+pod+"_") {
				continue
			}
			files, _ := os.ReadDir(s.B.Path(dir + "/" + e.Name() + "/" + container))
			idx := len(files) - 1
			if previous {
				idx--
			}
			if idx < 0 || idx >= len(files) {
				continue
			}
			rel := dir + "/" + e.Name() + "/" + container + "/" + files[idx].Name()
			var out []string
			for _, l := range readLines(s.B.Path(rel)) {
				if t, body := parseCRI(l); !t.IsZero() {
					out = append(out, t.Format("2006-01-02T15:04:05.000000000Z07:00")+" "+body)
				}
			}
			return out, rel
		}
	}
	return nil, ""
}
