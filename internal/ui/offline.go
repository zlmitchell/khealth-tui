package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/gather"
	"github.com/zlmitchell/khealth-tui/internal/helmcheck"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/rca"
)

// Offline is a log bundle opened in the TUI (khealth --analyze b --tui):
// every tab renders what the bundle recorded, the Incidents tab opens
// first, and nothing talks to a cluster. Inspect reads the bundle's object
// dumps, pod logs its collected logs; actions and refresh are off.
type Offline struct {
	Bundle   *gather.Bundle
	Replayed *gather.Replayed
	Timeline *rca.Timeline
	Source   *rca.BundleSource

	idxOnce sync.Once
	idx     map[string]*unstructured.Unstructured // kind/ns/name
	all     []*unstructured.Unstructured
}

// NewOffline builds the App over a bundle.
func NewOffline(cfg config.Config, o *Offline) *App {
	m := o.Bundle.Manifest
	cfg.Actions.Enabled = false
	cfg.SSH.Enabled = false
	cfg.Helm.CheckUpdates = false
	r := o.Replayed
	a := &App{
		cfg:        cfg,
		client:     &k8s.Client{Context: m.Context, Host: m.Server + "  [bundle " + m.Created.Local().Format("2006-01-02 15:04") + "]"},
		offline:    o,
		namespace:  cfg.Namespace,
		snap:       r.Snap,
		nodes:      r.Input.Nodes,
		pending:    map[string]bool{},
		collecting: map[string]string{},
		etcd:       r.Input.Etcd,
		etcdPend:   map[string]bool{},
		s3Reach:    map[string]etcd.S3Check{},
		logSum:     r.Input.Logs,
		helmLatest: map[string]helmcheck.Latest{},
		fp:         newFootprint(),
		sshEnabled: len(r.Input.Nodes) > 0,
		tab:        tabIncidents,
	}
	if a.nodes == nil {
		a.nodes = map[string]*nodeinfo.Info{}
	}
	if a.etcd == nil {
		a.etcd = map[string]*etcd.Probe{}
	}
	if a.logSum == nil {
		a.logSum = map[string]*logs.Summary{}
	}
	a.knownNodes = r.Snap.Nodes
	a.lastRefresh = m.Created
	a.spinner = spinner.New(spinner.WithSpinner(spinner.MiniDot))
	a.filter = textinput.New()
	a.filter.Prompt = "/"
	a.filter.CharLimit = 64
	a.nsInput = textinput.New()
	a.nsInput.Prompt = "namespace> "
	a.nsInput.CharLimit = 64
	a.inc.tl = o.Timeline
	a.inc.src = o.Source
	a.inc.list = rca.Extract(o.Timeline, r.Snap)
	a.inc.hyps = rca.Analyze(o.Source, o.Timeline)
	a.inc.ctx = map[string]*rca.Context{}
	a.recompute()
	return a
}

// clock is "now" for the checks: the gather time of a bundle.
func (a *App) clock() time.Time {
	if a.offline != nil {
		return a.offline.Bundle.Manifest.Created
	}
	return time.Now()
}

// readOnly refuses what a bundle cannot do, with a status line.
func (a *App) readOnly(what string) bool {
	if a.offline == nil {
		return false
	}
	a.setStatus(what + ": not available on a bundle (it is a recording, not a cluster)")
	return true
}

// index loads the bundle's object dumps once, for the inspector.
func (o *Offline) index() {
	o.idxOnce.Do(func() {
		o.idx = map[string]*unstructured.Unstructured{}
		files, _ := filepath.Glob(o.Bundle.Path("cluster/resources/*.yaml"))
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var list struct {
				Items []map[string]any `json:"items"`
			}
			if yaml.Unmarshal(raw, &list) != nil {
				continue
			}
			for _, it := range list.Items {
				u := &unstructured.Unstructured{Object: it}
				o.idx[u.GetKind()+"/"+u.GetNamespace()+"/"+u.GetName()] = u
				o.all = append(o.all, u)
			}
		}
	})
}

// getObject is k8s.Client.GetObject from the bundle.
func (o *Offline) getObject(ref k8s.ObjRef) (*unstructured.Unstructured, error) {
	o.index()
	if u := o.idx[ref.Kind+"/"+ref.Namespace+"/"+ref.Name]; u != nil {
		return u, nil
	}
	return nil, fmt.Errorf("%s %s/%s not found in the bundle (secrets and configmaps keep only their keys; other kinds are dumped only when gathered)", ref.Kind, ref.Namespace, ref.Name)
}

// childrenOf is k8s.Client.ChildrenOf from the bundle.
func (o *Offline) childrenOf(kind, ns string, owner *unstructured.Unstructured) []k8s.ObjRef {
	o.index()
	var out []k8s.ObjRef
	for _, u := range o.all {
		if u.GetKind() != kind || u.GetNamespace() != ns {
			continue
		}
		for _, or := range u.GetOwnerReferences() {
			if or.UID == owner.GetUID() {
				out = append(out, k8s.ObjRef{APIVersion: u.GetAPIVersion(), Kind: u.GetKind(), Namespace: u.GetNamespace(), Name: u.GetName(), Via: "child"})
			}
		}
	}
	return out
}

// offlineInspect is openInspectRef's fetch on a bundle.
func (a *App) offlineInspect(ref k8s.ObjRef, seq int) tea.Cmd {
	o, snap := a.offline, a.snap
	return func() tea.Msg {
		u, err := o.getObject(ref)
		if err != nil {
			return inspectMsg{seq: seq, level: inspectLevel{title: refTitle(ref), err: err.Error()}}
		}
		lvl := levelFromObject(u, snap)
		switch u.GetKind() {
		case "Deployment":
			lvl.refs = append(lvl.refs, o.childrenOf("ReplicaSet", u.GetNamespace(), u)...)
		case "CronJob":
			lvl.refs = append(lvl.refs, o.childrenOf("Job", u.GetNamespace(), u)...)
		}
		return inspectMsg{seq: seq, level: lvl}
	}
}

// offlineLogs feeds the log viewer from the bundle's collected logs.
func (a *App) offlineLogs(ns, pod, container string, previous bool, ch chan logChunk) {
	lines, ref := a.offline.Source.PodLog(ns, pod, container, previous)
	go func() {
		if lines == nil {
			which := "current"
			if previous {
				which = "previous"
			}
			ch <- logChunk{err: fmt.Errorf("the bundle holds no %s log of %s/%s %s (pod logs are gathered for failing, restarting and system pods, or all pods of a --gather-workload)", which, ns, pod, container), done: true}
			return
		}
		ch <- logChunk{lines: append([]string{"# " + ref}, lines...)}
		ch <- logChunk{done: true}
	}()
}
