package gather

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zlmitchell/khealth-tui/internal/checks"
	"github.com/zlmitchell/khealth-tui/internal/config"
	"github.com/zlmitchell/khealth-tui/internal/etcd"
	"github.com/zlmitchell/khealth-tui/internal/export"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/logs"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

// Bundle is an opened log bundle: a .tar.gz unpacked into a temporary
// directory, or a directory someone already unpacked.
type Bundle struct {
	Dir      string // the bundle's top directory (manifest.json)
	Manifest Manifest
	tmp      string
}

// Open reads the bundle at path. Close removes what Open unpacked.
func Open(path string) (*Bundle, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	b := &Bundle{}
	dir := path
	if !st.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b.tmp, err = os.MkdirTemp("", "khealth-analyze-")
		if err != nil {
			return nil, err
		}
		if _, _, err := extract(f, b.tmp, 1<<40); err != nil {
			b.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		dir = b.tmp
	}
	b.Dir, err = findRoot(dir)
	if err != nil {
		b.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	raw, err := os.ReadFile(filepath.Join(b.Dir, "manifest.json"))
	if err == nil {
		err = json.Unmarshal(raw, &b.Manifest)
	}
	if err != nil {
		b.Close()
		return nil, fmt.Errorf("%s: manifest.json: %w", path, err)
	}
	if b.Manifest.Format > FormatVersion {
		b.Close()
		return nil, fmt.Errorf("%s: bundle format %d is newer than this khealth reads (%d): update khealth", path, b.Manifest.Format, FormatVersion)
	}
	return b, nil
}

// findRoot is dir, or the one directory under it, that holds manifest.json.
func findRoot(dir string) (string, error) {
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
		return dir, nil
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, e.Name(), "manifest.json")); err == nil {
				return filepath.Join(dir, e.Name()), nil
			}
		}
	}
	return "", errors.New("not a khealth bundle (no manifest.json)")
}

// Close removes the unpacked copy.
func (b *Bundle) Close() {
	if b.tmp != "" {
		os.RemoveAll(b.tmp)
	}
}

// Path is a bundle path (forward slashes) on disk.
func (b *Bundle) Path(name string) string { return filepath.Join(b.Dir, filepath.FromSlash(name)) }

// Replayed is what the checks saw when the bundle was gathered, rebuilt
// from it.
type Replayed struct {
	Snap     *k8s.Snapshot
	Input    checks.Input
	Findings []checks.Finding
	// AtGather are the findings report.json recorded when the bundle was
	// written; Findings should match them unless the checks changed since.
	AtGather []export.Finding
	Notes    []string
}

// Replay rebuilds the checks' input from the snapshot and the raw probe
// output and evaluates it again, as of the moment the bundle was gathered.
// cfg supplies the thresholds; the cluster itself is never contacted.
func (b *Bundle) Replay(cfg config.Config) (*Replayed, error) {
	now := b.Manifest.Created
	r := &Replayed{Snap: &k8s.Snapshot{}}
	if raw, err := os.ReadFile(b.Path("snapshot.json")); err != nil {
		r.Notes = append(r.Notes, "no snapshot.json: API findings are missing")
	} else if err := json.Unmarshal(raw, r.Snap); err != nil {
		return nil, fmt.Errorf("snapshot.json: %w", err)
	}
	in := checks.Input{
		Snap: r.Snap, Nodes: map[string]*nodeinfo.Info{}, Etcd: map[string]*etcd.Probe{}, Logs: map[string]*logs.Summary{},
		Cfg: cfg, Now: now, APIServer: b.Manifest.Server,
	}
	ents, _ := os.ReadDir(b.Path("nodes"))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := "nodes/" + e.Name() + "/probe/"
		if out, err := os.ReadFile(b.Path(dir + "node.txt")); err == nil {
			m := b.probeMeta(dir+"node.meta.json", e.Name())
			info := nodeinfo.Parse(m.Node, m.Host, string(out), m.Started)
			info.HostKey = m.HostKey
			if !m.Finished.IsZero() {
				info.Collected = m.Finished
			}
			in.Nodes[m.Node] = info
			if ls := info.ClassifyLogs(now); ls != nil {
				in.Logs[m.Node] = ls
			}
		}
		if out, err := os.ReadFile(b.Path(dir + "etcd.txt")); err == nil {
			m := b.probeMeta(dir+"etcd.meta.json", e.Name())
			in.Etcd[m.Node] = etcd.Parse(m.Node, string(out))
		}
	}
	in.SSHEnabled = len(in.Nodes) > 0
	r.Input = in
	r.Findings = checks.Evaluate(in)
	if raw, err := os.ReadFile(b.Path("report.json")); err == nil {
		var rep export.Report
		if json.Unmarshal(raw, &rep) == nil {
			r.AtGather = rep.Findings
		}
	}
	return r, nil
}

// probeMeta reads a probe's metadata; bundles without it (or a damaged
// file) fall back to the directory name and a zero start time, which only
// loses the clock-skew check.
func (b *Bundle) probeMeta(name, dirName string) ProbeMeta {
	m := ProbeMeta{Node: dirName}
	if raw, err := os.ReadFile(b.Path(name)); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	if m.Node == "" {
		m.Node = dirName
	}
	return m
}

// Diff compares the replayed findings with the ones recorded at gather
// time, by severity, area, object and message: what only one side has.
func (r *Replayed) Diff() (onlyNow, onlyThen []string) {
	now := map[string]bool{}
	for _, f := range r.Findings {
		now[findingKey(f.Severity.String(), f.Area, f.Object, f.Message)] = true
	}
	then := map[string]bool{}
	for _, f := range r.AtGather {
		then[findingKey(f.Severity, f.Area, f.Object, f.Message)] = true
	}
	for k := range now {
		if !then[k] {
			onlyNow = append(onlyNow, k)
		}
	}
	for k := range then {
		if !now[k] {
			onlyThen = append(onlyThen, k)
		}
	}
	sort.Strings(onlyNow)
	sort.Strings(onlyThen)
	return onlyNow, onlyThen
}

func findingKey(sev, area, object, msg string) string {
	return strings.ToUpper(sev) + " " + area + " " + object + ": " + msg
}
