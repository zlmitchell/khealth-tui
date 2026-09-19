// Package helmcheck looks up the latest available chart versions from Helm
// repositories (index.yaml). Repositories come from the user's own `helm repo
// add` list (repositories.yaml with its credentials), so private repos work,
// plus any under helm.repos in khealth's config; helm's cached index files
// serve as an offline fallback. Only repos the user chose are consulted: an
// aggregator such as Artifact Hub matches by chart name and may not be the
// chart's real origin.
package helmcheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"k8s-health-tui/internal/config"
)

// Latest is the newest known version of a chart.
type Latest struct {
	Version string
	Source  string // repo name
	RepoURL string // chart repository URL usable with helm --repo
	Alias   string // helm CLI repo name when the repo is in repositories.yaml (`helm upgrade alias/chart` reuses its credentials)
	Err     string
}

// Release is what the lookup needs to know about an installed chart. Key is
// echoed back as the result map key.
type Release struct {
	Key     string
	Chart   string
	Repo    string // repository the release was installed from, when recorded (rke2 HelmChart spec.repo)
	Home    string // Chart.yaml origin hints, used to tell same-named charts in different repos apart
	Sources []string
}

// RepoStatus is how a repo's index was last obtained.
type RepoStatus struct {
	Name   string
	State  string // "index" (fetched), "cache" (helm's cached index, repo unreachable), "offline" (unreachable, no cache), "" (not tried yet)
	Detail string
	At     time.Time
}

// reachProbe is how long a TCP connect to the repo host may take before the
// host is treated as offline; offlineBackoff is how long that verdict holds.
const (
	reachProbe     = 2 * time.Second
	offlineBackoff = 10 * time.Minute
)

// indexEntry is one chart version in a repo index with its origin hints.
type indexEntry struct {
	Version string
	Home    string
	Sources []string
}

// Checker caches repo indexes.
type Checker struct {
	cfg      config.Helm
	client   *http.Client
	repos    []Repo
	cacheDir string // helm's <name>-index.yaml cache, used when a fetch fails
	loadErr  string

	mu      sync.Mutex
	indexes map[string]map[string][]indexEntry // repo -> chart -> versions
	extra   map[string]Repo                    // repos recorded on releases (spec.repo), by URL
	fetched map[string]time.Time
	status  map[string]RepoStatus
}

// New creates a checker. Repos listed under helm.repos take precedence over a
// same-named entry in the user's helm repositories.yaml.
func New(cfg config.Helm) *Checker {
	c := &Checker{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}, indexes: map[string]map[string][]indexEntry{}, fetched: map[string]time.Time{}, extra: map[string]Repo{}, status: map[string]RepoStatus{}}
	seen := map[string]bool{}
	for _, name := range sortedNames(cfg.Repos) {
		c.repos = append(c.repos, Repo{Name: name, URL: cfg.Repos[name]})
		seen[name] = true
	}
	if cfg.UseHelmRepos {
		c.cacheDir = HelmCacheDir()
		repos, err := LoadHelmRepos(HelmRepositoriesFile())
		if err != nil {
			c.loadErr = err.Error()
		}
		for _, r := range repos {
			if !seen[r.Name] {
				c.repos = append(c.repos, r)
				seen[r.Name] = true
			}
		}
	}
	return c
}

// Repos lists the repositories the checker consults, config first.
func (c *Checker) Repos() []Repo { return c.repos }

// LoadErr describes a problem reading the helm CLI's repositories.yaml ("" when fine).
func (c *Checker) LoadErr() string { return c.loadErr }

// Status reports, per repo (config and helm repos first, then repos recorded
// on releases), whether its index came from the network, helm's cache, or
// could not be obtained.
func (c *Checker) Status() []RepoStatus {
	repos := c.allRepos()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]RepoStatus, 0, len(repos))
	for _, r := range repos {
		st := c.status[r.Name]
		st.Name = r.Name
		out = append(out, st)
	}
	return out
}

func sortedNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Lookup returns the latest version for each release, keyed by Release.Key.
// A release whose install repo is recorded is checked against that repo
// only; otherwise the user's repos are searched and, when the chart name
// exists in more than one, the index entry's home/sources must match the
// release's Chart.yaml so a same-named chart from another publisher is never
// offered.
func (c *Checker) Lookup(ctx context.Context, rels []Release) map[string]Latest {
	out := map[string]Latest{}
	for _, r := range rels {
		if u := repoURL(r.Repo); u != "" {
			c.mu.Lock()
			if _, ok := c.extra[u]; !ok {
				c.extra[u] = Repo{Name: u, URL: u}
			}
			c.mu.Unlock()
		}
	}
	c.refreshIndexes(ctx)
	for _, r := range rels {
		if l, ok := c.forRelease(r); ok {
			out[r.Key] = l
		}
	}
	return out
}

// repoURL returns r when it is an http(s) chart repository URL, "" otherwise
// (rke2 HelmChart spec.repo may be blank when spec.chart is a tgz URL).
func repoURL(r string) string {
	r = strings.TrimSpace(r)
	if strings.HasPrefix(r, "http://") || strings.HasPrefix(r, "https://") {
		return strings.TrimSuffix(r, "/")
	}
	return ""
}

func (c *Checker) allRepos() []Repo {
	c.mu.Lock()
	defer c.mu.Unlock()
	repos := append([]Repo{}, c.repos...)
	for _, u := range sortedKeys(c.extra) {
		repos = append(repos, c.extra[u])
	}
	return repos
}

func sortedKeys(m map[string]Repo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (c *Checker) refreshIndexes(ctx context.Context) {
	for _, repo := range c.allRepos() {
		c.mu.Lock()
		stale := time.Since(c.fetched[repo.Name]) > time.Hour
		st := c.status[repo.Name]
		c.mu.Unlock()
		if !stale {
			continue
		}
		// an unreachable host is not retried on every refresh
		if st.State == "offline" || st.State == "cache" {
			if time.Since(st.At) < offlineBackoff {
				continue
			}
		}
		var body []byte
		var err error
		// cheap connect probe first so an offline machine never waits out the
		// HTTP timeout per repo on every refresh
		if err = reachable(ctx, repo.URL); err == nil {
			body, err = c.fetchIndex(ctx, repo)
		}
		state, detail := "index", ""
		if err != nil {
			// unreachable from here: fall back to what `helm repo update` cached
			state, detail = "offline", err.Error()
			body = nil
			if c.cacheDir != "" && repo.FromHelm {
				if cached, cerr := os.ReadFile(filepath.Join(c.cacheDir, repo.Name+"-index.yaml")); cerr == nil {
					body, state = cached, "cache"
				}
			}
		}
		var m map[string][]indexEntry
		if body != nil {
			if m, err = parseIndex(body); err != nil {
				state, detail, m = "offline", "bad index.yaml: "+err.Error(), nil
			}
		}
		c.mu.Lock()
		c.status[repo.Name] = RepoStatus{Name: repo.Name, State: state, Detail: detail, At: time.Now()}
		if m != nil {
			c.indexes[repo.Name] = m
			if state == "index" {
				c.fetched[repo.Name] = time.Now()
			}
		}
		c.mu.Unlock()
	}
}

// reachable makes a short TCP connection to the repo host (or the proxy that
// would carry the request) to tell "offline" from "slow" before any HTTP.
func reachable(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	target := u
	if p, _ := http.ProxyFromEnvironment(&http.Request{URL: u}); p != nil {
		target = p
	}
	host, port := target.Hostname(), target.Port()
	if port == "" {
		port = "443"
		if target.Scheme == "http" {
			port = "80"
		}
	}
	dctx, cancel := context.WithTimeout(ctx, reachProbe)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("unreachable: %s", host)
	}
	conn.Close()
	return nil
}

// fetchIndex downloads <repo>/index.yaml with the repo's credentials.
func (c *Checker) fetchIndex(ctx context.Context, repo Repo) ([]byte, error) {
	u := strings.TrimSuffix(repo.URL, "/") + "/index.yaml"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if repo.Username != "" || repo.Password != "" {
		req.SetBasicAuth(repo.Username, repo.Password)
	}
	resp, err := repo.httpClient(c.cfg.Timeout, c.client).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// parseIndex reduces a repo index.yaml to chart -> versions (+ origin hints).
func parseIndex(body []byte) (map[string][]indexEntry, error) {
	var idx struct {
		Entries map[string][]struct {
			Version string   `yaml:"version"`
			Home    string   `yaml:"home"`
			Sources []string `yaml:"sources"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(body, &idx); err != nil {
		return nil, err
	}
	m := map[string][]indexEntry{}
	for chart, entries := range idx.Entries {
		for _, e := range entries {
			m[chart] = append(m[chart], indexEntry{Version: e.Version, Home: e.Home, Sources: e.Sources})
		}
	}
	return m, nil
}

// candidate is the best stable version of a chart in one repo.
type candidate struct {
	repo   Repo
	best   string
	origin bool // the index entry's home/sources match the release's Chart.yaml
}

func (c *Checker) forRelease(r Release) (Latest, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// recorded install repo: the authoritative source, nothing else is consulted
	if u := repoURL(r.Repo); u != "" {
		repo := c.extra[u]
		if _, fetched := c.indexes[u]; !fetched {
			return Latest{Source: u, RepoURL: u, Err: "offline: " + u}, true
		}
		cand, ok := bestIn(repo, c.indexes[u], r)
		if !ok {
			return Latest{Source: u, RepoURL: u, Err: "chart not in " + u}, true
		}
		return toLatest(cand), true
	}
	var cands []candidate
	for _, repo := range c.repos {
		if cand, ok := bestIn(repo, c.indexes[repo.Name], r); ok {
			cands = append(cands, cand)
		}
	}
	if len(cands) == 0 {
		return Latest{}, false
	}
	// several repos carry this chart name: only trust the ones whose Chart.yaml
	// origin matches; if none does, refuse to guess
	if len(cands) > 1 {
		var matched []candidate
		var names []string
		for _, cand := range cands {
			names = append(names, cand.repo.Name)
			if cand.origin {
				matched = append(matched, cand)
			}
		}
		if len(matched) == 0 {
			return Latest{Err: "ambiguous: " + strings.Join(names, ", ") + " all have a " + r.Chart + " chart with a different origin"}, true
		}
		cands = matched
	}
	best := cands[0]
	for _, cand := range cands[1:] {
		if CompareVersions(cand.best, best.best) > 0 {
			best = cand
		}
	}
	return toLatest(best), true
}

func toLatest(cand candidate) Latest {
	l := Latest{Version: cand.best, Source: cand.repo.Name, RepoURL: cand.repo.URL}
	if cand.repo.FromHelm {
		l.Alias = cand.repo.Name
	}
	return l
}

// bestIn picks the highest stable version of r.Chart in one repo index.
func bestIn(repo Repo, idx map[string][]indexEntry, r Release) (candidate, bool) {
	cand := candidate{repo: repo}
	found := false
	for _, e := range idx[r.Chart] {
		if IsPrerelease(e.Version) {
			continue
		}
		if sameOrigin(e, r) {
			cand.origin = true
		}
		if !found || CompareVersions(e.Version, cand.best) > 0 {
			cand.best = e.Version
			found = true
		}
	}
	return cand, found
}

// sameOrigin reports whether an index entry and the installed chart point at
// the same home page or source repository.
func sameOrigin(e indexEntry, r Release) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
		return strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	}
	if r.Home != "" && e.Home != "" && norm(r.Home) == norm(e.Home) {
		return true
	}
	for _, a := range r.Sources {
		for _, b := range e.Sources {
			if a != "" && norm(a) == norm(b) {
				return true
			}
		}
	}
	return false
}

// IsPrerelease reports whether a semver string has a prerelease suffix.
func IsPrerelease(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	return strings.Contains(v, "-")
}

// CompareVersions compares two semver-ish strings (-1, 0, 1).
func CompareVersions(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	// a release beats a prerelease of the same core version
	ap, bp := IsPrerelease(a), IsPrerelease(b)
	switch {
	case ap && !bp:
		return -1
	case !ap && bp:
		return 1
	}
	return strings.Compare(stripMeta(a), stripMeta(b))
}

func stripMeta(v string) string {
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	return v
}

func parts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		n, _ := strconv.Atoi(strings.TrimFunc(p, func(r rune) bool { return r < '0' || r > '9' }))
		out[i] = n
	}
	return out
}
