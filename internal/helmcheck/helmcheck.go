// Package helmcheck looks up the latest available chart versions from
// configured Helm repositories (index.yaml) or Artifact Hub. It is opt-in
// because it needs outbound internet/registry access.
package helmcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	Source  string // repo name or "artifacthub"
	RepoURL string // chart repository URL usable with helm --repo
	Err     string
}

// Checker caches repo indexes and Artifact Hub lookups.
type Checker struct {
	cfg    config.Helm
	client *http.Client

	mu      sync.Mutex
	indexes map[string]map[string][]string // repo -> chart -> versions
	fetched map[string]time.Time
	hub     map[string]Latest
	hubAt   map[string]time.Time
}

// New creates a checker.
func New(cfg config.Helm) *Checker {
	return &Checker{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}, indexes: map[string]map[string][]string{}, fetched: map[string]time.Time{}, hub: map[string]Latest{}, hubAt: map[string]time.Time{}}
}

// Lookup returns the latest versions for the given chart names.
func (c *Checker) Lookup(ctx context.Context, charts []string) map[string]Latest {
	out := map[string]Latest{}
	c.refreshIndexes(ctx)
	var missing []string
	for _, ch := range charts {
		if l, ok := c.fromIndexes(ch); ok {
			out[ch] = l
			continue
		}
		missing = append(missing, ch)
	}
	if c.cfg.ArtifactHub && len(missing) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		var mu sync.Mutex
		for _, ch := range missing {
			wg.Add(1)
			go func(ch string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				l := c.artifactHub(ctx, ch)
				mu.Lock()
				out[ch] = l
				mu.Unlock()
			}(ch)
		}
		wg.Wait()
	}
	return out
}

func (c *Checker) refreshIndexes(ctx context.Context) {
	for name, repo := range c.cfg.Repos {
		c.mu.Lock()
		stale := time.Since(c.fetched[name]) > time.Hour
		c.mu.Unlock()
		if !stale {
			continue
		}
		u := strings.TrimSuffix(repo, "/") + "/index.yaml"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		var idx struct {
			Entries map[string][]struct {
				Version string `yaml:"version"`
			} `yaml:"entries"`
		}
		if err := yaml.Unmarshal(body, &idx); err != nil {
			continue
		}
		m := map[string][]string{}
		for chart, entries := range idx.Entries {
			for _, e := range entries {
				m[chart] = append(m[chart], e.Version)
			}
		}
		c.mu.Lock()
		c.indexes[name] = m
		c.fetched[name] = time.Now()
		c.mu.Unlock()
	}
}

func (c *Checker) fromIndexes(chart string) (Latest, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	best := Latest{}
	found := false
	for repo, m := range c.indexes {
		for _, v := range m[chart] {
			if IsPrerelease(v) {
				continue
			}
			if !found || CompareVersions(v, best.Version) > 0 {
				best = Latest{Version: v, Source: repo, RepoURL: c.cfg.Repos[repo]}
				found = true
			}
		}
	}
	return best, found
}

func (c *Checker) artifactHub(ctx context.Context, chart string) Latest {
	c.mu.Lock()
	if l, ok := c.hub[chart]; ok && time.Since(c.hubAt[chart]) < time.Hour {
		c.mu.Unlock()
		return l
	}
	c.mu.Unlock()

	u := "https://artifacthub.io/api/v1/packages/search?kind=0&limit=10&ts_query_web=" + url.QueryEscape(chart)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Latest{Err: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return Latest{Err: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Latest{Err: fmt.Sprintf("artifacthub HTTP %d", resp.StatusCode)}
	}
	var doc struct {
		Packages []struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			Repository struct {
				Name     string `json:"name"`
				URL      string `json:"url"`
				Official bool   `json:"official"`
			} `json:"repository"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Latest{Err: err.Error()}
	}
	best := Latest{Err: "not found on artifacthub"}
	found := false
	for _, p := range doc.Packages {
		if p.Name != chart {
			continue
		}
		if !found || (p.Repository.Official && !strings.HasSuffix(best.Source, "*")) || CompareVersions(p.Version, best.Version) > 0 {
			best = Latest{Version: p.Version, Source: "artifacthub/" + p.Repository.Name, RepoURL: p.Repository.URL}
			if p.Repository.Official {
				best.Source += "*"
			}
			found = true
		}
	}
	c.mu.Lock()
	c.hub[chart] = best
	c.hubAt[chart] = time.Now()
	c.mu.Unlock()
	return best
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
