package helmcheck

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"k8s-health-tui/internal/config"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1}, {"v2.0.0", "1.9.9", 1}, {"1.2.3", "1.2.3", 0},
		{"1.2.3-rc1", "1.2.3", -1}, {"1.10.0", "1.9.0", 1}, {"15.0.1+build", "15.0.1", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	if !IsPrerelease("1.0.0-alpha.1") || IsPrerelease("1.0.0+meta") {
		t.Errorf("prerelease detection")
	}
}

func TestParseHelmRepos(t *testing.T) {
	repos, err := parseHelmRepos([]byte(`apiVersion: ""
repositories:
- name: harbor
  url: https://harbor.example.com/chartrepo/lib
  username: bob
  password: s3cret
  caFile: /etc/ssl/harbor-ca.pem
  insecure_skip_tls_verify: true
- name: bitnami
  url: https://charts.bitnami.com/bitnami
- name: broken
  url: ""
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || repos[0].Name != "harbor" || repos[0].Username != "bob" || repos[0].Password != "s3cret" || repos[0].CAFile != "/etc/ssl/harbor-ca.pem" || !repos[0].Insecure || !repos[0].FromHelm {
		t.Fatalf("unexpected repos: %+v", repos)
	}
}

func TestForReleaseUsesOriginNotJustName(t *testing.T) {
	c := New(config.Helm{Timeout: time.Second})
	c.repos = []Repo{{Name: "mine", URL: "https://a"}, {Name: "harbor", URL: "https://b", FromHelm: true}}
	c.indexes = map[string]map[string][]indexEntry{
		"mine":                    {"nginx": {{Version: "9.0.0", Home: "https://other.example"}}, "redis": {{Version: "3.0.0"}}},
		"harbor":                  {"nginx": {{Version: "1.1.0", Sources: []string{"https://github.com/acme/nginx-chart"}}, {Version: "1.2.0-rc1"}}},
		"https://charts.internal": {"nginx": {{Version: "1.0.5"}}},
	}
	c.extra["https://charts.internal"] = Repo{Name: "https://charts.internal", URL: "https://charts.internal"}

	// same chart name in two repos: the one whose sources match the installed Chart.yaml wins, even at a lower version
	l, ok := c.forRelease(Release{Chart: "nginx", Sources: []string{"https://github.com/acme/nginx-chart.git"}})
	if !ok || l.Version != "1.1.0" || l.Source != "harbor" || l.Alias != "harbor" {
		t.Fatalf("origin match should win: %+v", l)
	}
	// no origin evidence matches either repo: refuse to guess
	l, ok = c.forRelease(Release{Chart: "nginx", Home: "https://nowhere"})
	if !ok || l.Version != "" || !strings.Contains(l.Err, "ambiguous") {
		t.Fatalf("ambiguous chart should carry an error, got %+v", l)
	}
	// only one repo has it: fine without origin evidence
	l, ok = c.forRelease(Release{Chart: "redis"})
	if !ok || l.Version != "3.0.0" || l.Source != "mine" || l.Alias != "" {
		t.Fatalf("unique repo: %+v", l)
	}
	// recorded install repo (rke2 HelmChart spec.repo) is authoritative
	l, ok = c.forRelease(Release{Chart: "nginx", Repo: "https://charts.internal/"})
	if !ok || l.Version != "1.0.5" || l.RepoURL != "https://charts.internal" || l.Alias != "" {
		t.Fatalf("recorded repo: %+v", l)
	}
	l, _ = c.forRelease(Release{Chart: "nginx", Repo: "https://never-fetched"})
	if l.Version != "" || !strings.Contains(l.Err, "offline") {
		t.Fatalf("unfetched recorded repo: %+v", l)
	}
	if _, ok := c.forRelease(Release{Chart: "nope"}); ok {
		t.Fatalf("unknown chart should not be found")
	}
}

func TestNoHelmCLIIsFine(t *testing.T) {
	// no helm installed / never ran `helm repo add`: no file, no error, no repos
	t.Setenv("HELM_REPOSITORY_CONFIG", t.TempDir()+"/nope/repositories.yaml")
	t.Setenv("HELM_REPOSITORY_CACHE", t.TempDir()+"/nope/cache")
	repos, err := LoadHelmRepos(HelmRepositoriesFile())
	if err != nil || len(repos) != 0 {
		t.Fatalf("missing file should be silent: %v %v", repos, err)
	}
	c := New(config.Helm{UseHelmRepos: true, Repos: map[string]string{"cfg": "https://x"}, Timeout: time.Second})
	if c.LoadErr() != "" || len(c.Repos()) != 1 || c.Repos()[0].Name != "cfg" {
		t.Fatalf("checker should carry on with config repos only: err=%q repos=%+v", c.LoadErr(), c.Repos())
	}
	// unreadable/corrupt file is reported, not fatal
	bad := t.TempDir() + "/repositories.yaml"
	os.WriteFile(bad, []byte("repositories: [not: valid"), 0o600)
	t.Setenv("HELM_REPOSITORY_CONFIG", bad)
	c = New(config.Helm{UseHelmRepos: true, Timeout: time.Second})
	if c.LoadErr() == "" || len(c.Repos()) != 0 {
		t.Fatalf("corrupt file should surface as LoadErr: err=%q repos=%+v", c.LoadErr(), c.Repos())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// no repos: lookup returns nothing and does not panic
	if got := c.Lookup(ctx, []Release{{Key: "x", Chart: "nginx"}}); len(got) != 0 {
		t.Fatalf("expected no results, got %+v", got)
	}
}

func TestOfflineRepoIsProbedOnceThenBackedOff(t *testing.T) {
	// a closed port: the connect probe fails fast, the HTTP fetch is never attempted
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	cache := t.TempDir()
	os.WriteFile(cache+"/harbor-index.yaml", []byte("entries:\n  nginx:\n  - version: 1.0.0\n"), 0o600)
	c := New(config.Helm{Timeout: time.Second})
	c.repos = []Repo{{Name: "harbor", URL: "http://" + addr, FromHelm: true}, {Name: "cfg", URL: "http://" + addr}}
	c.cacheDir = cache
	ctx := context.Background()

	start := time.Now()
	got := c.Lookup(ctx, []Release{{Key: "r", Chart: "nginx"}})
	if time.Since(start) > reachProbe*2 {
		t.Fatalf("offline lookup took %s", time.Since(start))
	}
	if got["r"].Version != "1.0.0" || got["r"].Source != "harbor" {
		t.Fatalf("helm cache should answer while offline: %+v", got)
	}
	st := map[string]RepoStatus{}
	for _, s := range c.Status() {
		st[s.Name] = s
	}
	if st["harbor"].State != "cache" || st["cfg"].State != "offline" {
		t.Fatalf("status: %+v", st)
	}
	// within the backoff the hosts are not probed again
	c.mu.Lock()
	first := c.status["cfg"].At
	c.mu.Unlock()
	c.Lookup(ctx, []Release{{Key: "r", Chart: "nginx"}})
	c.mu.Lock()
	again := c.status["cfg"].At
	c.mu.Unlock()
	if !again.Equal(first) {
		t.Fatalf("offline repo was re-probed inside the backoff")
	}
}
