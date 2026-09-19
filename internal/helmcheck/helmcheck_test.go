package helmcheck

import (
	"context"
	"os"
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

func TestLatestPrefersConfigRepoAndCarriesAlias(t *testing.T) {
	c := &Checker{repos: []Repo{{Name: "mine", URL: "https://a"}, {Name: "harbor", URL: "https://b", FromHelm: true}}, indexes: map[string]map[string][]string{
		"mine":   {"nginx": {"1.0.0", "1.2.0-rc1"}},
		"harbor": {"nginx": {"1.1.0"}, "redis": {"3.0.0"}},
	}}
	l, ok := c.fromIndexes("nginx")
	if !ok || l.Version != "1.1.0" || l.Source != "harbor" || l.Alias != "harbor" {
		t.Fatalf("highest stable across repos with alias for helm repos: %+v", l)
	}
	l, _ = c.fromIndexes("redis")
	if l.Alias != "harbor" || l.RepoURL != "https://b" {
		t.Fatalf("alias/url: %+v", l)
	}
	if _, ok := c.fromIndexes("nope"); ok {
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
	// no repos, artifact hub off: lookup returns nothing and does not panic
	if got := c.Lookup(ctx, []string{"nginx"}); len(got) != 0 {
		t.Fatalf("expected no results, got %+v", got)
	}
}
