package helmcheck

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// Repo is a chart repository to look up index.yaml from: either configured
// under helm.repos in khealth's config, or one the user already added with
// `helm repo add` (repositories.yaml, including its credentials and TLS
// options, so private repos work without duplicating secrets).
type Repo struct {
	Name     string
	URL      string
	Username string
	Password string
	CAFile   string
	CertFile string
	KeyFile  string
	Insecure bool
	FromHelm bool // defined in the helm CLI's repositories.yaml; `helm upgrade name/chart` reuses its credentials
}

// HelmRepositoriesFile returns the helm CLI's repositories.yaml path,
// honoring the same environment variables helm does.
func HelmRepositoriesFile() string {
	if v := os.Getenv("HELM_REPOSITORY_CONFIG"); v != "" {
		return v
	}
	if v := os.Getenv("HELM_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "repositories.yaml")
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "helm", "repositories.yaml")
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, "helm", "repositories.yaml")
		}
	case "darwin":
		return filepath.Join(home, "Library", "Preferences", "helm", "repositories.yaml")
	}
	return filepath.Join(home, ".config", "helm", "repositories.yaml")
}

// HelmCacheDir returns where `helm repo update` stores <name>-index.yaml.
func HelmCacheDir() string {
	if v := os.Getenv("HELM_REPOSITORY_CACHE"); v != "" {
		return v
	}
	if v := os.Getenv("HELM_CACHE_HOME"); v != "" {
		return filepath.Join(v, "repository")
	}
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, "helm", "repository")
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		if v := os.Getenv("TEMP"); v != "" {
			return filepath.Join(v, "helm", "repository")
		}
	case "darwin":
		return filepath.Join(home, "Library", "Caches", "helm", "repository")
	}
	return filepath.Join(home, ".cache", "helm", "repository")
}

// LoadHelmRepos parses the helm CLI's repositories.yaml. A missing file is
// not an error (no repos added yet).
func LoadHelmRepos(path string) ([]Repo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseHelmRepos(b)
}

func parseHelmRepos(b []byte) ([]Repo, error) {
	var f struct {
		Repositories []struct {
			Name     string `yaml:"name"`
			URL      string `yaml:"url"`
			Username string `yaml:"username"`
			Password string `yaml:"password"`
			CAFile   string `yaml:"caFile"`
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
			Insecure bool   `yaml:"insecure_skip_tls_verify"`
		} `yaml:"repositories"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	var out []Repo
	for _, r := range f.Repositories {
		if r.Name == "" || r.URL == "" {
			continue
		}
		out = append(out, Repo{Name: r.Name, URL: r.URL, Username: r.Username, Password: r.Password, CAFile: r.CAFile, CertFile: r.CertFile, KeyFile: r.KeyFile, Insecure: r.Insecure, FromHelm: true})
	}
	return out, nil
}

// httpClient builds a client honoring the repo's TLS options; the shared
// default client when it has none.
func (r Repo) httpClient(timeout time.Duration, def *http.Client) *http.Client {
	if r.CAFile == "" && r.CertFile == "" && r.KeyFile == "" && !r.Insecure {
		return def
	}
	tc := &tls.Config{InsecureSkipVerify: r.Insecure} //nolint:gosec // mirrors helm's insecure_skip_tls_verify
	if r.CAFile != "" {
		if pem, err := os.ReadFile(r.CAFile); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pem)
			tc.RootCAs = pool
		}
	}
	if r.CertFile != "" && r.KeyFile != "" {
		if cert, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile); err == nil {
			tc.Certificates = []tls.Certificate{cert}
		}
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}}
}
