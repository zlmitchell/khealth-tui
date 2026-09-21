package nodeinfo

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// PSAConfig is the PodSecurity plugin configuration an apiserver admission
// config file carries (kind AdmissionConfiguration, plugin PodSecurity):
// the levels namespaces without pod-security labels get, and the
// namespaces, users and runtime classes the admission skips altogether -
// effectively privileged, whatever their labels say.
type PSAConfig struct {
	Path                 string
	Enforce, Audit, Warn string // "" = privileged (the upstream default)
	ExemptNamespaces     []string
	ExemptUsers          []string
	ExemptRuntimeClasses []string
	External             string // plugin config in a separate file (path:) that was not read
}

// EnforceLevel is the enforce level unlabeled namespaces get.
func (p *PSAConfig) EnforceLevel() string {
	if p.Enforce == "" {
		return "privileged"
	}
	return strings.ToLower(p.Enforce)
}

// Exempt reports whether the namespace is listed in exemptions.namespaces.
func (p *PSAConfig) Exempt(ns string) bool {
	for _, n := range p.ExemptNamespaces {
		if n == ns {
			return true
		}
	}
	return false
}

// ParsePSA reads an AdmissionConfiguration file; nil when the file is
// something else (an audit policy, a sysctl list) or has no PodSecurity
// plugin entry.
func ParsePSA(path, body string) *PSAConfig {
	if !strings.Contains(body, "AdmissionConfiguration") {
		return nil
	}
	var doc struct {
		Kind    string `yaml:"kind"`
		Plugins []struct {
			Name          string `yaml:"name"`
			Path          string `yaml:"path"`
			Configuration struct {
				Defaults struct {
					Enforce string `yaml:"enforce"`
					Audit   string `yaml:"audit"`
					Warn    string `yaml:"warn"`
				} `yaml:"defaults"`
				Exemptions struct {
					Usernames      []string `yaml:"usernames"`
					RuntimeClasses []string `yaml:"runtimeClasses"`
					Namespaces     []string `yaml:"namespaces"`
				} `yaml:"exemptions"`
			} `yaml:"configuration"`
		} `yaml:"plugins"`
	}
	if yaml.Unmarshal([]byte(body), &doc) != nil || doc.Kind != "AdmissionConfiguration" {
		return nil
	}
	for _, p := range doc.Plugins {
		if p.Name != "PodSecurity" {
			continue
		}
		c := p.Configuration
		return &PSAConfig{Path: path, Enforce: c.Defaults.Enforce, Audit: c.Defaults.Audit, Warn: c.Defaults.Warn,
			ExemptNamespaces: c.Exemptions.Namespaces, ExemptUsers: c.Exemptions.Usernames, ExemptRuntimeClasses: c.Exemptions.RuntimeClasses, External: p.Path}
	}
	return nil
}

// EffectivePSA picks the admission config the cluster runs with from the
// files the server nodes' config tier read: the one at the path each
// node's kube-apiserver --admission-control-config-file names (paths, by
// node name), else the only AdmissionConfiguration found. Nil until a
// server node's config tier has been collected.
func EffectivePSA(infos map[string]*Info, paths map[string]string) *PSAConfig {
	var only *PSAConfig
	n := 0
	for name, ni := range infos {
		if ni == nil || ni.Err != nil {
			continue
		}
		for _, p := range ni.PSA {
			if p.Path == paths[name] {
				return p
			}
			if only == nil || only.Path != p.Path {
				n++
			}
			only = p
		}
	}
	if n == 1 {
		return only
	}
	return nil
}
