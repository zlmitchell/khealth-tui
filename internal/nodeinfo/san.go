package nodeinfo

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLList reads a key from an rke2/k3s config file as a list: a block or
// flow sequence, or a scalar split on commas the way rke2 splits its slice
// flags. "key+" entries (the config.yaml.d append syntax) follow the key's
// own values. A file yaml.v3 rejects but rke2 loads anyway - a duplicated
// key (the last one wins there), tab indentation - is read line by line
// instead, so a hand-edited config.yaml never shows up as "no tls-san".
func YAMLList(body, key string) []string {
	var m map[string]any
	if yaml.Unmarshal([]byte(body), &m) != nil {
		return scanList(body, key)
	}
	var out []string
	for _, k := range []string{key, key + "+"} {
		switch v := m[k].(type) {
		case string:
			out = append(out, splitCommas(v)...)
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// scanList is YAMLList for a file yaml.v3 cannot load: top-level "key:"
// lines with a block list, a flow list or a scalar; the last "key:" wins
// and every "key+:" appends.
func scanList(body, key string) []string {
	var base, extra []string
	var target *[]string
	inList := false
	for _, raw := range strings.Split(body, "\n") {
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if inList && strings.HasPrefix(t, "-") {
			if v := yamlScalar(strings.TrimPrefix(t, "-")); v != "" {
				*target = append(*target, v)
			}
			continue
		}
		inList = false
		if strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t") {
			continue // nested under another key
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case key:
			base = nil
			target = &base
		case key + "+":
			target = &extra
		default:
			continue
		}
		v = yamlScalar(v)
		switch {
		case v == "":
			inList = true
		case strings.HasPrefix(v, "["):
			for _, e := range strings.Split(strings.Trim(v, "[]"), ",") {
				if e = yamlScalar(e); e != "" {
					*target = append(*target, e)
				}
			}
		default:
			*target = append(*target, splitCommas(v)...)
		}
	}
	return append(base, extra...)
}

// yamlScalar trims a scalar's whitespace, trailing comment and quotes.
func yamlScalar(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		s = s[1 : len(s)-1]
	}
	return s
}

// splitCommas splits an rke2 slice value given as one scalar ("a,b").
func splitCommas(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// CertSANs parses a PEM certificate's subjectAltName entries.
func CertSANs(pemText string) (dns, ips []string, err error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, nil, errors.New("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	return c.DNSNames, ips, nil
}

// InClusterSAN reports SANs only meaningful inside the cluster: the
// kubernetes service names, loopback and the apiserver ClusterIP (from the
// service CIDRs, or the rke2/k3s and kubeadm defaults when unset).
func InClusterSAN(s string, serviceCIDRs []string) bool {
	l := strings.ToLower(s)
	if l == "localhost" || l == "kubernetes" || strings.HasPrefix(l, "kubernetes.default") || strings.Contains(l, ".svc") {
		return true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	if len(serviceCIDRs) == 0 {
		serviceCIDRs = []string{"10.43.0.0/16", "10.96.0.0/12"}
	}
	for _, c := range serviceCIDRs {
		for _, one := range strings.Split(c, ",") {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(one)); err == nil && n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// MissingSANs returns the tls-san entries that the certificate does not carry.
func MissingSANs(tlsSAN, certSANs []string) []string {
	have := map[string]bool{}
	for _, s := range certSANs {
		have[strings.ToLower(s)] = true
	}
	var out []string
	for _, s := range tlsSAN {
		if !have[strings.ToLower(s)] {
			out = append(out, s)
		}
	}
	return out
}
