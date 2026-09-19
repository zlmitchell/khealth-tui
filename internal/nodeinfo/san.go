package nodeinfo

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLList reads a key from an rke2/k3s config file as a list (a scalar
// counts as a one-element list).
func YAMLList(body, key string) []string {
	var m map[string]any
	if yaml.Unmarshal([]byte(body), &m) != nil {
		return nil
	}
	var out []string
	switch v := m[key].(type) {
	case string:
		out = append(out, v)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
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
