package nodeinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestYAMLList(t *testing.T) {
	cfg := "tls-san:\n  - a.example.com\n  - 10.0.0.100\n  - 7\nservice-cidr: 10.43.0.0/16\ntoken: x\nempty:\n"
	if got := YAMLList(cfg, "tls-san"); strings.Join(got, ",") != "a.example.com,10.0.0.100" {
		t.Errorf("list: %v", got)
	}
	if got := YAMLList(cfg, "service-cidr"); strings.Join(got, ",") != "10.43.0.0/16" {
		t.Errorf("scalar: %v", got)
	}
	if got := YAMLList(cfg, "missing"); got != nil {
		t.Errorf("missing key: %v", got)
	}
	if got := YAMLList(cfg, "empty"); got != nil {
		t.Errorf("null value: %v", got)
	}
	if got := YAMLList("tls-san: [", "tls-san"); got != nil {
		t.Errorf("bad yaml: %v", got)
	}
	// rke2 splits a scalar slice value on commas; config.yaml.d "key+" appends
	if got := YAMLList("tls-san: \"a.example.com, 10.0.0.100\"\ntls-san+:\n  - b.example.com\n", "tls-san"); strings.Join(got, ",") != "a.example.com,10.0.0.100,b.example.com" {
		t.Errorf("comma scalar + append: %v", got)
	}
	// a duplicated key breaks yaml.v3 but not rke2 (last wins): read line by line
	dup := "tls-san:\n  - old.example.com\nprofile: cis\ntls-san:\n- \"vip.example.com\" # the VIP\n- 10.0.0.100\ntls-san+: [x.example.com, 'y.example.com']\nkube-apiserver-arg:\n  - audit-log-maxage=30\n"
	if got := YAMLList(dup, "tls-san"); strings.Join(got, ",") != "vip.example.com,10.0.0.100,x.example.com,y.example.com" {
		t.Errorf("duplicate key fallback: %v", got)
	}
	if got := YAMLList(dup, "profile"); strings.Join(got, ",") != "cis" {
		t.Errorf("scalar via fallback: %v", got)
	}
	if got := YAMLList("\ttls-san:\n\t  - a\nservice-cidr: 10.43.0.0/16\n", "service-cidr"); strings.Join(got, ",") != "10.43.0.0/16" {
		t.Errorf("tab-indented file: %v", got)
	}
}

func TestCertSANs(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kube-apiserver"}, NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"kubernetes", "vip.example.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.100"), net.ParseIP("fd00::1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	dns, ips, err := CertSANs("junk before\n" + pemText)
	if err != nil || strings.Join(dns, ",") != "kubernetes,vip.example.com" || strings.Join(ips, ",") != "10.0.0.100,fd00::1" {
		t.Errorf("sans: %v %v %v", dns, ips, err)
	}
	if _, _, err := CertSANs("no pem here"); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("no pem: %v", err)
	}
	if _, _, err := CertSANs("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"); err == nil {
		t.Error("bad der must fail")
	}
}

func TestInClusterSAN(t *testing.T) {
	in := []string{"localhost", "LOCALHOST", "kubernetes", "kubernetes.default", "kubernetes.default.svc.cluster.local", "rancher.cattle-system.svc", "127.0.0.1", "::1", "0.0.0.0", "10.43.0.1", "10.96.0.1", "10.111.5.5"}
	for _, s := range in {
		if !InClusterSAN(s, nil) {
			t.Errorf("%s should be in-cluster", s)
		}
	}
	out := []string{"vip.example.com", "cp-1", "10.0.0.100", "192.168.1.1", "10.44.0.1", "10.112.0.1", "fd00::1"}
	for _, s := range out {
		if InClusterSAN(s, nil) {
			t.Errorf("%s should not be in-cluster", s)
		}
	}
	// explicit service CIDRs replace the defaults; several may be comma-joined
	cidrs := []string{"192.168.0.0/24, fd10::/64", "bad-cidr"}
	if !InClusterSAN("192.168.0.7", cidrs) || !InClusterSAN("fd10::5", cidrs) || InClusterSAN("10.43.0.1", cidrs) {
		t.Error("custom service cidrs")
	}
}

func TestMissingSANs(t *testing.T) {
	got := MissingSANs([]string{"VIP.example.com", "new.example.com", "10.0.0.100"}, []string{"vip.example.com", "10.0.0.100"})
	if strings.Join(got, ",") != "new.example.com" {
		t.Errorf("missing: %v", got)
	}
	if MissingSANs(nil, nil) != nil || MissingSANs([]string{"a"}, []string{"a"}) != nil {
		t.Error("nothing missing")
	}
}
