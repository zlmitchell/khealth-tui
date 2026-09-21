package bootstrap

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

	"k8s.io/client-go/tools/clientcmd"

	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

const rke2yaml = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0t
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: default
  user:
    client-certificate-data: LS0t
    client-key-data: LS0t
`

func servingCert(t *testing.T, dns []string, ips []string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kube-apiserver"}, NotAfter: time.Now().Add(time.Hour), DNSNames: dns}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseAndRank(t *testing.T) {
	cert := servingCert(t, []string{"kubernetes", "kubernetes.default.svc.cluster.local", "localhost", "cp-1", "k8s-prod.example.com"}, []string{"127.0.0.1", "10.43.0.1", "10.0.0.11", "10.0.0.100"})
	out := "=== KUBECONFIG /etc/rancher/rke2/rke2.yaml\n" + rke2yaml + "=== END\n" +
		"=== CONFIG /etc/rancher/rke2/config.yaml\ntls-san:\n  - k8s-prod.example.com\n  - k8s-new.example.com\ntoken: x\n=== END\n" +
		"=== CERT /var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt\n" + cert + "=== END\n" +
		"=== HOSTNAME\ncp-1.example.com\n=== END\n=== NODEIPS\n10.0.0.11\nfd00::11\n=== END\n"
	src := &Source{Host: "10.0.0.11"}
	if err := src.parse(out); err != nil {
		t.Fatal(err)
	}
	if src.Path != "/etc/rancher/rke2/rke2.yaml" || !strings.Contains(string(src.Kubeconfig), "127.0.0.1:6443") {
		t.Errorf("kubeconfig: %q %q", src.Path, src.Kubeconfig)
	}
	if len(src.TLSSAN) != 2 || src.Hostname != "cp-1.example.com" || len(src.CertDNS) != 5 || len(src.CertIPs) != 4 {
		t.Errorf("parsed: %+v", src)
	}
	lookup := func(name string) []net.IP {
		switch name {
		case "k8s-prod.example.com":
			return []net.IP{net.ParseIP("10.0.0.100")}
		case "cp-1":
			return []net.IP{net.ParseIP("10.0.0.11")}
		}
		return nil
	}
	eps := Rank(src, lookup)
	if eps[0].Host != "k8s-prod.example.com" || eps[0].Score != 100 {
		t.Errorf("best endpoint: %+v", eps[0])
	}
	if eps[1].Host != "10.0.0.100" {
		t.Errorf("second should be the VIP address: %+v", eps[1])
	}
	for _, e := range eps {
		if e.Host == "kubernetes" || e.Host == "localhost" || e.Host == "127.0.0.1" || strings.Contains(e.Host, ".svc") {
			t.Errorf("in-cluster SAN offered: %+v", e)
		}
	}
	if ClusterName("", eps[0], src) != "k8s-prod" {
		t.Errorf("name from DNS: %q", ClusterName("", eps[0], src))
	}
	if n := ClusterName("", Endpoint{Host: "10.0.0.100"}, src); n != "cp" {
		t.Errorf("name from hostname: %q", n)
	}
	if ClusterName("prod", eps[0], src) != "prod" {
		t.Errorf("explicit name")
	}
}

func TestRankFallsBackToSSHHost(t *testing.T) {
	cert := servingCert(t, []string{"kubernetes", "localhost"}, []string{"127.0.0.1", "10.43.0.1"})
	src := &Source{Host: "10.0.0.11:22"}
	_, ips, _ := nodeinfo.CertSANs(cert)
	src.CertIPs = ips
	src.CertDNS = []string{"kubernetes", "localhost"}
	eps := Rank(src, func(string) []net.IP { return nil })
	if len(eps) != 1 || eps[0].Host != "10.0.0.11" || eps[0].Score != 10 {
		t.Errorf("fallback: %+v", eps)
	}
}

func TestRewriteNamesTheCluster(t *testing.T) {
	out, err := Rewrite([]byte(rke2yaml), "k8s-prod.example.com", "prod")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := cfg.Clusters["prod"]
	if !ok || c.Server != "https://k8s-prod.example.com:6443" {
		t.Errorf("cluster: %+v", cfg.Clusters)
	}
	if _, ok := cfg.AuthInfos["prod"]; !ok {
		t.Errorf("user not renamed: %v", cfg.AuthInfos)
	}
	ctx, ok := cfg.Contexts["prod"]
	if !ok || ctx.Cluster != "prod" || ctx.AuthInfo != "prod" || cfg.CurrentContext != "prod" {
		t.Errorf("context: %+v current=%q", cfg.Contexts, cfg.CurrentContext)
	}
	if _, still := cfg.Clusters["default"]; still {
		t.Errorf("default cluster left behind")
	}
}
