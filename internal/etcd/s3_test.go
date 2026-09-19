package etcd

import (
	"strings"
	"testing"
)

func TestS3URL(t *testing.T) {
	for _, c := range []struct {
		ep       string
		insecure bool
		want     string
	}{
		{"", false, "https://s3.amazonaws.com"},
		{"minio.lab:9000", false, "https://minio.lab:9000"},
		{"minio.lab:9000", true, "http://minio.lab:9000"},
		{"https://s3.eu-west-1.amazonaws.com/", false, "https://s3.eu-west-1.amazonaws.com"},
	} {
		if got := S3URL(c.ep, c.insecure); got != c.want {
			t.Errorf("S3URL(%q,%v)=%q want %q", c.ep, c.insecure, got, c.want)
		}
	}
}

func TestS3CheckScriptAndParse(t *testing.T) {
	s := S3CheckScript("https://minio.lab:9000", "", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", false)
	for _, want := range []string{"mktemp /tmp/khealth-s3-ca", "<<'KHEALTH_EOF_CA'", "--cacert $CA", "curl $ARGS \"$URL/\"", "rm -f \"$CA\""} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "-k") {
		t.Errorf("no -k without skip-verify")
	}
	s = S3CheckScript("https://x", "/etc/rancher/rke2/s3-ca.crt", "", true)
	if !strings.Contains(s, "CA='/etc/rancher/rke2/s3-ca.crt'") || !strings.Contains(s, `ARGS="$ARGS -k"`) {
		t.Errorf("file CA / skip-verify:\n%s", s)
	}
	// hostile PEM content is not embedded
	s = S3CheckScript("https://x", "", "$(rm -rf /)", false)
	if strings.Contains(s, "rm -rf") {
		t.Errorf("unsafe PEM embedded")
	}

	for _, c := range []struct {
		out    string
		ok     bool
		code   int
		detail string
	}{
		{"403\n", true, 403, "HTTP 403"},
		{"curl: (60) SSL certificate problem: unable to get local issuer certificate\n", false, 0, "(60) SSL certificate problem: unable to get local issuer certificate"},
		{"curl: (6) Could not resolve host: minio.lab\n", false, 0, "(6) Could not resolve host: minio.lab"},
		{"ca-missing=/etc/s3-ca.crt\n200\n", true, 200, "HTTP 200 (configured CA /etc/s3-ca.crt not readable, verified with system CAs)"},
		{"curl-missing\n", false, 0, "curl not installed on node"},
		{"", false, 0, "no output"},
	} {
		r := ParseS3Check("cp-1", "https://minio.lab:9000", c.out)
		if r.OK != c.ok || r.HTTPCode != c.code || r.Detail != c.detail {
			t.Errorf("%q -> %+v", c.out, r)
		}
	}
}

// the RKE2CONFIG section masks credential values but keeps the keys
func TestParseS3InlineConfig(t *testing.T) {
	out := `
===DIST
rke2
===RKE2CONFIG
/etc/rancher/rke2/config.yaml: etcd-s3: true
/etc/rancher/rke2/config.yaml: etcd-s3-endpoint: minio.lab:9000
/etc/rancher/rke2/config.yaml: etcd-s3-bucket: rke2-snapshots
/etc/rancher/rke2/config.yaml: etcd-s3-access-key: <set>
/etc/rancher/rke2/config.yaml: etcd-s3-secret-key:
===END
`
	p := Parse("cp-1", out)
	if p.RKE2Config["etcd-s3-access-key"] != "<set>" || p.RKE2Config["etcd-s3-secret-key"] != "" || p.RKE2Config["etcd-s3-endpoint"] != "minio.lab:9000" {
		t.Errorf("config: %+v", p.RKE2Config)
	}
}
