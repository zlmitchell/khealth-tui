package checks

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
)

func TestEndpointReport(t *testing.T) {
	nodes := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "cp-1"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.11"}}}}}
	infos := map[string]*nodeinfo.Info{
		"cp-1": {ControlPlane: true, TLSSAN: []string{"k8s.example.com", "k8s-new.example.com"},
			APIServerSANs: []string{"kubernetes", "kubernetes.default.svc.cluster.local", "localhost", "k8s.example.com", "127.0.0.1", "10.43.0.1", "10.0.0.11", "10.0.0.100"}},
		"agent-1": {ControlPlane: false, TLSSAN: []string{"x"}},
	}
	rep := Endpoint("https://k8s.example.com:6443", nodes, infos, nil)
	if rep.Host != "k8s.example.com" || rep.IsNode != "" || len(rep.Servers) != 1 {
		t.Fatalf("report: %+v", rep)
	}
	s := rep.Servers[0]
	if !s.HostOK || len(s.Missing) != 1 || s.Missing[0] != "k8s-new.example.com" {
		t.Errorf("server: %+v", s)
	}
	if strings.Join(s.CertSANs, ",") != "k8s.example.com,10.0.0.11,10.0.0.100" {
		t.Errorf("external SANs: %v", s.CertSANs)
	}
	// pointing at one node's address
	rep = Endpoint("https://10.0.0.11:6443", nodes, infos, nil)
	if rep.IsNode != "cp-1" || !rep.Servers[0].HostOK {
		t.Errorf("node endpoint: %+v", rep)
	}
	// endpoint the cert does not cover
	rep = Endpoint("https://vip.example.com:6443", nodes, infos, nil)
	if rep.Servers[0].HostOK {
		t.Errorf("host should not be in cert")
	}
}

func TestEndpointKubeadm(t *testing.T) {
	nodes := []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "cp-1"}}}
	infos := map[string]*nodeinfo.Info{
		"cp-1": {ControlPlane: true, Dist: "kubeadm", APIServerSANs: []string{"kubernetes", "cp-1", "10.96.0.1", "10.0.0.11", "lb.example.com"}},
	}
	kc := &k8s.KubeadmConfig{ControlPlaneEndpoint: "lb.example.com:6443", CertSANs: []string{"lb-new.example.com"}, ServiceSubnet: "10.96.0.0/12"}
	rep := Endpoint("https://lb.example.com:6443", nodes, infos, kc)
	if len(rep.Servers) != 1 {
		t.Fatalf("servers: %+v", rep)
	}
	s := rep.Servers[0]
	if s.Dist != "kubeadm" || !s.HostOK || strings.Join(s.Missing, ",") != "lb-new.example.com" || strings.Join(s.TLSSAN, ",") != "lb-new.example.com,lb.example.com" {
		t.Errorf("kubeadm server: %+v", s)
	}
	if strings.Join(s.CertSANs, ",") != "cp-1,10.0.0.11,lb.example.com" {
		t.Errorf("external SANs: %v", s.CertSANs)
	}
}
