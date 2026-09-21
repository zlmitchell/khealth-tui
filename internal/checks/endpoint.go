package checks

import (
	"fmt"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/distro"
	"github.com/zlmitchell/khealth-tui/internal/k8s"
	"github.com/zlmitchell/khealth-tui/internal/nodeinfo"
	"github.com/zlmitchell/khealth-tui/internal/strutil"
)

// EndpointReport compares the API endpoint the kubeconfig uses with what the
// server nodes' apiserver certificates allow and what config.yaml asks for.
type EndpointReport struct {
	Host    string // kubeconfig server host ("" when unknown)
	IsNode  string // node whose address the host is ("" = not a node address: VIP / LB / external name)
	Servers []EndpointServer
}

// EndpointServer is one control-plane node's view.
type EndpointServer struct {
	Node     string
	Dist     string   // rke2, k3s, kubeadm
	TLSSAN   []string // config.yaml tls-san (rke2/k3s) or kubeadm certSANs + controlPlaneEndpoint
	CertSANs []string // external SANs of serving-kube-apiserver.crt (in-cluster names dropped)
	Missing  []string // tls-san entries the certificate lacks (rke2 reissues on restart)
	HostOK   bool     // kubeconfig host is in the certificate
	HasCert  bool
}

// APIHost extracts the host from a kubeconfig server URL.
func APIHost(server string) string {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	return h
}

// Endpoint builds the report; nodes without SSH data are skipped. For
// upstream (kubeadm) clusters the configured SANs come from the cluster's
// kubeadm-config ClusterConfiguration instead of a file on the node.
func Endpoint(apiServer string, nodes []corev1.Node, infos map[string]*nodeinfo.Info, kubeadm *k8s.KubeadmConfig) EndpointReport {
	rep := EndpointReport{Host: APIHost(apiServer)}
	var kubeadmSANs, kubeadmCIDRs []string
	if kubeadm != nil {
		kubeadmSANs = append(kubeadmSANs, kubeadm.CertSANs...)
		if h := APIHost("https://" + kubeadm.ControlPlaneEndpoint); h != "" {
			kubeadmSANs = append(kubeadmSANs, h)
		}
		if kubeadm.ServiceSubnet != "" {
			kubeadmCIDRs = []string{kubeadm.ServiceSubnet}
		}
	}
	for i := range nodes {
		for _, a := range nodes[i].Status.Addresses {
			if rep.Host != "" && strings.EqualFold(a.Address, rep.Host) {
				rep.IsNode = nodes[i].Name
			}
		}
	}
	for _, name := range strutil.SortedKeys(infos) {
		ni := infos[name]
		if ni == nil || ni.Err != nil || !ni.ControlPlane {
			continue
		}
		tlsSAN, cidrs := ni.TLSSAN, []string{}
		for _, cf := range ni.ConfigFiles {
			cidrs = append(cidrs, nodeinfo.YAMLList(cf.Content, "service-cidr")...)
		}
		if ni.Dist == "kubeadm" {
			tlsSAN, cidrs = kubeadmSANs, kubeadmCIDRs
		}
		if len(tlsSAN) == 0 && len(ni.APIServerSANs) == 0 {
			continue
		}
		s := EndpointServer{Node: name, Dist: ni.Dist, TLSSAN: tlsSAN, HasCert: len(ni.APIServerSANs) > 0}
		for _, san := range ni.APIServerSANs {
			if !nodeinfo.InClusterSAN(san, cidrs) {
				s.CertSANs = append(s.CertSANs, san)
			}
		}
		s.Missing = nodeinfo.MissingSANs(tlsSAN, ni.APIServerSANs)
		if rep.Host != "" {
			for _, san := range ni.APIServerSANs {
				if strings.EqualFold(san, rep.Host) {
					s.HostOK = true
				}
			}
		}
		rep.Servers = append(rep.Servers, s)
	}
	return rep
}

// evalEndpoint turns the report into findings.
func evalEndpoint(in Input, add func(Severity, string, string, string, string)) {
	rep := Endpoint(in.APIServer, in.Snap.Nodes, in.Nodes, in.Snap.Kubeadm)
	servers := 0
	for _, ni := range in.Nodes {
		if ni != nil && ni.Err == nil && ni.ControlPlane {
			servers++
		}
	}
	for _, s := range rep.Servers {
		if len(s.Missing) > 0 {
			add(SevWarn, "node", s.Node, fmt.Sprintf("%s %s configured but not in the apiserver certificate: kubeconfigs using it fail TLS until the cert is reissued", SANKey(s.Dist), strings.Join(s.Missing, ", ")), ReissueHint(s.Dist))
		}
		if rep.Host != "" && s.HasCert && !s.HostOK {
			add(SevWarn, "node", s.Node, fmt.Sprintf("kubeconfig endpoint %s is not in this server's apiserver certificate", rep.Host), "add it to "+SANKey(s.Dist)+" and reissue the certificate ("+ReissueHint(s.Dist)+"), or point the kubeconfig at a name/VIP the cert covers (--bootstrap-kubeconfig does that)")
		}
	}
	if rep.Host != "" && rep.IsNode != "" && servers > 1 {
		dist := "rke2"
		if len(rep.Servers) > 0 {
			dist = rep.Servers[0].Dist
		}
		add(SevInfo, "cluster", "endpoint", fmt.Sprintf("kubeconfig points at a single server node (%s = %s), not a VIP / load balancer", rep.Host, rep.IsNode), "put a VIP or DNS name in "+SANKey(dist)+" and use it as the kubeconfig server; the cluster stays reachable when that node is down")
	}
}

// SANKey names where the extra apiserver SANs are configured per distribution.
func SANKey(dist string) string { return distro.For(dist).SANKey }

// ReissueHint is how the apiserver serving certificate gets regenerated
// after the configured SANs change.
func ReissueHint(dist string) string { return distro.For(dist).Reissue }
