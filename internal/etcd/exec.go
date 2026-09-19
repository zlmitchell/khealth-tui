package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Execer runs a command inside a pod (satisfied by *k8s.Client).
type Execer interface {
	ExecInPod(ctx context.Context, ns, pod, container string, cmd []string) (string, string, error)
}

// EndpointHealth is one entry of `etcdctl endpoint health -w json`.
type EndpointHealth struct {
	Endpoint string
	Healthy  bool
	Took     string
	Error    string
}

// CertPaths returns the etcdctl cert flags as seen inside the etcd container.
func CertPaths(dist string) (ca, cert, key string) {
	switch dist {
	case "rke2":
		return "/var/lib/rancher/rke2/server/tls/etcd/server-ca.crt", "/var/lib/rancher/rke2/server/tls/etcd/server-client.crt", "/var/lib/rancher/rke2/server/tls/etcd/server-client.key"
	case "k3s":
		return "/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt", "/var/lib/rancher/k3s/server/tls/etcd/server-client.crt", "/var/lib/rancher/k3s/server/tls/etcd/server-client.key"
	default: // kubeadm static pod mounts /etc/kubernetes/pki/etcd
		return "/etc/kubernetes/pki/etcd/ca.crt", "/etc/kubernetes/pki/etcd/healthcheck-client.crt", "/etc/kubernetes/pki/etcd/healthcheck-client.key"
	}
}

// ExecProbe gathers cluster-wide etcd state through `kubectl exec` into the
// etcd static pod: member list first, then endpoint health/status against
// every member's client URL, then alarms.
func ExecProbe(ctx context.Context, ex Execer, node, pod, dist string) *Probe {
	p := &Probe{Node: node, Collected: time.Now(), Dist: dist, EtcdctlVia: "kubectl exec " + pod, RKE2Config: map[string]string{}}
	start := time.Now()
	defer func() { p.Duration = time.Since(start) }()
	ca, cert, key := CertPaths(dist)
	p.CA, p.Cert, p.Key = ca, cert, key
	base := fmt.Sprintf("ETCDCTL_API=3 etcdctl --cacert=%s --cert=%s --key=%s", ca, cert, key)
	run := func(script string) (string, error) {
		out, errOut, err := ex.ExecInPod(ctx, "kube-system", pod, "etcd", []string{"sh", "-c", script})
		if err != nil && strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("%v: %s", err, firstLine(errOut))
		}
		if strings.TrimSpace(errOut) != "" {
			p.Stderr = strings.TrimSpace(errOut)
		}
		return out, nil
	}

	// 1. members
	out, err := run(base + " --endpoints=https://127.0.0.1:2379 member list -w json")
	if err != nil {
		p.Err = fmt.Errorf("member list: %w", err)
		p.EtcdctlDiag = p.Err.Error()
		return p
	}
	parseEtcdctl(p, "---MEMBERS\n"+out+"\n")
	if len(p.Members) == 0 {
		p.Err = fmt.Errorf("member list returned no members: %s", firstLine(out))
		p.EtcdctlDiag = p.Err.Error()
		return p
	}
	var eps []string
	for _, m := range p.Members {
		eps = append(eps, m.ClientURLs...)
	}
	if len(eps) == 0 {
		eps = []string{"https://127.0.0.1:2379"}
	}
	epFlag := " --endpoints=" + strings.Join(eps, ",")
	p.Endpoint = strings.Join(eps, ",")

	// 2. health + status per endpoint, 3. alarms (non-zero exit is expected when a member is down)
	script := base + epFlag + " endpoint health -w json; echo; echo ---STATUS; " +
		base + epFlag + " endpoint status -w json; echo; echo ---ALARMS; " +
		base + " --endpoints=https://127.0.0.1:2379 alarm list -w json; echo"
	out, err = run(script)
	if err != nil {
		p.EtcdctlDiag = "health/status: " + err.Error()
		return p
	}
	healthRaw, rest, _ := strings.Cut(out, "---STATUS")
	parseEtcdctl(p, "---STATUS"+rest)
	p.EndpointHealth = parseEndpointHealth(healthRaw)
	allOK := len(p.EndpointHealth) > 0
	var bad []string
	for _, h := range p.EndpointHealth {
		if !h.Healthy {
			allOK = false
			bad = append(bad, h.Endpoint+" "+h.Error)
		}
	}
	p.Health = &Health{Healthy: allOK, Reason: strings.Join(bad, "; "), Raw: strings.TrimSpace(healthRaw)}
	p.EtcdctlOut = out
	return p
}

func parseEndpointHealth(raw string) []EndpointHealth {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// etcdctl may print warnings before the JSON array
	if i := strings.Index(raw, "["); i > 0 {
		raw = raw[i:]
	}
	var doc []struct {
		Endpoint string `json:"endpoint"`
		Health   bool   `json:"health"`
		Took     string `json:"took"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}
	out := make([]EndpointHealth, 0, len(doc))
	for _, d := range doc {
		out = append(out, EndpointHealth{Endpoint: d.Endpoint, Healthy: d.Health, Took: d.Took, Error: d.Error})
	}
	return out
}

// MemberByEndpoint finds the member whose client URLs include the endpoint.
func (p *Probe) MemberByEndpoint(ep string) *Member {
	for i := range p.Members {
		for _, u := range p.Members[i].ClientURLs {
			if u == ep {
				return &p.Members[i]
			}
		}
	}
	return nil
}
