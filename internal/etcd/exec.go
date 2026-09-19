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
	// rke2's hardened-etcd image has no shell: exec etcdctl directly (etcd 3.4+ defaults to the v3 API)
	base := []string{"etcdctl", "--cacert=" + ca, "--cert=" + cert, "--key=" + key}
	run := func(args ...string) (string, error) {
		argv := append(append([]string{}, base...), args...)
		out, errOut, err := ex.ExecInPod(ctx, "kube-system", pod, "etcd", argv)
		if err != nil && strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("%v: %s", err, firstLine(errOut))
		}
		if strings.TrimSpace(errOut) != "" {
			p.Stderr = strings.TrimSpace(errOut)
		}
		return out, nil
	}

	// 1. members
	out, err := run("--endpoints=https://127.0.0.1:2379", "member", "list", "-w", "json")
	if err != nil {
		p.Err = fmt.Errorf("member list: %w", err)
		p.EtcdctlDiag = p.Err.Error()
		return p
	}
	parseEtcdctl(p, "---MEMBERS\n"+out+"\n")
	membersRaw := strings.TrimSpace(out)
	p.EtcdctlOut = membersRaw
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
	epFlag := "--endpoints=" + strings.Join(eps, ",")
	p.Endpoint = strings.Join(eps, ",")

	// 2. health + status against every member's client URL (a down member
	// makes etcdctl exit non-zero but the JSON for the others is still printed)
	healthRaw, herr := run(epFlag, "endpoint", "health", "-w", "json")
	statusRaw, serr := run(epFlag, "endpoint", "status", "-w", "json")
	alarmRaw, aerr := run("--endpoints=https://127.0.0.1:2379", "alarm", "list", "-w", "json")
	var diags []string
	for _, e := range []error{herr, serr, aerr} {
		if e != nil {
			diags = append(diags, e.Error())
		}
	}
	if len(diags) > 0 {
		p.EtcdctlDiag = strings.Join(diags, "; ")
	}
	out = "---MEMBERS\n(see above)\n---STATUS\n" + statusRaw + "\n---ALARMS\n" + alarmRaw + "\n"
	parseEtcdctl(p, "---STATUS\n"+statusRaw+"\n---ALARMS\n"+alarmRaw+"\n")
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
	p.EtcdctlOut = "member list:\n" + strings.TrimSpace(p.EtcdctlOut) + "\nendpoint health:\n" + strings.TrimSpace(healthRaw) + "\n" + out
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
