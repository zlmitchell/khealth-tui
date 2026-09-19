// Package bootstrap builds a working kubeconfig from a node when the
// operator has SSH access but no kubeconfig: it fetches the admin kubeconfig
// (rke2.yaml / k3s.yaml / admin.conf), replaces the 127.0.0.1 server with an
// endpoint the apiserver certificate is actually valid for (a VIP DNS name
// when there is one), names the context after the cluster, verifies the
// result against the API and writes it under ~/.kube.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s-health-tui/internal/nodeinfo"
	"k8s-health-tui/internal/sshrun"
)

// Source is what the node reported.
type Source struct {
	Host        string   // SSH host as given
	Hostname    string   // node hostname
	Path        string   // kubeconfig path on the node
	Kubeconfig  []byte   // raw admin kubeconfig
	CertPath    string   // apiserver serving cert
	CertDNS     []string // SANs the certificate is valid for
	CertIPs     []string
	TLSSAN      []string // tls-san from config.yaml (intent; needs a restart to reach the cert)
	ServiceCIDR []string // service-cidr from config.yaml (the apiserver ClusterIP SAN is useless from outside)
	NodeIPs     []string // addresses on the node's interfaces
	ConfigDirs  []string // config files read (for the report)
}

// Endpoint is one candidate server address with the reason it was ranked.
type Endpoint struct {
	Host   string
	Score  int
	Reason string
}

// Result is the outcome of a bootstrap.
type Result struct {
	Path     string
	Name     string
	Server   string
	Version  string
	Endpoint Endpoint
	Notes    []string
}

// script prints the admin kubeconfig, the rke2/k3s config files, the
// apiserver serving certificate and the node's addresses in tagged sections.
const script = `
for f in /etc/rancher/rke2/rke2.yaml /etc/rancher/k3s/k3s.yaml /etc/kubernetes/admin.conf; do
  [ -f "$f" ] || continue
  echo "=== KUBECONFIG $f"; cat "$f"; echo; echo "=== END"; break
done
for f in /etc/rancher/rke2/config.yaml /etc/rancher/rke2/config.yaml.d/*.yaml /etc/rancher/k3s/config.yaml /etc/rancher/k3s/config.yaml.d/*.yaml; do
  [ -f "$f" ] || continue
  echo "=== CONFIG $f"; cat "$f"; echo; echo "=== END"
done
for c in /var/lib/rancher/rke2/server/tls/serving-kube-apiserver.crt /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt /etc/kubernetes/pki/apiserver.crt; do
  [ -f "$c" ] || continue
  echo "=== CERT $c"; cat "$c"; echo; echo "=== END"; break
done
echo "=== HOSTNAME"; hostname 2>/dev/null; echo "=== END"
echo "=== NODEIPS"
if command -v ip >/dev/null 2>&1; then ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
else hostname -I 2>/dev/null | tr ' ' '\n'; fi
echo "=== END"
`

var sectionRe = regexp.MustCompile(`(?m)^=== (KUBECONFIG|CONFIG|CERT|HOSTNAME|NODEIPS)(?: (.*))?$`)

// Fetch reads the kubeconfig, config and certificate from one node over SSH.
func Fetch(ctx context.Context, r *sshrun.Runner, host string) (*Source, error) {
	res := r.Run(ctx, host, script)
	if res.Err != nil {
		return nil, fmt.Errorf("ssh %s: %w", host, res.Err)
	}
	src := &Source{Host: host}
	if err := src.parse(res.Stdout); err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	if len(src.Kubeconfig) == 0 {
		return nil, fmt.Errorf("%s: no admin kubeconfig found (rke2.yaml, k3s.yaml or admin.conf); is this a server node, and did privilege escalation work? %s", host, strings.TrimSpace(res.Stderr))
	}
	return src, nil
}

func (s *Source) parse(out string) error {
	locs := sectionRe.FindAllStringSubmatchIndex(out, -1)
	for i, m := range locs {
		kind := out[m[2]:m[3]]
		arg := ""
		if m[4] >= 0 {
			arg = strings.TrimSpace(out[m[4]:m[5]])
		}
		bodyStart := m[1] + 1
		bodyEnd := len(out)
		if i+1 < len(locs) {
			bodyEnd = locs[i+1][0]
		}
		body := out[bodyStart:min(bodyEnd, len(out))]
		if j := strings.Index(body, "\n=== END"); j >= 0 {
			body = body[:j]
		}
		switch kind {
		case "KUBECONFIG":
			s.Path = arg
			s.Kubeconfig = []byte(strings.TrimSpace(body) + "\n")
		case "CONFIG":
			s.ConfigDirs = append(s.ConfigDirs, arg)
			s.TLSSAN = append(s.TLSSAN, nodeinfo.YAMLList(body, "tls-san")...)
			s.ServiceCIDR = append(s.ServiceCIDR, nodeinfo.YAMLList(body, "service-cidr")...)
		case "CERT":
			s.CertPath = arg
			dns, ips, err := nodeinfo.CertSANs(body)
			if err != nil {
				return fmt.Errorf("parse %s: %w", arg, err)
			}
			s.CertDNS, s.CertIPs = dns, ips
		case "HOSTNAME":
			s.Hostname = strings.TrimSpace(body)
		case "NODEIPS":
			for _, l := range strings.Split(body, "\n") {
				if l = strings.TrimSpace(l); l != "" {
					s.NodeIPs = append(s.NodeIPs, l)
				}
			}
		}
	}
	return nil
}

// Dist is the distribution the kubeconfig came from, by its path.
func (s *Source) Dist() string {
	switch {
	case strings.Contains(s.Path, "/k3s/"):
		return "k3s"
	case strings.HasPrefix(s.Path, "/etc/kubernetes/"):
		return "kubeadm"
	}
	return "rke2"
}

// sanHint says where to configure an extra apiserver SAN.
func (s *Source) sanHint(host string) string {
	switch s.Dist() {
	case "kubeadm":
		return fmt.Sprintf("%q to apiServer.certSANs in the kubeadm-config ConfigMap (kubectl -n kube-system edit cm kubeadm-config)", host)
	case "k3s":
		return fmt.Sprintf("`tls-san: [%s]` to /etc/rancher/k3s/config.yaml on every server", host)
	}
	return fmt.Sprintf("`tls-san: [%s]` to /etc/rancher/rke2/config.yaml on every server", host)
}

// reissueHint says how the serving certificate gets regenerated.
func (s *Source) reissueHint() string {
	switch s.Dist() {
	case "kubeadm":
		return "on each control-plane node run `kubeadm certs renew apiserver` and restart kube-apiserver"
	case "k3s":
		return "restart k3s on the servers (one at a time) to reissue it"
	}
	return "restart rke2-server on the servers (one at a time) to reissue it"
}

// Lookup resolves a DNS name; replaced in tests.
type Lookup func(name string) []net.IP

func defaultLookup(name string) []net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out
}

// Rank orders the certificate's SANs by how likely they are to be the
// cluster's stable entry point, from the operator's point of view:
//
//	a DNS name resolving to a SAN address that is not one of the node's own
//	addresses (a VIP / load balancer name) ranks first, then a bare VIP
//	address, then a DNS name for the node, then the SSH host itself.
//
// The SSH host is always appended as a last resort so a cluster whose
// certificate has no usable SAN still yields a kubeconfig (with a warning).
func Rank(src *Source, lookup Lookup) []Endpoint {
	if lookup == nil {
		lookup = defaultLookup
	}
	nodeIP := map[string]bool{}
	for _, ip := range src.NodeIPs {
		nodeIP[ip] = true
	}
	sanIP := map[string]bool{}
	for _, ip := range src.CertIPs {
		sanIP[ip] = true
	}
	sshHost, _, _ := net.SplitHostPort(src.Host)
	if sshHost == "" {
		sshHost = src.Host
	}
	skip := func(san string) bool { return nodeinfo.InClusterSAN(san, src.ServiceCIDR) }
	var eps []Endpoint
	seen := map[string]bool{}
	add := func(host string, score int, reason string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		eps = append(eps, Endpoint{Host: host, Score: score, Reason: reason})
	}
	for _, name := range src.CertDNS {
		if skip(name) {
			continue
		}
		resolved := lookup(name)
		switch {
		case len(resolved) == 0:
			add(name, 20, "in the certificate but does not resolve from here")
		case anyIP(resolved, func(ip string) bool { return sanIP[ip] && !nodeIP[ip] }):
			add(name, 100, "DNS name for a VIP / load-balancer address that is also in the certificate")
		case anyIP(resolved, func(ip string) bool { return !nodeIP[ip] }):
			add(name, 90, "DNS name resolving to an address that is not this node (load balancer)")
		case strings.EqualFold(name, sshHost):
			add(name, 60, "the SSH host, present in the certificate")
		default:
			add(name, 55, "DNS name of this node, present in the certificate")
		}
	}
	for _, ip := range src.CertIPs {
		if skip(ip) {
			continue
		}
		switch {
		case !nodeIP[ip]:
			add(ip, 80, "address in the certificate that is not one of this node's (VIP)")
		case ip == sshHost:
			add(ip, 50, "the SSH host address, present in the certificate")
		default:
			add(ip, 40, "this node's address, present in the certificate")
		}
	}
	if !seen[sshHost] {
		score, reason := 10, "the SSH host; NOT in the certificate, TLS verification will fail until tls-san is added"
		if ip := net.ParseIP(sshHost); ip == nil {
			// a name that resolves to a SAN address is fine for TLS only if the name itself is a SAN; it is not
			if anyIP(lookup(sshHost), func(ip string) bool { return sanIP[ip] }) {
				reason = "the SSH host name; it resolves to a certificate address but the name itself is not a SAN, so TLS verification will fail"
			}
		}
		add(sshHost, score, reason)
	}
	sort.SliceStable(eps, func(i, j int) bool { return eps[i].Score > eps[j].Score })
	return eps
}

func anyIP(ips []net.IP, f func(string) bool) bool {
	for _, ip := range ips {
		if f(ip.String()) {
			return true
		}
	}
	return false
}

// Rewrite points the kubeconfig at host (keeping the original port) and
// names the cluster, user and context after the cluster instead of
// "default", so several bootstrapped clusters can be merged and switched.
func Rewrite(kubeconfig []byte, host, name string) ([]byte, error) {
	cfg, err := clientcmd.Load(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	if len(cfg.Clusters) == 0 {
		return nil, errors.New("kubeconfig has no clusters")
	}
	for _, c := range cfg.Clusters {
		u, err := url.Parse(c.Server)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", c.Server, err)
		}
		port := u.Port()
		if port == "" {
			port = "6443"
		}
		u.Host = net.JoinHostPort(host, port)
		c.Server = u.String()
	}
	// rename default -> name (rke2/k3s use "default" for all three); only
	// when the file has a single entry of each kind, which is what the
	// distributions write
	if name != "" {
		if len(cfg.Clusters) == 1 {
			for old, c := range cfg.Clusters {
				delete(cfg.Clusters, old)
				cfg.Clusters[name] = c
			}
		}
		if len(cfg.AuthInfos) == 1 {
			for old, a := range cfg.AuthInfos {
				delete(cfg.AuthInfos, old)
				cfg.AuthInfos[name] = a
			}
		}
		for old, ctx := range cfg.Contexts {
			if len(cfg.Clusters) == 1 {
				ctx.Cluster = name
			}
			if len(cfg.AuthInfos) == 1 {
				ctx.AuthInfo = name
			}
			if len(cfg.Contexts) == 1 {
				delete(cfg.Contexts, old)
				cfg.Contexts[name] = ctx
				cfg.CurrentContext = name
			}
		}
	}
	return clientcmd.Write(*cfg)
}

// Verify connects to the API with the kubeconfig and returns the server version.
func Verify(ctx context.Context, kubeconfig []byte) (string, error) {
	rc, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return "", err
	}
	rc.Timeout = 8 * time.Second
	rc.WarningHandler = rest.NoWarnings{}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return "", err
	}
	v, err := cs.Discovery().ServerVersion()
	if err != nil {
		return "", err
	}
	return v.GitVersion, nil
}

// ClusterName picks the name for the context: an explicit name, else the
// first label of the endpoint's DNS name, else the node hostname without a
// trailing node index (cp-1 -> cp).
func ClusterName(explicit string, ep Endpoint, src *Source) string {
	if explicit != "" {
		return explicit
	}
	if net.ParseIP(ep.Host) == nil && ep.Host != "" {
		return strings.ToLower(strings.SplitN(ep.Host, ".", 2)[0])
	}
	h := strings.ToLower(strings.SplitN(src.Hostname, ".", 2)[0])
	h = regexp.MustCompile(`[-_]?\d+$`).ReplaceAllString(h, "")
	if h == "" {
		h = "cluster"
	}
	return h
}

// Options drive Run.
type Options struct {
	Hosts  []string // SSH hosts to try in order (server nodes)
	Out    string   // output path ("" = ~/.kube/khealth-<name>.yaml)
	Name   string   // cluster/context name ("" = derived)
	Lookup Lookup
	Log    func(format string, args ...any)
}

// Run fetches from the first reachable host, ranks the endpoints, verifies
// them in order and writes the first that works (or the best candidate with
// a warning when none does).
func Run(ctx context.Context, r *sshrun.Runner, o Options) (*Result, error) {
	logf := o.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var src *Source
	var errs []string
	for _, h := range o.Hosts {
		s, err := Fetch(ctx, r, h)
		if err != nil {
			errs = append(errs, err.Error())
			logf("  %s: %v", h, err)
			continue
		}
		src = s
		break
	}
	if src == nil {
		return nil, fmt.Errorf("no host yielded a kubeconfig: %s", strings.Join(errs, "; "))
	}
	logf("  %s: %s (cert %s: %d DNS, %d IP SANs)", src.Host, src.Path, filepath.Base(src.CertPath), len(src.CertDNS), len(src.CertIPs))
	eps := Rank(src, o.Lookup)
	res := &Result{}
	// tls-san entries not yet in the certificate mean a pending restart
	for _, s := range nodeinfo.MissingSANs(src.TLSSAN, append(append([]string{}, src.CertDNS...), src.CertIPs...)) {
		res.Notes = append(res.Notes, fmt.Sprintf("tls-san %q is configured but not in the serving certificate yet: %s", s, src.reissueHint()))
	}
	var out []byte
	for _, ep := range eps {
		name := ClusterName(o.Name, ep, src)
		kc, err := Rewrite(src.Kubeconfig, ep.Host, name)
		if err != nil {
			return nil, err
		}
		v, err := Verify(ctx, kc)
		if err != nil {
			logf("  %-40s %s", ep.Host, shortErr(err))
			if ep.Score <= 10 && out == nil {
				out, res.Endpoint, res.Name = kc, ep, name
				res.Notes = append(res.Notes, "no endpoint verified; wrote the SSH host - "+shortErr(err))
			}
			continue
		}
		logf("  %-40s ok  %s (%s)", ep.Host, v, ep.Reason)
		out, res.Endpoint, res.Name, res.Version = kc, ep, name, v
		break
	}
	if out == nil {
		return nil, errors.New("no endpoint could be verified")
	}
	if !strings.Contains(res.Endpoint.Reason, "certificate") || res.Endpoint.Score <= 10 {
		res.Notes = append(res.Notes, fmt.Sprintf("add %s so the certificate covers a stable name, then %s", src.sanHint(res.Endpoint.Host), src.reissueHint()))
	}
	path := o.Out
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".kube", "khealth-"+res.Name+".yaml")
	}
	if err := writeFile(path, out); err != nil {
		return nil, err
	}
	res.Path = path
	res.Server = "https://" + res.Endpoint.Host
	return res, nil
}

// writeFile writes 0600, keeping a .bak of an existing file.
func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, path+".bak"); err != nil {
			return fmt.Errorf("back up existing %s: %w", path, err)
		}
	}
	return os.WriteFile(path, b, 0o600)
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "certificate is valid for"):
		if i := strings.Index(s, "x509:"); i >= 0 {
			s = s[i:]
		}
		return "TLS: " + s
	case strings.Contains(s, "no such host"):
		return "does not resolve"
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
