// Package k8s wraps client-go and gathers a point-in-time Snapshot of the
// cluster state that the health checks and the UI consume.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Options tune how much load the client puts on the API server.
type Options struct {
	// WatchCache lists with resourceVersion=0: the apiserver serves the list
	// from its watch cache instead of a quorum read from etcd. Data can lag
	// by milliseconds, which is fine for a dashboard, and it takes the
	// refresh cycle off etcd entirely - the component we may be diagnosing.
	WatchCache bool
	// Protobuf requests application/vnd.kubernetes.protobuf for typed lists:
	// ~3-5x fewer bytes than JSON and much cheaper for the apiserver to
	// encode. Raw endpoints (readyz, metrics.k8s.io, kubelet proxy) stay JSON.
	Protobuf bool
	// Server replaces the kubeconfig's server URL (same CA, same
	// credentials): khealth fails over to another control-plane node's
	// apiserver when the configured one is down.
	Server string
	// DiscoveryTTL caches API discovery + CRD definitions (large, static)
	// and ConfigzTTL the per-node kubelet configz; 0 fetches every cycle.
	DiscoveryTTL time.Duration
	ConfigzTTL   time.Duration
	// DeniedTTL: a call the token is not allowed to make (403), or whose
	// API type does not exist (404 on a list), is not retried for this long
	// (R resets it); the cached error is still reported every cycle.
	DeniedTTL time.Duration
}

// DefaultOptions are what khealth uses unless configured otherwise.
func DefaultOptions() Options {
	return Options{WatchCache: true, Protobuf: true, DiscoveryTTL: 5 * time.Minute, ConfigzTTL: 10 * time.Minute, DeniedTTL: 10 * time.Minute}
}

// Client bundles the typed and dynamic clients for one kubeconfig context.
type Client struct {
	CS      *kubernetes.Clientset
	Dyn     dynamic.Interface
	Meta    metadata.Interface // metadata-only lists (names without payloads)
	Config  *rest.Config
	Context string
	Host    string
	Opts    Options

	mapperOnce sync.Once
	restMapper meta.RESTMapper

	stats *transportStats

	cacheMu     sync.Mutex
	discovery   []CRDInfo
	discoveryAt time.Time
	configz     map[string]configzEntry
	helmFP      string
	helmCache   []HelmRelease
	denied      map[string]deniedEntry
	// Longhorn: the settings list (~80 KB, static) is kept for DiscoveryTTL;
	// the engines list (the largest per-volume object, needed for rebuild
	// progress and the replica mode map) is refreshed when a volume is not
	// healthy or after DiscoveryTTL, and carried forward otherwise.
	lhSettings   map[string]string
	lhSettingsAt time.Time
	lhEngines    map[string]lhEngineFacts
	lhEnginesAt  time.Time
}

type deniedEntry struct {
	err error
	at  time.Time
}

// Denied reports the remembered error for a call that the token may not
// make (or whose resource type does not exist), while the DeniedTTL holds.
func (c *Client) Denied(what string) (error, bool) {
	if c == nil || c.Opts.DeniedTTL <= 0 {
		return nil, false
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	e, ok := c.denied[what]
	if !ok {
		return nil, false
	}
	if time.Since(e.at) > c.Opts.DeniedTTL {
		delete(c.denied, what)
		return nil, false
	}
	return e.err, true
}

// NoteDenied remembers err for what when it is a permission (403) or, with
// notFound, a missing-resource (404) error. Returns true when remembered.
func (c *Client) NoteDenied(what string, err error, notFound bool) bool {
	if c == nil || err == nil || c.Opts.DeniedTTL <= 0 {
		return false
	}
	if !(apierrors.IsForbidden(err) || (notFound && apierrors.IsNotFound(err)) || strings.Contains(err.Error(), "is forbidden:")) {
		return false
	}
	c.cacheMu.Lock()
	if c.denied == nil {
		c.denied = map[string]deniedEntry{}
	}
	c.denied[what] = deniedEntry{err: err, at: time.Now()}
	c.cacheMu.Unlock()
	return true
}

// DeniedList names the calls currently being skipped, sorted.
func (c *Client) DeniedList() []string {
	if c == nil {
		return nil
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	var out []string
	for k, e := range c.denied {
		if time.Since(e.at) <= c.Opts.DeniedTTL {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ResetDenied forgets every skipped call and the Longhorn caches (R / full
// refresh).
func (c *Client) ResetDenied() {
	if c == nil {
		return
	}
	c.cacheMu.Lock()
	c.denied = nil
	c.lhSettings, c.lhEngines = nil, nil
	c.cacheMu.Unlock()
}

// dynList lists a dynamic resource with the snapshot list options, skipping
// types the token cannot list or that are not installed (DeniedTTL).
func (c *Client) dynList(ctx context.Context, what string, gvr schema.GroupVersionResource) (*unstructured.UnstructuredList, error) {
	if err, ok := c.Denied(what); ok {
		return nil, err
	}
	l, err := c.Dyn.Resource(gvr).List(ctx, c.listOpts())
	if err != nil {
		c.NoteDenied(what, err, true)
	}
	return l, err
}

type configzEntry struct {
	cfg map[string]any
	at  time.Time
}

// Stats are cumulative API server traffic counters for this client (every
// request through client-go: lists, proxies, exec, log streams).
type Stats struct {
	Requests int64
	BytesIn  int64 // response bodies
	BytesOut int64 // request bodies
	Errors   int64 // transport errors (not HTTP status codes)
}

// Sub returns s - o.
func (s Stats) Sub(o Stats) Stats {
	return Stats{Requests: s.Requests - o.Requests, BytesIn: s.BytesIn - o.BytesIn, BytesOut: s.BytesOut - o.BytesOut, Errors: s.Errors - o.Errors}
}

type transportStats struct {
	requests, bytesIn, bytesOut, errors atomic.Int64
}

type countingTransport struct {
	rt http.RoundTripper
	st *transportStats
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.st.requests.Add(1)
	if req.ContentLength > 0 {
		t.st.bytesOut.Add(req.ContentLength)
	}
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		t.st.errors.Add(1)
		return nil, err
	}
	if resp.Body != nil {
		resp.Body = &countingBody{ReadCloser: resp.Body, n: &t.st.bytesIn}
	}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

// Stats returns the cumulative traffic counters.
func (c *Client) Stats() Stats {
	if c == nil || c.stats == nil {
		return Stats{}
	}
	return Stats{Requests: c.stats.requests.Load(), BytesIn: c.stats.bytesIn.Load(), BytesOut: c.stats.bytesOut.Load(), Errors: c.stats.errors.Load()}
}

// getOpts returns the GetOptions for a snapshot get: with the watch cache
// on, resourceVersion=0 is served from the apiserver cache like the lists.
func (c *Client) getOpts() metav1.GetOptions {
	if c.Opts.WatchCache {
		return metav1.GetOptions{ResourceVersion: "0"}
	}
	return metav1.GetOptions{}
}

// listOpts returns the ListOptions for a snapshot list.
func (c *Client) listOpts() metav1.ListOptions {
	if c.Opts.WatchCache {
		return metav1.ListOptions{ResourceVersion: "0"}
	}
	return metav1.ListOptions{}
}

// New builds a Client from a kubeconfig path (empty = default loading rules)
// and an optional context name, with DefaultOptions.
func New(kubeconfig, ctxName string) (*Client, error) {
	return NewWithOptions(kubeconfig, ctxName, DefaultOptions())
}

// NewWithOptions is New with explicit load-reduction options.
func NewWithOptions(kubeconfig, ctxName string, opts Options) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName != "" {
		overrides.CurrentContext = ctxName
	}
	if opts.Server != "" {
		overrides.ClusterInfo.Server = opts.Server
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	raw, err := cc.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	restCfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build client config: %w", err)
	}
	restCfg.Timeout = 30 * time.Second
	// a dead control-plane host must fail fast (default: the request
	// timeout), or every refresh stalls before the SSH collection even starts
	restCfg.Dial = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	restCfg.QPS = 50
	restCfg.Burst = 100
	// Deprecation warnings would otherwise go to stderr via klog and corrupt
	// the TUI frame.
	restCfg.WarningHandler = rest.NoWarnings{}
	st := &transportStats{}
	restCfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { return &countingTransport{rt: rt, st: st} })

	typedCfg := rest.CopyConfig(restCfg)
	if opts.Protobuf {
		typedCfg.ContentType = "application/vnd.kubernetes.protobuf"
		typedCfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	}
	cs, err := kubernetes.NewForConfig(typedCfg)
	if err != nil {
		return nil, err
	}
	// dynamic: always JSON (unstructured); metadata: protobuf-capable itself
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	md, err := metadata.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	name := ctxName
	if name == "" {
		name = raw.CurrentContext
	}
	return &Client{CS: cs, Dyn: dyn, Meta: md, Config: restCfg, Context: name, Host: restCfg.Host, Opts: opts, stats: st, configz: map[string]configzEntry{}}, nil
}

// Ping asks the apiserver for /version; the error says why it is not
// usable (connection, TLS, credentials).
func (c *Client) Ping(ctx context.Context) (string, error) {
	b, err := c.CS.Discovery().RESTClient().Get().AbsPath("/version").DoRaw(ctx)
	if err != nil {
		return "", err
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	_ = json.Unmarshal(b, &v)
	return v.GitVersion, nil
}

// Unreachable reports whether a snapshot's errors say the apiserver could
// not be reached at all (as opposed to refusing a request), which is when
// another control-plane node's apiserver is worth trying.
func Unreachable(errs []string) bool {
	for _, e := range errs {
		for _, m := range []string{"connection refused", "i/o timeout", "no route to host", "network is unreachable", "context deadline exceeded", "EOF", "connection reset", "no such host", "dial tcp"} {
			if strings.Contains(e, m) {
				return true
			}
		}
	}
	return false
}

// CheckKubeconfig reports whether a kubeconfig loads and yields a usable
// client config, without connecting.
func CheckKubeconfig(kubeconfig, ctxName string) error {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName != "" {
		overrides.CurrentContext = ctxName
	}
	_, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	return err
}
