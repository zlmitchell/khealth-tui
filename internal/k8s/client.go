// Package k8s wraps client-go and gathers a point-in-time Snapshot of the
// cluster state that the health checks and the UI consume.
package k8s

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// DiscoveryTTL caches API discovery + CRD definitions (large, static)
	// and ConfigzTTL the per-node kubelet configz; 0 fetches every cycle.
	DiscoveryTTL time.Duration
	ConfigzTTL   time.Duration
}

// DefaultOptions are what khealth uses unless configured otherwise.
func DefaultOptions() Options {
	return Options{WatchCache: true, Protobuf: true, DiscoveryTTL: 5 * time.Minute, ConfigzTTL: 10 * time.Minute}
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
