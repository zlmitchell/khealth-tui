// Package k8s wraps client-go and gathers a point-in-time Snapshot of the
// cluster state that the health checks and the UI consume.
package k8s

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client bundles the typed and dynamic clients for one kubeconfig context.
type Client struct {
	CS      *kubernetes.Clientset
	Dyn     dynamic.Interface
	Config  *rest.Config
	Context string
	Host    string

	mapperOnce sync.Once
	restMapper meta.RESTMapper
}

// New builds a Client from a kubeconfig path (empty = default loading rules)
// and an optional context name.
func New(kubeconfig, ctxName string) (*Client, error) {
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

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	name := ctxName
	if name == "" {
		name = raw.CurrentContext
	}
	return &Client{CS: cs, Dyn: dyn, Config: restCfg, Context: name, Host: restCfg.Host}, nil
}
