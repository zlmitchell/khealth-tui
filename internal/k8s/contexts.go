package k8s

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ContextInfo is a kubeconfig context khealth can switch to.
type ContextInfo struct {
	Name    string
	Cluster string
	Server  string
	File    string // "" = the configured kubeconfig / KUBECONFIG chain; else the file that holds it (bootstrapped khealth-*.yaml)
	Current bool
	SSH     SSHHint // how khealth reached this cluster's nodes last time (context extension "khealth")
}

// SSHHint is what khealth remembers about a cluster in the kubeconfig
// context itself (extension "khealth"): the SSH user/key/port/escalation
// and the node it was bootstrapped from. Never a password.
type SSHHint struct {
	User         string `json:"ssh-user,omitempty"`
	Key          string `json:"ssh-key,omitempty"`
	Port         int    `json:"ssh-port,omitempty"`
	Become       string `json:"become,omitempty"`
	Host         string `json:"bootstrap-host,omitempty"`
	Node         string `json:"bootstrap-node,omitempty"` // the node Host is an address of (its hostname): dial that node there, whatever the node object says
	Bootstrapped string `json:"bootstrapped,omitempty"`   // RFC 3339
}

// Empty reports whether the hint carries nothing worth applying.
func (h SSHHint) Empty() bool {
	return h.User == "" && h.Key == "" && h.Port == 0 && h.Become == "" && h.Host == ""
}

const hintExtension = "khealth"

// SetSSHHint stores the hint on a context of a kubeconfig.
func SetSSHHint(cfg *clientcmdapi.Config, ctxName string, h SSHHint) {
	ctx := cfg.Contexts[ctxName]
	if ctx == nil {
		return
	}
	b, err := json.Marshal(h)
	if err != nil {
		return
	}
	if ctx.Extensions == nil {
		ctx.Extensions = map[string]runtime.Object{}
	}
	ctx.Extensions[hintExtension] = &runtime.Unknown{Raw: b, ContentType: runtime.ContentTypeJSON}
}

// GetSSHHint reads the hint stored on a context.
func GetSSHHint(ctx *clientcmdapi.Context) SSHHint {
	var h SSHHint
	if ctx == nil {
		return h
	}
	if u, ok := ctx.Extensions[hintExtension].(*runtime.Unknown); ok && len(u.Raw) > 0 {
		_ = json.Unmarshal(u.Raw, &h)
	}
	return h
}

// Contexts lists the contexts of the configured kubeconfig (or the
// KUBECONFIG chain / ~/.kube/config) plus those in the files an earlier
// `khealth user@host` bootstrap wrote under ~/.kube (khealth-*.yaml), so a
// cluster reached once stays one keypress away.
func Contexts(kubeconfig, current string) []ContextInfo {
	var out []ContextInfo
	seen := map[string]bool{}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	if raw, err := rules.Load(); err == nil {
		cur := current
		if cur == "" {
			cur = raw.CurrentContext
		}
		for name, c := range raw.Contexts {
			ci := ContextInfo{Name: name, Cluster: c.Cluster, Current: name == cur, SSH: GetSSHHint(c)}
			if cl := raw.Clusters[c.Cluster]; cl != nil {
				ci.Server = cl.Server
			}
			out = append(out, ci)
			seen[name+"\x00"+ci.Server] = true
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		files, _ := filepath.Glob(filepath.Join(home, ".kube", "khealth-*.yaml"))
		for _, f := range files {
			if f == kubeconfig {
				continue
			}
			raw, err := clientcmd.LoadFromFile(f)
			if err != nil {
				continue
			}
			for name, c := range raw.Contexts {
				ci := ContextInfo{Name: name, Cluster: c.Cluster, File: f, SSH: GetSSHHint(c)}
				if cl := raw.Clusters[c.Cluster]; cl != nil {
					ci.Server = cl.Server
				}
				if seen[name+"\x00"+ci.Server] {
					continue
				}
				seen[name+"\x00"+ci.Server] = true
				out = append(out, ci)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Current != out[j].Current {
			return out[i].Current
		}
		return out[i].Name < out[j].Name
	})
	return out
}
