package k8s

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Control-plane plumbing that can stop a whole cluster while every node and
// pod looks fine: admission webhooks that fail closed with nothing behind
// them, aggregated APIs that do not answer (namespace deletion and the
// garbage collector need discovery), certificate requests nobody approves,
// disruption budgets that block every drain, and Services with no ready
// endpoint. Each list is optional: a token without the RBAC just leaves it
// empty.

// Webhook is one entry of a Validating/MutatingWebhookConfiguration,
// reduced to what decides whether it can block the cluster.
type Webhook struct {
	Config, Name   string
	Mutating       bool
	FailClosed     bool   // failurePolicy Fail (the default when unset)
	ServiceNS      string // "" for a URL webhook
	ServiceName    string
	Resources      []string // resources the rules match, as written ("pods", "pods/exec", "*", "deployments")
	SkipsKubeSys   bool     // the namespaceSelector excludes kube-system
	TimeoutSeconds int32
	CAExpires      time.Time // earliest notAfter in caBundle (zero when none)
}

// APIService is one aggregated API registration.
type APIService struct {
	Name      string
	Local     bool // served by the apiserver itself (no service)
	Available bool
	Reason    string
	Message   string
	Service   string // namespace/name
}

// CSR is a CertificateSigningRequest's state.
type CSR struct {
	Name, Signer, Requestor string
	Created                 time.Time
	Pending                 bool // neither approved nor denied
}

var apiServiceGVR = schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}

// fetchControl adds the lists above to s; optional runs one call in the
// fetch's worker group and remembers RBAC refusals.
func (c *Client) fetchControl(ctx context.Context, s *Snapshot, mu *sync.Mutex, optional func(string, func() error)) {
	cs := c.CS
	all := c.listOpts()
	c.cacheMu.Lock()
	whFresh, csrFresh := time.Since(c.webhooksAt) < c.Opts.DiscoveryTTL, time.Since(c.csrsAt) < c.Opts.DiscoveryTTL
	if whFresh {
		s.Webhooks = c.webhooks
	}
	if csrFresh {
		s.CSRs = c.csrs
	}
	c.cacheMu.Unlock()
	if !whFresh {
		optional("webhookconfigurations", func() error {
			var out []Webhook
			vl, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, all)
			if err != nil {
				return err
			}
			for _, cfg := range vl.Items {
				for _, w := range cfg.Webhooks {
					out = append(out, webhookOf(cfg.Name, false, w.FailurePolicy, w.ClientConfig, w.Rules, w.NamespaceSelector, w.TimeoutSeconds, w.Name))
				}
			}
			ml, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, all)
			if err != nil {
				return err
			}
			for _, cfg := range ml.Items {
				for _, w := range cfg.Webhooks {
					out = append(out, webhookOf(cfg.Name, true, w.FailurePolicy, w.ClientConfig, w.Rules, w.NamespaceSelector, w.TimeoutSeconds, w.Name))
				}
			}
			mu.Lock()
			s.Webhooks = out
			mu.Unlock()
			c.cacheMu.Lock()
			c.webhooks, c.webhooksAt = out, time.Now()
			c.cacheMu.Unlock()
			return nil
		})
	}
	optional("endpointslices", func() error {
		l, err := cs.DiscoveryV1().EndpointSlices("").List(ctx, all)
		if err != nil {
			return err
		}
		ready := map[string]int{}
		for _, es := range l.Items {
			svc := es.Labels["kubernetes.io/service-name"]
			if svc == "" {
				continue
			}
			key := es.Namespace + "/" + svc
			if _, seen := ready[key]; !seen {
				ready[key] = 0 // the Service has slices, even if none is ready
			}
			for _, ep := range es.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					ready[key]++
				}
			}
		}
		mu.Lock()
		s.ServiceReady = ready
		mu.Unlock()
		return nil
	})
	optional("apiservices", func() error {
		l, err := c.dynList(ctx, "apiservices", apiServiceGVR)
		if err != nil {
			return err
		}
		var out []APIService
		for _, it := range l.Items {
			out = append(out, apiServiceOf(it))
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		mu.Lock()
		s.APIServices = out
		mu.Unlock()
		return nil
	})
	if !csrFresh {
		optional("certificatesigningrequests", func() error {
			l, err := cs.CertificatesV1().CertificateSigningRequests().List(ctx, all)
			if err != nil {
				return err
			}
			var out []CSR
			for _, r := range l.Items {
				out = append(out, CSR{Name: r.Name, Signer: r.Spec.SignerName, Requestor: r.Spec.Username, Created: r.CreationTimestamp.Time, Pending: csrPending(r)})
			}
			mu.Lock()
			s.CSRs = out
			mu.Unlock()
			c.cacheMu.Lock()
			c.csrs, c.csrsAt = out, time.Now()
			c.cacheMu.Unlock()
			return nil
		})
	}
	optional("poddisruptionbudgets", func() error {
		l, err := cs.PolicyV1().PodDisruptionBudgets("").List(ctx, all)
		if err != nil {
			return err
		}
		mu.Lock()
		s.PDBs = l.Items
		mu.Unlock()
		return nil
	})
}

func webhookOf(cfg string, mutating bool, fp *admissionv1.FailurePolicyType, cc admissionv1.WebhookClientConfig, rules []admissionv1.RuleWithOperations, nsSel *metav1.LabelSelector, timeout *int32, name string) Webhook {
	w := Webhook{Config: cfg, Name: name, Mutating: mutating, FailClosed: fp == nil || *fp == admissionv1.Fail, TimeoutSeconds: 10}
	if timeout != nil {
		w.TimeoutSeconds = *timeout
	}
	if cc.Service != nil {
		w.ServiceNS, w.ServiceName = cc.Service.Namespace, cc.Service.Name
	}
	for _, r := range rules {
		w.Resources = append(w.Resources, r.Resources...)
	}
	if nsSel != nil {
		for _, e := range nsSel.MatchExpressions {
			if e.Key == "kubernetes.io/metadata.name" && e.Operator == metav1.LabelSelectorOpNotIn {
				for _, v := range e.Values {
					if v == "kube-system" {
						w.SkipsKubeSys = true
					}
				}
			}
		}
		// a selector that requires a label kube-system does not carry also skips it
		if len(nsSel.MatchLabels) > 0 {
			w.SkipsKubeSys = true
		}
	}
	rest := cc.CABundle
	for len(rest) > 0 {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if cert, err := x509.ParseCertificate(b.Bytes); err == nil && (w.CAExpires.IsZero() || cert.NotAfter.Before(w.CAExpires)) {
			w.CAExpires = cert.NotAfter
		}
	}
	return w
}

func apiServiceOf(it unstructured.Unstructured) APIService {
	a := APIService{Name: it.GetName(), Local: true, Available: true}
	if ns, ok, _ := unstructured.NestedString(it.Object, "spec", "service", "namespace"); ok && ns != "" {
		name, _, _ := unstructured.NestedString(it.Object, "spec", "service", "name")
		a.Service, a.Local = ns+"/"+name, false
	}
	conds, _, _ := unstructured.NestedSlice(it.Object, "status", "conditions")
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Available" {
			a.Available = m["status"] == "True"
			a.Reason, _ = m["reason"].(string)
			a.Message, _ = m["message"].(string)
		}
	}
	return a
}

func csrPending(r certificatesv1.CertificateSigningRequest) bool {
	for _, c := range r.Status.Conditions {
		if c.Type == certificatesv1.CertificateApproved || c.Type == certificatesv1.CertificateDenied || c.Type == certificatesv1.CertificateFailed {
			return false
		}
	}
	return true
}
