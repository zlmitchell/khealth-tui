package k8s

import (
	"context"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CertManager is the state of cert-manager's Certificates and issuers (nil
// without its CRDs). Rancher's own ingress certificate, webhook certificates
// and app TLS often come from it, and a failed issuance stays silent until
// the certificate expires.
type CertManager struct {
	Certificates []CMCertificate
	Issuers      []CMIssuer
}

// CMCertificate is one certificates.cert-manager.io object.
type CMCertificate struct {
	Namespace, Name, Secret, Issuer string
	Ready                           bool
	Reason, Message                 string
	NotAfter, RenewalTime           time.Time
	Created                         time.Time
}

// CMIssuer is an Issuer or ClusterIssuer.
type CMIssuer struct {
	Kind, Namespace, Name string
	Ready                 bool
	Message               string
}

var (
	cmCertGVR          = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	cmIssuerGVR        = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}
	cmClusterIssuerGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}
)

// fetchCertManager lists cert-manager objects (optional: absent CRDs and
// RBAC refusals are remembered and skipped).
func (c *Client) fetchCertManager(ctx context.Context, s *Snapshot, mu *sync.Mutex, optional func(string, func() error)) {
	optional("certificates.cert-manager.io", func() error {
		l, err := c.dynList(ctx, "certificates.cert-manager.io", cmCertGVR)
		if err != nil {
			return err
		}
		cm := &CertManager{}
		for _, it := range l.Items {
			cert := CMCertificate{Namespace: it.GetNamespace(), Name: it.GetName(), Created: it.GetCreationTimestamp().Time}
			cert.Secret, _, _ = unstructured.NestedString(it.Object, "spec", "secretName")
			cert.Issuer, _, _ = unstructured.NestedString(it.Object, "spec", "issuerRef", "name")
			cert.Ready, cert.Reason, cert.Message = readyCond(it)
			if v, ok, _ := unstructured.NestedString(it.Object, "status", "notAfter"); ok {
				cert.NotAfter, _ = time.Parse(time.RFC3339, v)
			}
			if v, ok, _ := unstructured.NestedString(it.Object, "status", "renewalTime"); ok {
				cert.RenewalTime, _ = time.Parse(time.RFC3339, v)
			}
			cm.Certificates = append(cm.Certificates, cert)
		}
		for _, kind := range []struct {
			gvr  schema.GroupVersionResource
			kind string
		}{{cmIssuerGVR, "Issuer"}, {cmClusterIssuerGVR, "ClusterIssuer"}} {
			il, err := c.Dyn.Resource(kind.gvr).List(ctx, c.listOpts())
			if err != nil {
				continue
			}
			for _, it := range il.Items {
				ok, _, msg := readyCond(it)
				cm.Issuers = append(cm.Issuers, CMIssuer{Kind: kind.kind, Namespace: it.GetNamespace(), Name: it.GetName(), Ready: ok, Message: msg})
			}
		}
		mu.Lock()
		s.CertManager = cm
		mu.Unlock()
		return nil
	})
}

// readyCond reads the Ready condition of a cert-manager object.
func readyCond(it unstructured.Unstructured) (bool, string, string) {
	conds, _, _ := unstructured.NestedSlice(it.Object, "status", "conditions")
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" {
			reason, _ := m["reason"].(string)
			msg, _ := m["message"].(string)
			return m["status"] == "True", reason, msg
		}
	}
	return false, "", "no Ready condition yet"
}
