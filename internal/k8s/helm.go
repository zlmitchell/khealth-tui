package k8s

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

// HelmRelease is a decoded Helm v3 release (latest revision only).
type HelmRelease struct {
	Namespace   string
	Name        string
	Revision    int
	Status      string
	Chart       string
	Version     string
	AppVersion  string
	Updated     time.Time
	Description string
	ValuesYAML  string // user-supplied values (helm get values)
	Storage     string // secret | configmap
	Bundled     bool   // installed by rke2/k3s HelmChart controller
	History     []HelmRevision
}

// HelmRevision is one entry of a release's history (newest first).
type HelmRevision struct {
	Revision    int
	Status      string
	Chart       string
	Version     string
	AppVersion  string
	Updated     time.Time
	Description string
}

type helmReleaseJSON struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   int    `json:"version"`
	Info      struct {
		Status       string    `json:"status"`
		LastDeployed time.Time `json:"last_deployed"`
		Description  string    `json:"description"`
	} `json:"info"`
	Chart struct {
		Metadata struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			AppVersion string `json:"appVersion"`
		} `json:"metadata"`
	} `json:"chart"`
	Config map[string]any `json:"config"`
}

func (c *Client) helmReleases(ctx context.Context) ([]HelmRelease, error) {
	latest := map[string]HelmRelease{}
	history := map[string][]HelmRevision{}
	secrets, err := c.CS.CoreV1().Secrets("").List(ctx, metav1.ListOptions{FieldSelector: "type=helm.sh/release.v1"})
	if err != nil {
		return nil, err
	}
	for _, sec := range secrets.Items {
		rel, err := decodeHelmRelease(sec.Data["release"])
		if err != nil {
			continue
		}
		rel.Storage = "secret"
		rel.Namespace = sec.Namespace
		key := rel.Namespace + "/" + rel.Name
		history[key] = append(history[key], HelmRevision{Revision: rel.Revision, Status: rel.Status, Chart: rel.Chart, Version: rel.Version, AppVersion: rel.AppVersion, Updated: rel.Updated, Description: rel.Description})
		if cur, ok := latest[key]; !ok || rel.Revision > cur.Revision {
			latest[key] = rel
		}
	}
	// releases stored in configmaps (HELM_DRIVER=configmap)
	if cms, err := c.CS.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{LabelSelector: "owner=helm"}); err == nil {
		for _, cm := range cms.Items {
			raw, ok := cm.Data["release"]
			if !ok {
				continue
			}
			rel, err := decodeHelmRelease([]byte(raw))
			if err != nil {
				continue
			}
			rel.Storage = "configmap"
			rel.Namespace = cm.Namespace
			key := rel.Namespace + "/" + rel.Name
			history[key] = append(history[key], HelmRevision{Revision: rel.Revision, Status: rel.Status, Chart: rel.Chart, Version: rel.Version, AppVersion: rel.AppVersion, Updated: rel.Updated, Description: rel.Description})
			if cur, ok := latest[key]; !ok || rel.Revision > cur.Revision {
				latest[key] = rel
			}
		}
	}
	// releases installed by the rke2/k3s HelmChart controller carry the CR name
	bundled := map[string]bool{}
	if l, err := c.Dyn.Resource(helmChartGVR).List(ctx, metav1.ListOptions{}); err == nil {
		for _, it := range l.Items {
			ns, _, _ := unstructured.NestedString(it.Object, "spec", "targetNamespace")
			if ns == "" {
				ns = it.GetNamespace()
			}
			bundled[ns+"/"+it.GetName()] = true
		}
	}
	out := make([]HelmRelease, 0, len(latest))
	for key, r := range latest {
		h := history[key]
		sort.Slice(h, func(i, j int) bool { return h[i].Revision > h[j].Revision })
		r.History = h
		r.Bundled = bundled[key]
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+out[i].Name < out[j].Namespace+out[j].Name })
	return out, nil
}

// decodeHelmRelease decodes the "release" payload: base64(gzip(json)).
// The secret Data value is already base64-decoded once by the API client, but
// Helm base64-encodes the gzip blob a second time.
func decodeHelmRelease(data []byte) (HelmRelease, error) {
	if len(data) == 0 {
		return HelmRelease{}, fmt.Errorf("empty release")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		b = data
	}
	if len(b) > 3 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return HelmRelease{}, err
		}
		defer zr.Close()
		b, err = io.ReadAll(zr)
		if err != nil {
			return HelmRelease{}, err
		}
	}
	var rj helmReleaseJSON
	if err := json.Unmarshal(b, &rj); err != nil {
		return HelmRelease{}, err
	}
	rel := HelmRelease{
		Name:        rj.Name,
		Namespace:   rj.Namespace,
		Revision:    rj.Version,
		Status:      rj.Info.Status,
		Chart:       rj.Chart.Metadata.Name,
		Version:     rj.Chart.Metadata.Version,
		AppVersion:  rj.Chart.Metadata.AppVersion,
		Updated:     rj.Info.LastDeployed,
		Description: rj.Info.Description,
	}
	if len(rj.Config) > 0 {
		if y, err := yaml.Marshal(rj.Config); err == nil {
			rel.ValuesYAML = string(y)
		}
	}
	return rel, nil
}
