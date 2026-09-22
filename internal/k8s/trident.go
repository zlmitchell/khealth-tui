package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Trident storage classes and the backends they select. A Trident
// StorageClass names its backends through parameters (backendType,
// storagePools, additionalStoragePools, excludeStoragePools) and a label
// selector matched against the backends' virtual pools; the ONTAP policies
// a volume ends up with (snapshot, export, QoS, tiering, space reserve)
// are the defaults of the pool it landed on. Trident mirrors every
// StorageClass it accepted as a TridentStorageClass CR, so a class without
// one was rejected (bad parameters) or created while the controller was
// down.

// TridentPool is a physical or virtual storage pool of a backend: the
// labels a StorageClass selector matches and the policy defaults volumes
// inherit. Virtual pools (config.storage[]) are named <backend>_pool_<i>
// as Trident does; a backend without virtual pools has one pool named
// after the backend carrying the backend-level labels and defaults.
type TridentPool struct {
	Name     string
	Labels   map[string]string // backend labels, overridden by the pool's own
	Zone     string
	Region   string
	Defaults map[string]string // snapshotPolicy, exportPolicy, qosPolicy, adaptiveQosPolicy, tieringPolicy, spaceReserve, snapshotReserve, ...
}

// TridentStorageClass is a tridentstorageclasses.trident.netapp.io CR: the
// StorageClass as Trident accepted it.
type TridentStorageClass struct {
	Name            string
	Attributes      map[string]string   // backendType, selector, media, provisioningType, snapshots, clones, encryption, IOPS
	Pools           map[string][]string // storagePools: backend -> pools
	AdditionalPools map[string][]string
	ExcludePools    map[string][]string
}

// TridentSCMatch is what a StorageClass resolves to on one backend.
type TridentSCMatch struct {
	Backend *TridentBackend
	Pools   []TridentPool
}

// TridentSCResolution is a Trident StorageClass with the backends and pools
// its parameters select.
type TridentSCResolution struct {
	Name        string
	BackendType string
	Selector    string
	PoolsParam  string // the storagePools parameter as written
	Registered  bool   // a TridentStorageClass CR exists
	Matches     []TridentSCMatch
	Problems    []string // pool names that do not exist on the backend, backends named but absent
}

// Online counts the matched backends that are online.
func (r TridentSCResolution) Online() int {
	n := 0
	for _, m := range r.Matches {
		if m.Backend.Online && (m.Backend.State == "" || m.Backend.State == "online") {
			n++
		}
	}
	return n
}

// Policies summarizes the policy defaults of the matched pools: one value
// per key when every pool agrees, "a|b" when they differ.
func (r TridentSCResolution) Policies() map[string]string {
	vals := map[string]map[string]bool{}
	for _, m := range r.Matches {
		for _, p := range m.Pools {
			for k, v := range p.Defaults {
				if vals[k] == nil {
					vals[k] = map[string]bool{}
				}
				vals[k][v] = true
			}
		}
	}
	out := map[string]string{}
	for k, set := range vals {
		var vs []string
		for v := range set {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		out[k] = strings.Join(vs, "|")
	}
	return out
}

var (
	tridentStorageClassGVR = schema.GroupVersionResource{Group: "trident.netapp.io", Version: "v1", Resource: "tridentstorageclasses"}

	// tridentPolicyKeys are the pool defaults worth showing (no credentials,
	// no LIFs): what a provisioned volume inherits.
	tridentPolicyKeys = []string{"snapshotPolicy", "exportPolicy", "qosPolicy", "adaptiveQosPolicy", "tieringPolicy", "spaceReserve", "snapshotReserve", "snapshotDir", "securityStyle", "unixPermissions", "encryption", "splitOnClone", "spaceAllocation"}

	selEq       = regexp.MustCompile(`^([\w-]+)\s*={1,2}\s*([\w-]+)$`)
	selNotEq    = regexp.MustCompile(`^([\w-]+)\s*!=\s*([\w-]+)$`)
	selIn       = regexp.MustCompile(`^([\w-]+)\s+in\s+\(([\s\w,-]+)\)$`)
	selNotIn    = regexp.MustCompile(`^([\w-]+)\s+notin\s+\(([\s\w,-]+)\)$`)
	selExists   = regexp.MustCompile(`^([\w-]+)$`)
	selNotExist = regexp.MustCompile(`^!([\w-]+)$`)
)

// tridentBackendCfg returns the driver config of a TridentBackend CR.
// Trident persists BackendPersistent.Config, a union that wraps the config
// in a driver-specific key (ontap_config, solidfire_config, azure_config,
// ...), so unwrap that when the fields are not at the top level - without
// it the driver name and the pools are simply missing and every
// StorageClass resolves to no backend.
func tridentBackendCfg(o map[string]any) map[string]any {
	cfg, _, _ := unstructured.NestedMap(o, "config")
	if _, ok := cfg["storageDriverName"]; ok {
		return cfg
	}
	for k, v := range cfg {
		if m, ok := v.(map[string]any); ok && strings.HasSuffix(k, "_config") {
			return m
		}
	}
	return cfg
}

// parseTridentBackendConfig reads the non-secret parts of a TridentBackend
// config: labels, region/zone, policy defaults and the virtual pools.
func parseTridentBackendConfig(cfg map[string]any) (labels map[string]string, region, zone string, pools []TridentPool) {
	if cfg == nil {
		return nil, "", "", nil
	}
	backendName, _ := cfg["backendName"].(string)
	labels = stringMap(cfg["labels"])
	region, _ = cfg["region"].(string)
	zone, _ = cfg["zone"].(string)
	base := policyDefaults(cfg["defaults"])
	storage, _ := cfg["storage"].([]any)
	for i, s := range storage {
		sm, _ := s.(map[string]any)
		if sm == nil {
			continue
		}
		p := TridentPool{Name: fmt.Sprintf("%s_pool_%d", backendName, i), Labels: map[string]string{}, Defaults: map[string]string{}}
		for k, v := range labels {
			p.Labels[k] = v
		}
		for k, v := range stringMap(sm["labels"]) {
			p.Labels[k] = v
		}
		for k, v := range base {
			p.Defaults[k] = v
		}
		for k, v := range policyDefaults(sm["defaults"]) {
			p.Defaults[k] = v
		}
		p.Region, _ = sm["region"].(string)
		p.Zone, _ = sm["zone"].(string)
		if p.Region == "" {
			p.Region = region
		}
		if p.Zone == "" {
			p.Zone = zone
		}
		pools = append(pools, p)
	}
	if len(pools) == 0 {
		pools = []TridentPool{{Name: backendName, Labels: labels, Region: region, Zone: zone, Defaults: base}}
	}
	return labels, region, zone, pools
}

func policyDefaults(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for _, k := range tridentPolicyKeys {
		if s, ok := m[k].(string); ok && s != "" {
			out[k] = s
		}
	}
	return out
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for k, x := range m {
		switch s := x.(type) {
		case string:
			out[k] = s
		default:
			out[k] = fmt.Sprint(s)
		}
	}
	return out
}

// tridentStorageClasses lists the TridentStorageClass CRs. ok is false
// when the list could not be made (denied or absent), so callers do not
// mistake that for "Trident accepted no class".
func (c *Client) tridentStorageClasses(ctx context.Context) (out []TridentStorageClass, ok bool) {
	l, err := c.dynList(ctx, "tridentstorageclasses.trident.netapp.io", tridentStorageClassGVR)
	if err != nil {
		return nil, false
	}
	for _, it := range l.Items {
		sc := TridentStorageClass{Name: it.GetName(), Attributes: map[string]string{}}
		spec, _, _ := unstructured.NestedMap(it.Object, "spec")
		if n, _ := spec["name"].(string); n != "" {
			sc.Name = n
		}
		// attributes marshal as {"request": <value>} (storageattribute.Request); older objects hold plain values
		if attrs, _ := spec["attributes"].(map[string]any); attrs != nil {
			for k, v := range attrs {
				if m, ok := v.(map[string]any); ok {
					if r, ok := m["request"]; ok {
						v = r
					}
				}
				switch x := v.(type) {
				case string:
					sc.Attributes[k] = x
				case bool:
					sc.Attributes[k] = strconv.FormatBool(x)
				case float64:
					sc.Attributes[k] = strconv.FormatInt(int64(x), 10)
				case int64:
					sc.Attributes[k] = strconv.FormatInt(x, 10)
				default:
					b, _ := json.Marshal(x)
					sc.Attributes[k] = string(b)
				}
			}
		}
		sc.Pools = poolMap(spec["storagePools"])
		sc.AdditionalPools = poolMap(spec["additionalStoragePools"])
		sc.ExcludePools = poolMap(spec["excludeStoragePools"])
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, true
}

func poolMap(v any) map[string][]string {
	m, _ := v.(map[string]any)
	if m == nil {
		return nil
	}
	out := map[string][]string{}
	for k, x := range m {
		l, _ := x.([]any)
		for _, p := range l {
			if s, ok := p.(string); ok {
				out[k] = append(out[k], s)
			}
		}
		if out[k] == nil {
			out[k] = []string{}
		}
	}
	return out
}

// parsePoolsParam reads the storagePools StorageClass parameter
// ("backend1:pool1,pool2;backend2:pool3" - a backend without pools means
// all of its pools).
func parsePoolsParam(s string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		backend, pools, _ := strings.Cut(part, ":")
		backend = strings.TrimSpace(backend)
		out[backend] = []string{}
		for _, p := range strings.Split(pools, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out[backend] = append(out[backend], p)
			}
		}
	}
	return out
}

// labelSelectorMatch evaluates a Trident selector ("performance=gold;
// !legacy; tier in (a,b)") against pool labels. Unparseable terms match
// nothing, as Trident rejects the class in that case.
func labelSelectorMatch(selector string, labels map[string]string) bool {
	for _, term := range strings.Split(selector, ";") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		switch {
		case selEq.MatchString(term):
			m := selEq.FindStringSubmatch(term)
			if v, ok := labels[m[1]]; !ok || v != m[2] {
				return false
			}
		case selNotEq.MatchString(term):
			m := selNotEq.FindStringSubmatch(term)
			if v, ok := labels[m[1]]; ok && v == m[2] {
				return false
			}
		case selIn.MatchString(term), selNotIn.MatchString(term):
			in := selIn.MatchString(term)
			var m []string
			if in {
				m = selIn.FindStringSubmatch(term)
			} else {
				m = selNotIn.FindStringSubmatch(term)
			}
			v, ok := labels[m[1]]
			found := false
			for _, x := range strings.Split(m[2], ",") {
				if ok && strings.TrimSpace(x) == v {
					found = true
				}
			}
			if in && !found || !in && found {
				return false
			}
		case selNotExist.MatchString(term):
			if _, ok := labels[selNotExist.FindStringSubmatch(term)[1]]; ok {
				return false
			}
		case selExists.MatchString(term):
			if _, ok := labels[term]; !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ResolveStorageClasses works out, for every StorageClass provisioned by
// Trident, which backends and pools its parameters select and whether
// Trident registered it.
func (ti *TridentInfo) ResolveStorageClasses(classes []storagev1.StorageClass, backends []TridentBackend) []TridentSCResolution {
	var out []TridentSCResolution
	registered := map[string]bool{}
	if ti != nil {
		for _, sc := range ti.StorageClasses {
			registered[sc.Name] = true
		}
	}
	for i := range classes {
		sc := &classes[i]
		if sc.Provisioner != "csi.trident.netapp.io" && sc.Provisioner != "netapp.io/trident" {
			continue
		}
		p := sc.Parameters
		r := TridentSCResolution{Name: sc.Name, BackendType: p["backendType"], Selector: p["selector"], PoolsParam: p["storagePools"], Registered: registered[sc.Name] || ti == nil || !ti.StorageClassesListed}
		want := parsePoolsParam(p["storagePools"])
		for b, pools := range parsePoolsParam(p["additionalStoragePools"]) {
			want[b] = append(want[b], pools...)
		}
		exclude := parsePoolsParam(p["excludeStoragePools"])
		byName := map[string]*TridentBackend{}
		for j := range backends {
			byName[backends[j].BackendName] = &backends[j]
		}
		for b := range want {
			if byName[b] == nil {
				r.Problems = append(r.Problems, "backend "+b+" (storagePools) does not exist")
			}
		}
		for j := range backends {
			b := &backends[j]
			if r.BackendType != "" && !strings.EqualFold(b.Driver, r.BackendType) {
				continue
			}
			wantPools, named := want[b.BackendName]
			if len(want) > 0 && !named {
				continue
			}
			var pools []TridentPool
			for _, pool := range b.Pools {
				if len(wantPools) > 0 && !slices.Contains(wantPools, pool.Name) {
					continue
				}
				if ex, ok := exclude[b.BackendName]; ok && (len(ex) == 0 || slices.Contains(ex, pool.Name)) {
					continue
				}
				if r.Selector != "" && !labelSelectorMatch(r.Selector, pool.Labels) {
					continue
				}
				pools = append(pools, pool)
			}
			for _, wp := range wantPools {
				known := false
				for _, pool := range b.Pools {
					if pool.Name == wp {
						known = true
					}
				}
				// physical pools (aggregates) are not in the CR: only virtual pool names can be checked
				if !known && strings.Contains(wp, "_pool_") {
					r.Problems = append(r.Problems, "pool "+wp+" is not a virtual pool of backend "+b.BackendName)
				}
				if !known && len(b.Pools) == 1 && b.Pools[0].Name == b.BackendName {
					pools = b.Pools // aggregate names: trust them
				}
			}
			if len(pools) > 0 {
				r.Matches = append(r.Matches, TridentSCMatch{Backend: b, Pools: pools})
			}
		}
		sort.Strings(r.Problems)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
