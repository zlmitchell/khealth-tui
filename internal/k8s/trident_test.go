package k8s

import (
	"context"
	"strings"
	"testing"

	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTridentBackendPools(t *testing.T) {
	// an ONTAP NAS backend with two virtual pools (gold / silver) and a
	// backend-level snapshot policy the silver pool overrides; the config
	// also carries a password that must never be copied out
	o := map[string]any{"backendName": "nas-1", "config": map[string]any{
		"storageDriverName": "ontap-nas", "backendName": "nas-1", "managementLIF": "10.1.1.1", "password": "secret", "username": "admin",
		"labels": map[string]any{"site": "dc1"}, "region": "us", "zone": "us-a",
		"defaults": map[string]any{"snapshotPolicy": "none", "exportPolicy": "default", "spaceReserve": "none", "snapshotReserve": "5"},
		"storage": []any{
			map[string]any{"labels": map[string]any{"performance": "gold"}, "defaults": map[string]any{"qosPolicy": "gold", "snapshotPolicy": "hourly"}, "zone": "us-b"},
			map[string]any{"labels": map[string]any{"performance": "silver", "site": "dc2"}},
		},
	}}
	labels, region, zone, pools := parseTridentBackendConfig(o)
	if labels["site"] != "dc1" || region != "us" || zone != "us-a" || len(pools) != 2 {
		t.Fatalf("backend: labels=%v region=%q zone=%q pools=%d", labels, region, zone, len(pools))
	}
	gold, silver := pools[0], pools[1]
	if gold.Name != "nas-1_pool_0" || gold.Labels["performance"] != "gold" || gold.Labels["site"] != "dc1" || gold.Defaults["qosPolicy"] != "gold" || gold.Defaults["snapshotPolicy"] != "hourly" || gold.Defaults["exportPolicy"] != "default" || gold.Zone != "us-b" || gold.Region != "us" {
		t.Errorf("gold pool: %+v", gold)
	}
	if silver.Name != "nas-1_pool_1" || silver.Labels["site"] != "dc2" || silver.Defaults["snapshotPolicy"] != "none" || silver.Defaults["qosPolicy"] != "" || silver.Zone != "us-a" {
		t.Errorf("silver pool: %+v", silver)
	}
	for _, p := range pools {
		for k, v := range p.Defaults {
			if strings.Contains(k, "assword") || v == "secret" || v == "10.1.1.1" {
				t.Errorf("secret leaked into pool defaults: %s=%s", k, v)
			}
		}
	}
	// no virtual pools: one pool named after the backend with the backend defaults
	_, _, _, pools = parseTridentBackendConfig(map[string]any{"config": map[string]any{"backendName": "san-1", "defaults": map[string]any{"spaceReserve": "volume"}}})
	if len(pools) != 1 || pools[0].Name != "san-1" || pools[0].Defaults["spaceReserve"] != "volume" {
		t.Errorf("physical pool: %+v", pools)
	}
}

func TestTridentLabelSelector(t *testing.T) {
	labels := map[string]string{"performance": "gold", "site": "dc1", "legacy": "true"}
	for sel, want := range map[string]bool{
		"performance=gold": true, "performance==gold": true, "performance=silver": false, "performance!=silver": true, "performance!=gold": false,
		"performance in (gold, silver)": true, "performance in (bronze)": false, "site notin (dc2,dc3)": true, "site notin (dc1)": false,
		"site": true, "protection": false, "!protection": true, "!legacy": false,
		"performance=gold; site=dc1": true, "performance=gold; site=dc2": false, "performance=gold; ": true, "garbage==": false,
	} {
		if got := labelSelectorMatch(sel, labels); got != want {
			t.Errorf("selector %q: got %v want %v", sel, got, want)
		}
	}
	if p := parsePoolsParam("nas-1:nas-1_pool_0, nas-1_pool_1; san-1"); len(p) != 2 || len(p["nas-1"]) != 2 || p["nas-1"][1] != "nas-1_pool_1" || len(p["san-1"]) != 0 {
		t.Errorf("storagePools parse: %v", p)
	}
}

func TestTridentResolveStorageClasses(t *testing.T) {
	backends := []TridentBackend{
		{BackendName: "nas-1", Driver: "ontap-nas", Online: true, State: "online", Pools: []TridentPool{
			{Name: "nas-1_pool_0", Labels: map[string]string{"performance": "gold"}, Defaults: map[string]string{"qosPolicy": "gold", "snapshotPolicy": "hourly"}},
			{Name: "nas-1_pool_1", Labels: map[string]string{"performance": "silver"}, Defaults: map[string]string{"snapshotPolicy": "none"}},
		}},
		{BackendName: "san-1", Driver: "ontap-san", Online: false, State: "offline", Pools: []TridentPool{{Name: "san-1", Labels: map[string]string{"performance": "gold"}, Defaults: map[string]string{"spaceReserve": "volume"}}}},
	}
	sc := func(name string, params map[string]string) storagev1.StorageClass {
		return storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Provisioner: "csi.trident.netapp.io", Parameters: params}
	}
	classes := []storagev1.StorageClass{
		sc("gold-nas", map[string]string{"backendType": "ontap-nas", "selector": "performance=gold"}),
		sc("any-gold", map[string]string{"selector": "performance=gold"}),
		sc("san-only", map[string]string{"backendType": "ontap-san"}),
		sc("nowhere", map[string]string{"backendType": "ontap-nas", "selector": "performance=platinum"}),
		sc("bad-pools", map[string]string{"storagePools": "nas-1:nas-1_pool_9; ghost:aggr1"}),
		sc("aggr", map[string]string{"storagePools": "san-1:aggr1"}),
		sc("unregistered", map[string]string{"backendType": "ontap-nas"}),
		{ObjectMeta: metav1.ObjectMeta{Name: "local-path"}, Provisioner: "rancher.io/local-path"},
	}
	ti := &TridentInfo{StorageClassesListed: true}
	for _, n := range []string{"gold-nas", "any-gold", "san-only", "nowhere", "bad-pools", "aggr", "orphan-tsc"} {
		ti.StorageClasses = append(ti.StorageClasses, TridentStorageClass{Name: n})
	}
	res := ti.ResolveStorageClasses(classes, backends)
	byName := map[string]TridentSCResolution{}
	for _, r := range res {
		byName[r.Name] = r
	}
	if len(res) != 7 {
		t.Fatalf("resolved %d classes, want the 7 Trident ones", len(res))
	}
	if r := byName["gold-nas"]; len(r.Matches) != 1 || r.Matches[0].Backend.BackendName != "nas-1" || len(r.Matches[0].Pools) != 1 || r.Matches[0].Pools[0].Name != "nas-1_pool_0" || r.Online() != 1 || r.Policies()["qosPolicy"] != "gold" || !r.Registered {
		t.Errorf("gold-nas: %+v", r)
	}
	if r := byName["any-gold"]; len(r.Matches) != 2 || r.Online() != 1 || r.Policies()["snapshotPolicy"] != "hourly" || r.Policies()["spaceReserve"] != "volume" {
		t.Errorf("any-gold: %+v", r)
	}
	if r := byName["san-only"]; len(r.Matches) != 1 || r.Online() != 0 {
		t.Errorf("san-only: %+v", r)
	}
	if r := byName["nowhere"]; len(r.Matches) != 0 {
		t.Errorf("nowhere: %+v", r)
	}
	if r := byName["bad-pools"]; len(r.Matches) != 0 || len(r.Problems) != 2 || !strings.Contains(r.Problems[0], "ghost") || !strings.Contains(r.Problems[1], "nas-1_pool_9") {
		t.Errorf("bad-pools: %+v", r)
	}
	if r := byName["aggr"]; len(r.Matches) != 1 || len(r.Problems) != 0 {
		t.Errorf("aggr (physical pool names are trusted): %+v", r)
	}
	if r := byName["unregistered"]; r.Registered || len(r.Matches) != 1 {
		t.Errorf("unregistered: %+v", r)
	}
	// without the TSC list nothing is called unregistered
	if r := (&TridentInfo{}).ResolveStorageClasses(classes[:1], backends); !r[0].Registered {
		t.Error("registered must default to true when the TSC list is unavailable")
	}
	if r := (*TridentInfo)(nil).ResolveStorageClasses(classes[:1], backends); !r[0].Registered {
		t.Error("nil TridentInfo")
	}
}

func TestTridentStorageClassCRs(t *testing.T) {
	f := newFakeAPI(t)
	rke2Cluster(f)
	f.mu.Lock()
	delete(f.deny, "/apis/trident.netapp.io/v1/tridentbackends")
	f.mu.Unlock()
	const gv = "trident.netapp.io/v1"
	f.set("/apis/trident.netapp.io/v1/tridentbackends", ulist(gv, "TridentBackend",
		uobj("trident", "tbe-1", map[string]any{"backendName": "nas-1", "state": "online", "online": true, "config": map[string]any{"storageDriverName": "ontap-nas", "backendName": "nas-1", "password": "x", "storage": []any{map[string]any{"labels": map[string]any{"performance": "gold"}}}}}),
	))
	f.set("/apis/trident.netapp.io/v1/tridentstorageclasses", ulist(gv, "TridentStorageClass",
		uobj("trident", "gold", map[string]any{"spec": map[string]any{"name": "gold", "attributes": map[string]any{"backendType": map[string]any{"request": "ontap-nas"}, "selector": map[string]any{"request": "performance=gold"}, "snapshots": map[string]any{"request": true}}, "storagePools": map[string]any{"nas-1": []any{"nas-1_pool_0"}}}}),
		uobj("trident", "plain", map[string]any{"spec": map[string]any{"attributes": map[string]any{"backendType": "ontap-san"}}}),
	))
	c := f.client(t, DefaultOptions())
	s := c.Fetch(context.Background())
	if len(s.TridentBackends) != 1 || len(s.TridentBackends[0].Pools) != 1 || s.TridentBackends[0].Pools[0].Labels["performance"] != "gold" {
		t.Fatalf("backend pools: %+v", s.TridentBackends)
	}
	ti := s.Trident
	if ti == nil || !ti.StorageClassesListed || len(ti.StorageClasses) != 2 {
		t.Fatalf("trident storage classes: %+v", ti)
	}
	gold := ti.StorageClasses[0]
	if gold.Name != "gold" || gold.Attributes["backendType"] != "ontap-nas" || gold.Attributes["selector"] != "performance=gold" || gold.Attributes["snapshots"] != "true" || len(gold.Pools["nas-1"]) != 1 {
		t.Errorf("gold: %+v", gold)
	}
	if plain := ti.StorageClasses[1]; plain.Name != "plain" || plain.Attributes["backendType"] != "ontap-san" {
		t.Errorf("plain: %+v", plain)
	}
}
