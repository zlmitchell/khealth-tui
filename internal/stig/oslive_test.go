package stig

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"k8s-health-tui/internal/k8s"
	"k8s-health-tui/internal/nodeinfo"
)

// Opt-in harness: run the STIG probe on a real host or container
// (go run ./tools/scriptdump -stig > p.sh; sh p.sh > out.txt), then
// KHT_PROBE_OUT=out.txt go test -v -run TestOSLive ./internal/stig/
// prints every FAIL/MANUAL result for eyeballing.
func TestOSLive(t *testing.T) {
	path := os.Getenv("KHT_PROBE_OUT")
	if path == "" {
		t.Skip()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info := nodeinfo.Parse("n1", "h", string(raw), time.Now())
	fmt.Printf("probed=%v cmd=%d sweep=%d passwd=%d shadow=%d files=%d stat=%d viol=%d\n", info.STIGProbed, len(info.STIGCmd), len(info.STIGSweep), len(info.Passwd), len(info.ShadowMeta), len(info.STIGFiles), len(info.STIGStat), len(info.STIGViol))
	rs := Evaluate(Input{Snap: &k8s.Snapshot{}, Nodes: map[string]*nodeinfo.Info{"n1": info}})
	counts := map[Status]int{}
	var fails, manuals []string
	for _, r := range rs {
		if r.Group != "os" {
			continue
		}
		counts[r.Status]++
		if r.Status == Fail && len(fails) < 400 {
			fails = append(fails, r.ID+" "+r.Title[:min(60, len(r.Title))]+" :: "+r.Detail)
		}
		if r.Status == Manual {
			manuals = append(manuals, r.ID+" :: "+r.Detail)
		}
	}
	fmt.Println("counts:", counts)
	sort.Strings(fails)
	sort.Strings(manuals)
	fmt.Println("--- FAIL")
	for _, f := range fails {
		fmt.Println(f)
	}
	fmt.Println("--- MANUAL")
	for _, m := range manuals {
		fmt.Println(m)
	}
}
