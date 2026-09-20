package perf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoggerAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perf.jsonl")
	l, err := OpenLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(CycleRecord{Cycle: 1, At: time.Unix(1700000000, 0).UTC(), Heavy: true, LocalCPUS: 0.25, Goroutines: 12,
		Probes: []ProbeRecord{{Node: "cp-1", Kind: "etcd", WallMS: 40, RemoteCPU: 0.75, Load1: 1.5}}})
	l.Write(CycleRecord{Cycle: 2})
	l.Close()

	// a second open appends rather than truncates
	l2, err := OpenLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Write(CycleRecord{Cycle: 3})
	l2.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 records, got %d:\n%s", len(lines), b)
	}
	var r CycleRecord
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Cycle != 1 || !r.Heavy || len(r.Probes) != 1 || r.Probes[0].RemoteCPU != 0.75 {
		t.Errorf("record round trip: %+v", r)
	}
	if !strings.Contains(lines[0], `"local_cpu_s":0.25`) {
		t.Errorf("json field names: %s", lines[0])
	}

	// a nil logger is a no-op everywhere (the app runs without --perf-log)
	var none *Logger
	none.Write(CycleRecord{})
	none.Close()

	if _, err := OpenLogger(filepath.Join(t.TempDir(), "missing", "dir", "perf.jsonl")); err == nil {
		t.Errorf("opening under a missing directory should fail")
	}
}

func TestRemoteCostCPU(t *testing.T) {
	if got := (RemoteCost{User: 1.5, Sys: 0.5}).CPU(); got != 2 {
		t.Errorf("CPU() = %v, want 2", got)
	}
}
