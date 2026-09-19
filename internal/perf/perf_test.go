package perf

import (
	"math"
	"testing"
)

func TestParseSection(t *testing.T) {
	// dash / busybox format
	rc := ParseSection("\n0.52 0.58 0.59 1/1234 5678\n0m0.004s 0m0.002s\n0m1.250s 0m0.750s\n")
	if !rc.Parsed || math.Abs(rc.User-1.254) > 1e-6 || math.Abs(rc.Sys-0.752) > 1e-6 || rc.Load1 != 0.52 {
		t.Fatalf("got %+v", rc)
	}
	// minutes, no loadavg
	rc = ParseSection("1m2.5s 0m0s\n0m0s 0m0s")
	if !rc.Parsed || rc.User != 62.5 || rc.Sys != 0 || rc.Load1 != -1 {
		t.Fatalf("got %+v", rc)
	}
	if rc := ParseSection(""); rc.Parsed {
		t.Fatal("empty section parsed")
	}
}

func TestSampleLocal(t *testing.T) {
	l := SampleLocal()
	if l.Goroutines < 1 || l.SysBytes == 0 || l.CPUSeconds < 0 {
		t.Fatalf("got %+v", l)
	}
}
