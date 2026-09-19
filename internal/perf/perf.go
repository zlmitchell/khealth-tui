// Package perf measures the footprint khealth itself has on the systems it
// inspects: remote CPU consumed by the SSH probes (POSIX `times`), API
// server traffic (requests/bytes per refresh) and the local process (CPU
// seconds, heap, goroutines). Nothing here talks to the network; it parses
// what the probes and the HTTP transport already produce.
package perf

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Footer is appended to every script sent over SSH (see ScriptFooter). It
// prints the load average after the probe and the CPU the shell and its
// children used, in the format of the POSIX `times` builtin.
const Footer = "\nsec PERF\ncat /proc/loadavg 2>/dev/null\ntimes\n"

// RemoteCost is what one probe cost the node, parsed from the PERF section.
type RemoteCost struct {
	User, Sys float64 // CPU seconds used by the script and everything it ran
	Load1     float64 // 1-minute load average when the script finished (-1 = unknown)
	Parsed    bool
}

// CPU returns user+sys seconds.
func (r RemoteCost) CPU() float64 { return r.User + r.Sys }

// timesRe matches one field of `times` output: "0m1.234s", "1m2s", "0.12".
var timesRe = regexp.MustCompile(`(?:(\d+)m)?(\d+(?:\.\d+)?)s?`)

func timesField(s string) float64 {
	m := timesRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0
	}
	min, _ := strconv.ParseFloat(m[1], 64)
	sec, _ := strconv.ParseFloat(m[2], 64)
	return min*60 + sec
}

// ParseSection parses the PERF section: an optional /proc/loadavg line
// followed by the two lines of `times` (shell, then children).
func ParseSection(sec string) RemoteCost {
	rc := RemoteCost{Load1: -1}
	var timesLines []string
	for _, l := range strings.Split(sec, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		f := strings.Fields(l)
		// loadavg: "0.52 0.58 0.59 1/1234 5678"
		if len(f) == 5 && strings.Contains(f[3], "/") {
			rc.Load1, _ = strconv.ParseFloat(f[0], 64)
			continue
		}
		if len(f) == 2 {
			timesLines = append(timesLines, l)
		}
	}
	for _, l := range timesLines {
		f := strings.Fields(l)
		rc.User += timesField(f[0])
		rc.Sys += timesField(f[1])
		rc.Parsed = true
	}
	return rc
}

// Local is a sample of this process.
type Local struct {
	CPUSeconds float64 // total CPU consumed by the process since start (user+sys, all threads)
	HeapBytes  uint64
	SysBytes   uint64 // memory obtained from the OS
	Goroutines int
	At         time.Time
}

var localSamples = []metrics.Sample{
	{Name: "/cpu/classes/total:cpu-seconds"},
	{Name: "/cpu/classes/idle:cpu-seconds"},
	{Name: "/memory/classes/heap/objects:bytes"},
	{Name: "/memory/classes/total:bytes"},
}

// SampleLocal reads the runtime metrics. Works on every platform (no
// getrusage): CPU is the Go runtime's own accounting of its threads, which
// includes GC and the cgo-free network poller - i.e. the whole process.
func SampleLocal() Local {
	s := make([]metrics.Sample, len(localSamples))
	copy(s, localSamples)
	metrics.Read(s)
	l := Local{Goroutines: runtime.NumGoroutine(), At: time.Now()}
	if s[0].Value.Kind() == metrics.KindFloat64 {
		l.CPUSeconds = s[0].Value.Float64()
		if s[1].Value.Kind() == metrics.KindFloat64 {
			// "total" counts idle Ps too (GOMAXPROCS threads parked); subtract
			l.CPUSeconds -= s[1].Value.Float64()
		}
	}
	if s[2].Value.Kind() == metrics.KindUint64 {
		l.HeapBytes = s[2].Value.Uint64()
	}
	if s[3].Value.Kind() == metrics.KindUint64 {
		l.SysBytes = s[3].Value.Uint64()
	}
	return l
}

// ProbeRecord is one SSH probe in a cycle record.
type ProbeRecord struct {
	Node       string  `json:"node"`
	Kind       string  `json:"kind"` // node | node+heavy | node+stig | etcd | s3
	WallMS     int64   `json:"wall_ms"`
	RemoteCPU  float64 `json:"remote_cpu_s"`
	RemoteUser float64 `json:"remote_user_s"`
	RemoteSys  float64 `json:"remote_sys_s"`
	Load1      float64 `json:"load1"`
	OutBytes   int     `json:"out_bytes"`
	ScriptSize int     `json:"script_bytes"`
	Err        string  `json:"err,omitempty"`
	Skipped    string  `json:"skipped,omitempty"` // reason when the probe was not run this cycle
}

// APIRecord is the API server traffic of one refresh.
type APIRecord struct {
	FetchMS  int64 `json:"fetch_ms"`
	Requests int64 `json:"requests"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	Errors   int   `json:"errors"`
	Pods     int   `json:"pods"`
	Nodes    int   `json:"nodes"`
	Events   int   `json:"events"`
}

// CycleRecord is one line of the perf log.
type CycleRecord struct {
	Cycle       int           `json:"cycle"`
	At          time.Time     `json:"at"`
	Heavy       bool          `json:"heavy"`
	API         APIRecord     `json:"api"`
	Probes      []ProbeRecord `json:"probes"`
	LocalCPUS   float64       `json:"local_cpu_s"` // CPU seconds this process used during the cycle
	LocalHeap   uint64        `json:"local_heap_bytes"`
	LocalSys    uint64        `json:"local_sys_bytes"`
	Goroutines  int           `json:"goroutines"`
	Recomputes  int           `json:"recomputes"`
	RecomputeMS int64         `json:"recompute_ms"`
}

// Logger appends CycleRecords as JSON lines.
type Logger struct {
	mu sync.Mutex
	w  io.WriteCloser
}

// OpenLogger opens (appends to) the perf log file.
func OpenLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{w: f}, nil
}

// Write appends one record.
func (l *Logger) Write(r CycleRecord) {
	if l == nil {
		return
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	l.mu.Lock()
	_, _ = l.w.Write(append(b, '\n'))
	l.mu.Unlock()
}

// Close closes the file.
func (l *Logger) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	_ = l.w.Close()
	l.mu.Unlock()
}
