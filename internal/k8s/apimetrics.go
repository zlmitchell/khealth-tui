package k8s

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIMetrics is what khealth reads from the answering apiserver's /metrics:
// API Priority & Fairness rejections (429s) and the object count per
// resource in storage. The page is 10 MB and more, so it is read at most
// every apiMetricsTTL and streamed: only the two families are kept.
type APIMetrics struct {
	At       time.Time
	Rejected map[string]float64 // "priority_level|reason" -> rejected requests since the apiserver started
	// RejectedNew is the growth since the previous scrape (nil on the first
	// scrape: nothing to compare with yet)
	RejectedNew map[string]float64
	Since       time.Duration      // window RejectedNew covers
	Objects     map[string]float64 // resource -> objects in storage
}

const apiMetricsTTL = 15 * time.Minute

// fetchAPIMetrics fills s.APIMetrics from the cache or a new scrape.
func (c *Client) fetchAPIMetrics(ctx context.Context, s *Snapshot, mu *sync.Mutex, optional func(string, func() error)) {
	c.cacheMu.Lock()
	cached := c.apiMetrics
	c.cacheMu.Unlock()
	if cached != nil && time.Since(cached.At) < apiMetricsTTL {
		s.APIMetrics = cached
		return
	}
	optional("apiserver /metrics", func() error {
		rc, err := c.CS.CoreV1().RESTClient().Get().AbsPath("/metrics").Stream(ctx)
		if err != nil {
			return err
		}
		defer rc.Close()
		m := &APIMetrics{At: time.Now(), Rejected: map[string]float64{}, Objects: map[string]float64{}}
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			l := sc.Text()
			switch {
			case strings.HasPrefix(l, "apiserver_flowcontrol_rejected_requests_total{"):
				if v, ok := metricValue(l); ok {
					m.Rejected[label(l, "priority_level")+"|"+label(l, "reason")] += v
				}
			case strings.HasPrefix(l, "apiserver_storage_objects{"):
				if v, ok := metricValue(l); ok {
					m.Objects[label(l, "resource")] = v
				}
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		if cached != nil {
			m.RejectedNew, m.Since = map[string]float64{}, m.At.Sub(cached.At)
			for k, v := range m.Rejected {
				if d := v - cached.Rejected[k]; d > 0 {
					m.RejectedNew[k] = d
				}
			}
		}
		c.cacheMu.Lock()
		c.apiMetrics = m
		c.cacheMu.Unlock()
		mu.Lock()
		s.APIMetrics = m
		mu.Unlock()
		return nil
	})
}

func metricValue(l string) (float64, bool) {
	i := strings.LastIndexByte(l, ' ')
	if i < 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(l[i+1:], 64)
	return v, err == nil
}

// label returns one label's value from a Prometheus text line.
func label(l, name string) string {
	i := strings.Index(l, name+`="`)
	if i < 0 {
		return ""
	}
	rest := l[i+len(name)+2:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}
