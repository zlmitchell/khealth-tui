package rca

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/zlmitchell/khealth-tui/internal/k8s"
)

// Request is one access-log line of an ingress controller or proxy.
type Request struct {
	Time       time.Time
	Controller string // ingress-nginx | traefik | envoy
	Method     string
	Host, Path string
	Status     int
	Duration   time.Duration // -1: not logged
	Upstream   string        // what the proxy sent it to: ns-svc-port, svc@provider, outbound|80||svc.ns.svc..., or an address
	Ref        Ref
}

// Minute is the traffic to the workload in one minute.
type Minute struct {
	Start     time.Time
	Requests  int
	Errors5xx int
	Errors4xx int
	P95       time.Duration
}

// IngressView is the traffic that reached the workload through a
// controller around the incident.
type IngressView struct {
	Services    []string // ns/name of the Services in front of the workload
	Routes      []string // Ingress / HTTPRoute objects that send traffic to them
	Controllers []string // controller pods whose logs were read
	Minutes     []Minute
	Errors      []Request // the 5xx closest to the incident
	Total       int
	Note        string // why the view is empty, when it is
}

var (
	// ingress-nginx: ... [time] "GET /p HTTP/1.1" 502 150 "ref" "ua" 512 0.004 [shop-web-80] [] 10.42.0.5:80 0 0.004 502 id
	nginxLine = regexp.MustCompile(`"([A-Z]+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "[^"]*" \d+ ([\d.]+) \[([^\]]*)\]`)
	// traefik common log: ... "GET /p HTTP/1.1" 200 12 "-" "-" 42 "router@kubernetes" "http://10.42.0.5:80" 3ms
	traefikLine = regexp.MustCompile(`"([A-Z]+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "[^"]*" \d+ "([^"]*)" "([^"]*)" (\d+)ms`)
	// envoy (istio default): [time] "GET /p HTTP/1.1" 503 UF ... "host" "10.42.0.5:8080" outbound|80||web.shop.svc.cluster.local
	envoyLine = regexp.MustCompile(`"([A-Z]+) (\S+) [^"]*" (\d{3}) .*?"([^"]*)" "([^"]*)" (\S+)`)
)

// ParseRequest reads one controller log line (the API's timestamp prefix
// already split off into t).
func ParseRequest(controller string, t time.Time, line string) (Request, bool) {
	r := Request{Time: t, Controller: controller, Duration: -1}
	switch controller {
	case "ingress-nginx":
		m := nginxLine.FindStringSubmatch(line)
		if m == nil {
			return r, false
		}
		r.Method, r.Path, r.Upstream = m[1], m[2], m[5]
		r.Status, _ = strconv.Atoi(m[3])
		if f, err := strconv.ParseFloat(m[4], 64); err == nil {
			r.Duration = time.Duration(f * float64(time.Second))
		}
		return r, true
	case "traefik":
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			var j struct {
				RequestMethod, RequestPath, RequestHost, ServiceName, ServiceAddr string
				DownstreamStatus                                                  int
				Duration                                                          int64
			}
			if json.Unmarshal([]byte(line), &j) != nil || j.DownstreamStatus == 0 {
				return r, false
			}
			r.Method, r.Path, r.Host, r.Status = j.RequestMethod, j.RequestPath, j.RequestHost, j.DownstreamStatus
			r.Upstream = j.ServiceName + " " + j.ServiceAddr
			r.Duration = time.Duration(j.Duration)
			return r, true
		}
		m := traefikLine.FindStringSubmatch(line)
		if m == nil {
			return r, false
		}
		r.Method, r.Path, r.Upstream = m[1], m[2], m[4]+" "+m[5]
		r.Status, _ = strconv.Atoi(m[3])
		if ms, err := strconv.Atoi(m[6]); err == nil {
			r.Duration = time.Duration(ms) * time.Millisecond
		}
		return r, true
	case "envoy":
		m := envoyLine.FindStringSubmatch(line)
		if m == nil {
			return r, false
		}
		r.Method, r.Path, r.Host = m[1], m[2], m[4]
		r.Status, _ = strconv.Atoi(m[3])
		r.Upstream = m[5] + " " + m[6]
		return r, true
	}
	return r, false
}

// matches reports whether the request went to one of the Services (or
// straight to one of the pod IPs, as traefik and envoy log it).
func (r Request) matches(svcs []svcRef, podIPs map[string]bool) bool {
	up := r.Upstream
	for _, s := range svcs {
		if strings.Contains(up, s.ns+"-"+s.name+"-") || // nginx: ns-svc-port
			strings.Contains(up, s.ns+"-"+s.name+"@") || // traefik: ns-svc-port@kubernetes / ns-svc@...
			strings.Contains(up, s.name+"."+s.ns+".svc") { // envoy: outbound|80||svc.ns.svc.cluster.local
			return true
		}
	}
	for _, f := range strings.FieldsFunc(up, func(c rune) bool { return c == ' ' || c == '/' || c == ',' }) {
		host := f
		if i := strings.LastIndex(f, ":"); i > 0 {
			host = f[:i]
		}
		if podIPs[host] {
			return true
		}
	}
	return false
}

type svcRef struct{ ns, name string }

// Ingress reads the controllers' access logs around t and keeps the
// requests that went to the workload's pods.
func Ingress(src Source, pods []*corev1.Pod, t time.Time, window time.Duration) *IngressView {
	s := src.Snap()
	v := &IngressView{}
	if len(pods) == 0 {
		v.Note = "no pods to match traffic against"
		return v
	}
	ns := pods[0].Namespace
	podIPs := map[string]bool{}
	for _, p := range pods {
		if p.Status.PodIP != "" {
			podIPs[p.Status.PodIP] = true
		}
	}
	var svcs []svcRef
	for i := range s.Services {
		sv := &s.Services[i]
		if sv.Namespace != ns || len(sv.Spec.Selector) == 0 {
			continue
		}
		for _, p := range pods {
			if selects(sv.Spec.Selector, p.Labels) {
				svcs = append(svcs, svcRef{sv.Namespace, sv.Name})
				v.Services = append(v.Services, sv.Namespace+"/"+sv.Name)
				break
			}
		}
	}
	if len(svcs) == 0 {
		v.Note = "no Service selects the workload's pods: it takes no ingress traffic"
		return v
	}
	names := map[string]bool{}
	for _, sv := range svcs {
		names[sv.name] = true
	}
	for i := range s.Ingresses {
		ing := &s.Ingresses[i]
		if ing.Namespace != ns {
			continue
		}
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Backend.Service != nil && names[p.Backend.Service.Name] {
					v.Routes = append(v.Routes, "ingress "+ing.Name+" "+r.Host+p.Path)
				}
			}
		}
	}
	for _, rt := range src.Objects("httproutes.gateway.networking.k8s.io") {
		if rt.GetNamespace() != ns {
			continue
		}
		rules, _, _ := unstructuredSlice(mapAt(rt.Object, "spec"), "rules")
		for _, r := range rules {
			brefs, _, _ := unstructuredSlice(r.(map[string]any), "backendRefs")
			for _, b := range brefs {
				if names[str(b.(map[string]any)["name"])] {
					v.Routes = append(v.Routes, "httproute "+rt.GetName())
				}
			}
		}
	}
	from, to := t.Add(-window), t.Add(window)
	var reqs []Request
	for i := range s.Pods {
		p := &s.Pods[i]
		kind := k8s.IngressController(p)
		if kind == "" {
			continue
		}
		for _, ctr := range p.Spec.Containers {
			for _, prev := range []bool{false, true} {
				lines, file := src.PodLog(p.Namespace, p.Name, ctr.Name, prev)
				if lines == nil {
					continue
				}
				v.Controllers = appendOnce(v.Controllers, p.Namespace+"/"+p.Name)
				for li, l := range lines {
					ts, body := parseAPI(l)
					if ts.IsZero() || ts.Before(from) || ts.After(to) {
						continue
					}
					r, ok := ParseRequest(kind, ts, body)
					if !ok || !r.matches(svcs, podIPs) {
						continue
					}
					r.Ref = Ref{File: file, Line: li + 1}
					reqs = append(reqs, r)
				}
			}
		}
	}
	if len(v.Controllers) == 0 {
		v.Note = "no ingress controller logs in the bundle (ingress-nginx, traefik or envoy pods)"
		return v
	}
	sort.SliceStable(reqs, func(i, j int) bool { return reqs[i].Time.Before(reqs[j].Time) })
	v.Total = len(reqs)
	v.Minutes = perMinute(reqs)
	for _, r := range reqs {
		if r.Status >= 500 {
			v.Errors = append(v.Errors, r)
		}
	}
	sort.SliceStable(v.Errors, func(i, j int) bool { return absDur(v.Errors[i].Time.Sub(t)) < absDur(v.Errors[j].Time.Sub(t)) })
	if len(v.Errors) > 20 {
		v.Errors = v.Errors[:20]
	}
	if v.Total == 0 {
		v.Note = "the controllers logged no request for these Services in the window (access logging may be off: traefik needs accessLog enabled)"
	}
	return v
}

func perMinute(reqs []Request) []Minute {
	var out []Minute
	var durs []time.Duration
	flush := func() {
		if len(out) == 0 {
			return
		}
		sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
		if len(durs) > 0 {
			out[len(out)-1].P95 = durs[max(0, (len(durs)*95+99)/100-1)] // nearest-rank p95
		}
		durs = durs[:0]
	}
	for _, r := range reqs {
		m := r.Time.Truncate(time.Minute)
		if len(out) == 0 || !out[len(out)-1].Start.Equal(m) {
			flush()
			out = append(out, Minute{Start: m})
		}
		cur := &out[len(out)-1]
		cur.Requests++
		switch {
		case r.Status >= 500:
			cur.Errors5xx++
		case r.Status >= 400:
			cur.Errors4xx++
		}
		if r.Duration >= 0 {
			durs = append(durs, r.Duration)
		}
	}
	flush()
	return out
}

func selects(sel, labels map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func mapAt(obj map[string]any, key string) map[string]any {
	m, _ := obj[key].(map[string]any)
	return m
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
