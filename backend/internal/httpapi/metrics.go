package httpapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// metrics is a minimal Prometheus text-format registry: request counts and a
// latency histogram per route, plus gauges the app reports.
type metrics struct {
	mu       sync.Mutex
	requests map[string]int64 // route|status → count
	hist     map[string]*histogram
	gauges   func() map[string]float64
}

var buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1, 2.5, 5}

type histogram struct {
	counts []int64
	sum    float64
	n      int64
}

func newMetrics() *metrics {
	return &metrics{requests: map[string]int64{}, hist: map[string]*histogram{}}
}

func (m *metrics) observeRequest(route string, status int, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[fmt.Sprintf("%s|%d", route, status)]++
	h, ok := m.hist[route]
	if !ok {
		h = &histogram{counts: make([]int64, len(buckets))}
		m.hist[route] = h
	}
	s := d.Seconds()
	for i, b := range buckets {
		if s <= b {
			h.counts[i]++
		}
	}
	h.sum += s
	h.n++
}

func esc(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) }

func (m *metrics) handler(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	b.WriteString("# HELP prahari_http_requests_total HTTP requests by route and status.\n# TYPE prahari_http_requests_total counter\n")
	keys := make([]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		route, status, _ := strings.Cut(k, "|")
		fmt.Fprintf(&b, "prahari_http_requests_total{route=\"%s\",status=\"%s\"} %d\n", esc(route), status, m.requests[k])
	}
	b.WriteString("# HELP prahari_http_request_duration_seconds Request latency by route.\n# TYPE prahari_http_request_duration_seconds histogram\n")
	routes := make([]string, 0, len(m.hist))
	for r := range m.hist {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, route := range routes {
		h := m.hist[route]
		for i, bk := range buckets {
			fmt.Fprintf(&b, "prahari_http_request_duration_seconds_bucket{route=\"%s\",le=\"%g\"} %d\n", esc(route), bk, h.counts[i])
		}
		fmt.Fprintf(&b, "prahari_http_request_duration_seconds_bucket{route=\"%s\",le=\"+Inf\"} %d\n", esc(route), h.n)
		fmt.Fprintf(&b, "prahari_http_request_duration_seconds_sum{route=\"%s\"} %g\n", esc(route), h.sum)
		fmt.Fprintf(&b, "prahari_http_request_duration_seconds_count{route=\"%s\"} %d\n", esc(route), h.n)
	}
	if m.gauges != nil {
		g := m.gauges()
		names := make([]string, 0, len(g))
		for k := range g {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "# TYPE %s gauge\n%s %g\n", n, n, g[n])
		}
	}
	_, _ = w.Write([]byte(b.String()))
}
