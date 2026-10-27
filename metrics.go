package apigateway

import (
	"bytes"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultLatencyBuckets defines standard Prometheus histogram boundaries in seconds (1ms to 10s).
var DefaultLatencyBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

// RouteHistogram holds sharded atomic counters for latency histogram buckets.
type RouteHistogram struct {
	buckets   []atomic.Uint64 // len == len(DefaultLatencyBuckets) + 1 (last is +Inf)
	sumMicros atomic.Uint64   // cumulative microseconds
	count     atomic.Uint64   // total request count
}

// MetricsCollector gathers high-throughput, lock-free Prometheus operational metrics.
type MetricsCollector struct {
	startTime time.Time

	// Gauges
	inFlight atomic.Int64

	// Counters and Histograms (sync.Map with *atomic.Uint64 values for zero contention)
	requestsTotal   sync.Map // key: "method:route:status" -> *atomic.Uint64
	routeHistograms sync.Map // key: "route" -> *RouteHistogram
	rateLimited     sync.Map // key: "tier" -> *atomic.Uint64
	cacheOps        sync.Map // key: "status" -> *atomic.Uint64
	idempotencyOps  sync.Map // key: "status" -> *atomic.Uint64
	circuitTrips    sync.Map // key: "upstream" -> *atomic.Uint64
}

// NewMetricsCollector initializes a Prometheus metrics collector.
func NewMetricsCollector(startTime time.Time) *MetricsCollector {
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}
	return &MetricsCollector{
		startTime: startTime,
	}
}

// IncInFlight increments the active in-flight request gauge.
func (m *MetricsCollector) IncInFlight() {
	m.inFlight.Add(1)
}

// DecInFlight decrements the active in-flight request gauge.
func (m *MetricsCollector) DecInFlight() {
	m.inFlight.Add(-1)
}

// InFlight returns the current number of in-flight requests.
func (m *MetricsCollector) InFlight() int64 {
	val := m.inFlight.Load()
	if val < 0 {
		return 0
	}
	return val
}

// RecordRequest updates request count and latency histogram.
func (m *MetricsCollector) RecordRequest(method, route string, statusCode int, duration time.Duration) {
	if method == "" {
		method = "UNKNOWN"
	}
	if route == "" {
		route = "/unmatched"
	}

	// 1. Total requests counter
	reqKey := fmt.Sprintf("%s:%s:%d", method, route, statusCode)
	val, ok := m.requestsTotal.Load(reqKey)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.requestsTotal.LoadOrStore(reqKey, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)

	// 2. Latency histogram
	hVal, hOk := m.routeHistograms.Load(route)
	if !hOk {
		newH := &RouteHistogram{
			buckets: make([]atomic.Uint64, len(DefaultLatencyBuckets)+1),
		}
		actualH, _ := m.routeHistograms.LoadOrStore(route, newH)
		hVal = actualH
	}
	hist := hVal.(*RouteHistogram)

	sec := duration.Seconds()
	for i, upper := range DefaultLatencyBuckets {
		if sec <= upper {
			hist.buckets[i].Add(1)
		}
	}
	// +Inf bucket always matches
	hist.buckets[len(DefaultLatencyBuckets)].Add(1)
	hist.sumMicros.Add(uint64(duration.Microseconds()))
	hist.count.Add(1)
}

// RecordRateLimit records a rejected rate-limited request.
func (m *MetricsCollector) RecordRateLimit(tier string) {
	if tier == "" {
		tier = "unknown"
	}
	val, ok := m.rateLimited.Load(tier)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.rateLimited.LoadOrStore(tier, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordCacheOp records an RFC 9111 cache operation (HIT, MISS, 304_NOT_MODIFIED, BYPASS, STORE, PURGE).
func (m *MetricsCollector) RecordCacheOp(status string) {
	if status == "" {
		status = "UNKNOWN"
	}
	val, ok := m.cacheOps.Load(status)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.cacheOps.LoadOrStore(status, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordIdempotencyOp records an Idempotency-Key operation (NEW, REPLAYED, CONFLICT, ABORTED).
func (m *MetricsCollector) RecordIdempotencyOp(status string) {
	if status == "" {
		status = "UNKNOWN"
	}
	val, ok := m.idempotencyOps.Load(status)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.idempotencyOps.LoadOrStore(status, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordCircuitTrip records an upstream circuit breaker trip event.
func (m *MetricsCollector) RecordCircuitTrip(upstream string) {
	if upstream == "" {
		upstream = "unknown"
	}
	val, ok := m.circuitTrips.Load(upstream)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.circuitTrips.LoadOrStore(upstream, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RenderPrometheus generates standard Prometheus OpenMetrics text format (version 0.0.4).
func (m *MetricsCollector) RenderPrometheus(proxies map[string]*UpstreamProxy) string {
	var buf bytes.Buffer

	// 1. aeitron_api_requests_total
	buf.WriteString("# HELP aeitron_api_requests_total Total number of HTTP requests processed by the API gateway\n")
	buf.WriteString("# TYPE aeitron_api_requests_total counter\n")
	type reqEntry struct {
		method string
		route  string
		status string
		count  uint64
	}
	var reqs []reqEntry
	m.requestsTotal.Range(func(key, value any) bool {
		parts := strings.Split(key.(string), ":")
		if len(parts) == 3 {
			reqs = append(reqs, reqEntry{
				method: parts[0],
				route:  parts[1],
				status: parts[2],
				count:  value.(*atomic.Uint64).Load(),
			})
		}
		return true
	})
	sort.Slice(reqs, func(i, j int) bool {
		if reqs[i].route != reqs[j].route {
			return reqs[i].route < reqs[j].route
		}
		if reqs[i].method != reqs[j].method {
			return reqs[i].method < reqs[j].method
		}
		return reqs[i].status < reqs[j].status
	})
	for _, r := range reqs {
		buf.WriteString(fmt.Sprintf("aeitron_api_requests_total{method=\"%s\",route=\"%s\",status=\"%s\"} %d\n",
			r.method, r.route, r.status, r.count))
	}

	// 2. aeitron_api_request_duration_seconds (Histogram)
	buf.WriteString("\n# HELP aeitron_api_request_duration_seconds Latency of HTTP requests handled by the API gateway in seconds\n")
	buf.WriteString("# TYPE aeitron_api_request_duration_seconds histogram\n")
	var routes []string
	m.routeHistograms.Range(func(key, value any) bool {
		routes = append(routes, key.(string))
		return true
	})
	sort.Strings(routes)
	for _, route := range routes {
		val, _ := m.routeHistograms.Load(route)
		hist := val.(*RouteHistogram)

		for i, bound := range DefaultLatencyBuckets {
			buf.WriteString(fmt.Sprintf("aeitron_api_request_duration_seconds_bucket{route=\"%s\",le=\"%s\"} %d\n",
				route, formatBucketBound(bound), hist.buckets[i].Load()))
		}
		buf.WriteString(fmt.Sprintf("aeitron_api_request_duration_seconds_bucket{route=\"%s\",le=\"+Inf\"} %d\n",
			route, hist.buckets[len(DefaultLatencyBuckets)].Load()))

		sumSec := float64(hist.sumMicros.Load()) / 1e6
		buf.WriteString(fmt.Sprintf("aeitron_api_request_duration_seconds_sum{route=\"%s\"} %.6f\n", route, sumSec))
		buf.WriteString(fmt.Sprintf("aeitron_api_request_duration_seconds_count{route=\"%s\"} %d\n", route, hist.count.Load()))
	}

	// 3. aeitron_api_in_flight_requests
	buf.WriteString("\n# HELP aeitron_api_in_flight_requests Current number of concurrent HTTP requests being processed\n")
	buf.WriteString("# TYPE aeitron_api_in_flight_requests gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_in_flight_requests %d\n", m.InFlight()))

	// 4. aeitron_api_rate_limited_total
	buf.WriteString("\n# HELP aeitron_api_rate_limited_total Total requests rejected due to rate limiting\n")
	buf.WriteString("# TYPE aeitron_api_rate_limited_total counter\n")
	type tierEntry struct {
		tier  string
		count uint64
	}
	var tiers []tierEntry
	m.rateLimited.Range(func(key, value any) bool {
		tiers = append(tiers, tierEntry{
			tier:  key.(string),
			count: value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(tiers, func(i, j int) bool { return tiers[i].tier < tiers[j].tier })
	for _, t := range tiers {
		buf.WriteString(fmt.Sprintf("aeitron_api_rate_limited_total{tier=\"%s\"} %d\n", t.tier, t.count))
	}

	// 5. aeitron_api_cache_operations_total
	buf.WriteString("\n# HELP aeitron_api_cache_operations_total Total RFC 9111 edge cache operations by status\n")
	buf.WriteString("# TYPE aeitron_api_cache_operations_total counter\n")
	type cacheEntry struct {
		status string
		count  uint64
	}
	var cacheOps []cacheEntry
	m.cacheOps.Range(func(key, value any) bool {
		cacheOps = append(cacheOps, cacheEntry{
			status: key.(string),
			count:  value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(cacheOps, func(i, j int) bool { return cacheOps[i].status < cacheOps[j].status })
	for _, c := range cacheOps {
		buf.WriteString(fmt.Sprintf("aeitron_api_cache_operations_total{status=\"%s\"} %d\n", c.status, c.count))
	}

	// 6. aeitron_api_idempotency_operations_total
	buf.WriteString("\n# HELP aeitron_api_idempotency_operations_total Total idempotency engine operations by status\n")
	buf.WriteString("# TYPE aeitron_api_idempotency_operations_total counter\n")
	type idempEntry struct {
		status string
		count  uint64
	}
	var idempOps []idempEntry
	m.idempotencyOps.Range(func(key, value any) bool {
		idempOps = append(idempOps, idempEntry{
			status: key.(string),
			count:  value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(idempOps, func(i, j int) bool { return idempOps[i].status < idempOps[j].status })
	for _, idm := range idempOps {
		buf.WriteString(fmt.Sprintf("aeitron_api_idempotency_operations_total{status=\"%s\"} %d\n", idm.status, idm.count))
	}

	// 7. aeitron_api_circuit_breaker_state & trips
	if len(proxies) > 0 {
		buf.WriteString("\n# HELP aeitron_api_circuit_breaker_state Circuit breaker status for upstreams (0=closed, 1=half-open, 2=open)\n")
		buf.WriteString("# TYPE aeitron_api_circuit_breaker_state gauge\n")

		var proxyRoutes []string
		for r := range proxies {
			proxyRoutes = append(proxyRoutes, r)
		}
		sort.Strings(proxyRoutes)

		for _, r := range proxyRoutes {
			proxy := proxies[r]
			if proxy != nil && proxy.CircuitBreaker() != nil {
				stateCode := proxy.CircuitBreaker().StateCode()
				stateName := proxy.CircuitBreaker().State()
				buf.WriteString(fmt.Sprintf("aeitron_api_circuit_breaker_state{route=\"%s\",upstream=\"%s\",state=\"%s\"} %d\n",
					r, proxy.UpstreamURL(), stateName, stateCode))
			}
		}

		buf.WriteString("\n# HELP aeitron_api_circuit_breaker_consecutive_failures Current consecutive failure count for upstream\n")
		buf.WriteString("# TYPE aeitron_api_circuit_breaker_consecutive_failures gauge\n")
		for _, r := range proxyRoutes {
			proxy := proxies[r]
			if proxy != nil && proxy.CircuitBreaker() != nil {
				fails := proxy.CircuitBreaker().ConsecutiveFails()
				buf.WriteString(fmt.Sprintf("aeitron_api_circuit_breaker_consecutive_failures{route=\"%s\",upstream=\"%s\"} %d\n",
					r, proxy.UpstreamURL(), fails))
			}
		}
	}

	// 8. Runtime & Process Gauges
	buf.WriteString("\n# HELP aeitron_api_uptime_seconds Seconds elapsed since gateway initialization\n")
	buf.WriteString("# TYPE aeitron_api_uptime_seconds gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_uptime_seconds %d\n", int64(time.Since(m.startTime).Seconds())))

	buf.WriteString("\n# HELP aeitron_api_goroutines Number of active Go goroutines\n")
	buf.WriteString("# TYPE aeitron_api_goroutines gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_goroutines %d\n", runtime.NumGoroutine()))

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	buf.WriteString("\n# HELP aeitron_api_memory_alloc_bytes Bytes allocated and still in use by API gateway\n")
	buf.WriteString("# TYPE aeitron_api_memory_alloc_bytes gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_memory_alloc_bytes %d\n", memStats.Alloc))

	buf.WriteString("\n# HELP aeitron_api_memory_sys_bytes Total bytes of memory obtained from the OS\n")
	buf.WriteString("# TYPE aeitron_api_memory_sys_bytes gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_memory_sys_bytes %d\n", memStats.Sys))

	buf.WriteString("\n# HELP aeitron_api_gc_runs_total Total completed GC cycles\n")
	buf.WriteString("# TYPE aeitron_api_gc_runs_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_gc_runs_total %d\n", memStats.NumGC))

	return buf.String()
}

func formatBucketBound(bound float64) string {
	if bound == math.Floor(bound) {
		return fmt.Sprintf("%.0f", bound)
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.4f", bound), "0"), ".")
}
