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
	requestsTotal       sync.Map // key: "method:route:status" -> *atomic.Uint64
	routeHistograms     sync.Map // key: "route" -> *RouteHistogram
	rateLimited         sync.Map // key: "tier" -> *atomic.Uint64
	cacheOps            sync.Map // key: "status" -> *atomic.Uint64
	idempotencyOps      sync.Map // key: "status" -> *atomic.Uint64
	circuitTrips        sync.Map // key: "upstream" -> *atomic.Uint64
	compressedResponses sync.Map // key: "encoding" -> *atomic.Uint64
	compressionSavings  atomic.Uint64

	// Webhook Engine Metrics
	webhookDispatched sync.Map // key: eventType -> *atomic.Uint64
	webhookDeliveries sync.Map // key: status -> *atomic.Uint64
	webhookDLQ        atomic.Uint64
	webhookActiveSubs atomic.Int64

	// Cluster State Adapter Metrics
	clusterMode        atomic.Pointer[string]
	clusterStateOps    sync.Map // key: op -> *atomic.Uint64
	clusterStateErrors atomic.Uint64

	// Distributed Tracing Metrics
	tracesTotal     atomic.Uint64
	spansTotal      sync.Map // key: spanName -> *atomic.Uint64
	slowTracesTotal atomic.Uint64

	// Server-Sent Events (SSE) Metrics
	sseActiveConnections atomic.Int64
	sseEventsPublished   atomic.Uint64
	sseEventsDelivered   atomic.Uint64
}

// NewMetricsCollector initializes a Prometheus metrics collector.
func NewMetricsCollector(startTime time.Time) *MetricsCollector {
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}
	col := &MetricsCollector{
		startTime: startTime,
	}
	defaultMode := "memory"
	col.clusterMode.Store(&defaultMode)
	return col
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

// RecordCompression records a compressed response event and updates cumulative saved wire bytes.
func (m *MetricsCollector) RecordCompression(uncompressed, compressed int64, encoding string) {
	if encoding == "" {
		return
	}
	val, ok := m.compressedResponses.Load(encoding)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.compressedResponses.LoadOrStore(encoding, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)

	if uncompressed > compressed {
		savings := uint64(uncompressed - compressed)
		m.compressionSavings.Add(savings)
	}
}

// CompressionSavings returns total egress bandwidth saved in bytes.
func (m *MetricsCollector) CompressionSavings() uint64 {
	return m.compressionSavings.Load()
}

// RecordWebhookDispatched increments the counter for dispatched webhook events.
func (m *MetricsCollector) RecordWebhookDispatched(eventType string) {
	if eventType == "" {
		eventType = "unknown"
	}
	val, ok := m.webhookDispatched.Load(eventType)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.webhookDispatched.LoadOrStore(eventType, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordWebhookDelivery records an asynchronous webhook delivery attempt by outcome status.
func (m *MetricsCollector) RecordWebhookDelivery(status string) {
	if status == "" {
		status = "unknown"
	}
	val, ok := m.webhookDeliveries.Load(status)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.webhookDeliveries.LoadOrStore(status, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordWebhookDLQ increments the count of failed webhooks routed to Dead-Letter Queue.
func (m *MetricsCollector) RecordWebhookDLQ() {
	m.webhookDLQ.Add(1)
}

// SetWebhookActiveSubscriptions updates the active webhook subscriptions gauge.
func (m *MetricsCollector) SetWebhookActiveSubscriptions(count int64) {
	m.webhookActiveSubs.Store(count)
}

// RecordSSEConnect increments active SSE client connections.
func (m *MetricsCollector) RecordSSEConnect() {
	m.sseActiveConnections.Add(1)
}

// RecordSSEDisconnect decrements active SSE client connections.
func (m *MetricsCollector) RecordSSEDisconnect() {
	m.sseActiveConnections.Add(-1)
}

// RecordSSEEventPublished increments published SSE events counter.
func (m *MetricsCollector) RecordSSEEventPublished() {
	m.sseEventsPublished.Add(1)
}

// RecordSSEEventDelivered increments delivered SSE events counter.
func (m *MetricsCollector) RecordSSEEventDelivered() {
	m.sseEventsDelivered.Add(1)
}

// SetClusterMode stores the active cluster adapter mode ("memory" or "redis").
func (m *MetricsCollector) SetClusterMode(mode string) {
	m.clusterMode.Store(&mode)
}

// ClusterMode returns the active cluster adapter mode.
func (m *MetricsCollector) ClusterMode() string {
	ptr := m.clusterMode.Load()
	if ptr == nil {
		return "memory"
	}
	return *ptr
}

// RecordClusterOp increments the counter for a cluster state operation.
func (m *MetricsCollector) RecordClusterOp(op string) {
	if op == "" {
		op = "unknown"
	}
	val, ok := m.clusterStateOps.Load(op)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.clusterStateOps.LoadOrStore(op, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordClusterError increments the cluster state error counter.
func (m *MetricsCollector) RecordClusterError() {
	m.clusterStateErrors.Add(1)
}

// ClusterErrors returns the total cluster state errors count.
func (m *MetricsCollector) ClusterErrors() uint64 {
	return m.clusterStateErrors.Load()
}

// RecordTrace increments the total completed distributed traces counter.
func (m *MetricsCollector) RecordTrace() {
	m.tracesTotal.Add(1)
}

// RecordSpan increments the counter for an individual span name.
func (m *MetricsCollector) RecordSpan(name string) {
	if name == "" {
		name = "unknown"
	}
	val, ok := m.spansTotal.Load(name)
	if !ok {
		newCounter := &atomic.Uint64{}
		actual, _ := m.spansTotal.LoadOrStore(name, newCounter)
		val = actual
	}
	val.(*atomic.Uint64).Add(1)
}

// RecordSlowTrace increments the counter for requests exceeding latency budget (>50ms).
func (m *MetricsCollector) RecordSlowTrace() {
	m.slowTracesTotal.Add(1)
}

// TracesTotal returns the total count of recorded distributed traces.
func (m *MetricsCollector) TracesTotal() uint64 {
	return m.tracesTotal.Load()
}

// SlowTracesTotal returns the count of traces exceeding 50ms.
func (m *MetricsCollector) SlowTracesTotal() uint64 {
	return m.slowTracesTotal.Load()
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

	// 7. aeitron_api_compressed_responses_total & aeitron_api_compression_savings_bytes_total
	buf.WriteString("\n# HELP aeitron_api_compressed_responses_total Total responses compressed by algorithm\n")
	buf.WriteString("# TYPE aeitron_api_compressed_responses_total counter\n")
	type compEntry struct {
		encoding string
		count    uint64
	}
	var compEntries []compEntry
	m.compressedResponses.Range(func(key, value any) bool {
		compEntries = append(compEntries, compEntry{
			encoding: key.(string),
			count:    value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(compEntries, func(i, j int) bool { return compEntries[i].encoding < compEntries[j].encoding })
	for _, c := range compEntries {
		buf.WriteString(fmt.Sprintf("aeitron_api_compressed_responses_total{encoding=\"%s\"} %d\n", c.encoding, c.count))
	}

	buf.WriteString("\n# HELP aeitron_api_compression_savings_bytes_total Total egress bandwidth saved via response compression in bytes\n")
	buf.WriteString("# TYPE aeitron_api_compression_savings_bytes_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_compression_savings_bytes_total %d\n", m.compressionSavings.Load()))

	// 8. aeitron_api_circuit_breaker_state & trips
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

		buf.WriteString("\n# HELP aeitron_api_upstream_node_health Health status of upstream backend nodes (1=healthy, 0=unhealthy)\n")
		buf.WriteString("# TYPE aeitron_api_upstream_node_health gauge\n")
		for _, r := range proxyRoutes {
			proxy := proxies[r]
			if proxy != nil && proxy.Pool() != nil {
				for _, n := range proxy.Pool().Nodes() {
					hVal := 0
					if n.IsHealthy() {
						hVal = 1
					}
					buf.WriteString(fmt.Sprintf("aeitron_api_upstream_node_health{route=\"%s\",node=\"%s\"} %d\n",
						r, n.URLString(), hVal))
				}
			}
		}

		buf.WriteString("\n# HELP aeitron_api_upstream_node_active_connections Current active in-flight requests per upstream node\n")
		buf.WriteString("# TYPE aeitron_api_upstream_node_active_connections gauge\n")
		for _, r := range proxyRoutes {
			proxy := proxies[r]
			if proxy != nil && proxy.Pool() != nil {
				for _, n := range proxy.Pool().Nodes() {
					buf.WriteString(fmt.Sprintf("aeitron_api_upstream_node_active_connections{route=\"%s\",node=\"%s\"} %d\n",
						r, n.URLString(), n.ActiveConnections()))
				}
			}
		}

		buf.WriteString("\n# HELP aeitron_api_upstream_node_requests_total Total requests routed to upstream node\n")
		buf.WriteString("# TYPE aeitron_api_upstream_node_requests_total counter\n")
		for _, r := range proxyRoutes {
			proxy := proxies[r]
			if proxy != nil && proxy.Pool() != nil {
				for _, n := range proxy.Pool().Nodes() {
					buf.WriteString(fmt.Sprintf("aeitron_api_upstream_node_requests_total{route=\"%s\",node=\"%s\"} %d\n",
						r, n.URLString(), n.TotalRequests()))
				}
			}
		}
	}

	// 8. Webhook Engine Metrics
	buf.WriteString("\n# HELP aeitron_api_webhook_dispatched_total Total asynchronous cloud events dispatched to webhooks\n")
	buf.WriteString("# TYPE aeitron_api_webhook_dispatched_total counter\n")
	type webhookDispatchedEntry struct {
		eventType string
		count     uint64
	}
	var dispatches []webhookDispatchedEntry
	m.webhookDispatched.Range(func(key, value any) bool {
		dispatches = append(dispatches, webhookDispatchedEntry{
			eventType: key.(string),
			count:     value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(dispatches, func(i, j int) bool {
		return dispatches[i].eventType < dispatches[j].eventType
	})
	for _, d := range dispatches {
		buf.WriteString(fmt.Sprintf("aeitron_api_webhook_dispatched_total{event_type=\"%s\"} %d\n", d.eventType, d.count))
	}

	buf.WriteString("\n# HELP aeitron_api_webhook_deliveries_total Total webhook delivery attempts by outcome status\n")
	buf.WriteString("# TYPE aeitron_api_webhook_deliveries_total counter\n")
	type webhookDeliveryEntry struct {
		status string
		count  uint64
	}
	var deliveries []webhookDeliveryEntry
	m.webhookDeliveries.Range(func(key, value any) bool {
		deliveries = append(deliveries, webhookDeliveryEntry{
			status: key.(string),
			count:  value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(deliveries, func(i, j int) bool {
		return deliveries[i].status < deliveries[j].status
	})
	for _, d := range deliveries {
		buf.WriteString(fmt.Sprintf("aeitron_api_webhook_deliveries_total{status=\"%s\"} %d\n", d.status, d.count))
	}

	buf.WriteString("\n# HELP aeitron_api_webhook_dlq_total Total failed webhooks permanently routed to Dead-Letter Queue\n")
	buf.WriteString("# TYPE aeitron_api_webhook_dlq_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_webhook_dlq_total %d\n", m.webhookDLQ.Load()))

	buf.WriteString("\n# HELP aeitron_api_webhook_active_subscriptions Current active registered webhook subscriptions\n")
	buf.WriteString("# TYPE aeitron_api_webhook_active_subscriptions gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_webhook_active_subscriptions %d\n", m.webhookActiveSubs.Load()))

	// 9. Cluster State Adapter Metrics
	buf.WriteString("\n# HELP aeitron_api_cluster_state_mode Current cluster state adapter mode (1=active)\n")
	buf.WriteString("# TYPE aeitron_api_cluster_state_mode gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_cluster_state_mode{mode=\"%s\"} 1\n", m.ClusterMode()))

	buf.WriteString("\n# HELP aeitron_api_cluster_state_ops_total Total distributed cluster state operations by type\n")
	buf.WriteString("# TYPE aeitron_api_cluster_state_ops_total counter\n")
	type clusterOpEntry struct {
		op    string
		count uint64
	}
	var clusterOps []clusterOpEntry
	m.clusterStateOps.Range(func(key, value any) bool {
		clusterOps = append(clusterOps, clusterOpEntry{
			op:    key.(string),
			count: value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(clusterOps, func(i, j int) bool {
		return clusterOps[i].op < clusterOps[j].op
	})
	for _, o := range clusterOps {
		buf.WriteString(fmt.Sprintf("aeitron_api_cluster_state_ops_total{op=\"%s\"} %d\n", o.op, o.count))
	}

	buf.WriteString("\n# HELP aeitron_api_cluster_state_errors_total Total cluster state adapter connection or command errors\n")
	buf.WriteString("# TYPE aeitron_api_cluster_state_errors_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_cluster_state_errors_total %d\n", m.clusterStateErrors.Load()))

	// 10. Distributed Tracing Metrics
	buf.WriteString("\n# HELP aeitron_api_traces_total Total number of distributed traces recorded\n")
	buf.WriteString("# TYPE aeitron_api_traces_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_traces_total %d\n", m.tracesTotal.Load()))

	buf.WriteString("\n# HELP aeitron_api_spans_total Total number of execution spans tracked by operation\n")
	buf.WriteString("# TYPE aeitron_api_spans_total counter\n")
	type spanEntry struct {
		name  string
		count uint64
	}
	var spans []spanEntry
	m.spansTotal.Range(func(key, value any) bool {
		spans = append(spans, spanEntry{
			name:  key.(string),
			count: value.(*atomic.Uint64).Load(),
		})
		return true
	})
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].name < spans[j].name
	})
	for _, s := range spans {
		buf.WriteString(fmt.Sprintf("aeitron_api_spans_total{name=\"%s\"} %d\n", s.name, s.count))
	}

	buf.WriteString("\n# HELP aeitron_api_slow_traces_total Total traces exceeding the 50ms latency threshold\n")
	buf.WriteString("# TYPE aeitron_api_slow_traces_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_slow_traces_total %d\n", m.slowTracesTotal.Load()))

	// Server-Sent Events (SSE) Telemetry
	buf.WriteString("\n# HELP aeitron_api_sse_active_connections Current active real-time SSE stream connections\n")
	buf.WriteString("# TYPE aeitron_api_sse_active_connections gauge\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_sse_active_connections %d\n", m.sseActiveConnections.Load()))

	buf.WriteString("\n# HELP aeitron_api_sse_events_published_total Total real-time infrastructure events published\n")
	buf.WriteString("# TYPE aeitron_api_sse_events_published_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_sse_events_published_total %d\n", m.sseEventsPublished.Load()))

	buf.WriteString("\n# HELP aeitron_api_sse_events_delivered_total Total real-time infrastructure events delivered to SSE subscribers\n")
	buf.WriteString("# TYPE aeitron_api_sse_events_delivered_total counter\n")
	buf.WriteString(fmt.Sprintf("aeitron_api_sse_events_delivered_total %d\n", m.sseEventsDelivered.Load()))

	// 11. Runtime & Process Gauges
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
