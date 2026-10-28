package apigateway

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	traceCounter atomic.Uint64
	// W3C traceparent regex: 00-{32 hex trace-id}-{16 hex parent-id}-{2 hex flags}
	w3cTraceparentRegex = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
)

// Span represents an individual timed unit of execution within a distributed trace.
type Span struct {
	TraceID        string            `json:"trace_id"`
	SpanID         string            `json:"span_id"`
	ParentSpanID   string            `json:"parent_span_id,omitempty"`
	Name           string            `json:"name"` // e.g. "gateway.ingress", "gateway.auth", "gateway.upstream"
	Kind           string            `json:"kind"` // "SERVER", "CLIENT", "INTERNAL"
	StartTime      time.Time         `json:"start_time"`
	EndTime        time.Time         `json:"end_time"`
	DurationMicros int64             `json:"duration_micros"`
	StatusCode     int               `json:"status_code"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	Events         []SpanEvent       `json:"events,omitempty"`
	mu             sync.Mutex        `json:"-"`
}

// SpanEvent records a timestamped milestone or annotation inside a span.
type SpanEvent struct {
	Name         string            `json:"name"`
	Timestamp    time.Time         `json:"timestamp"`
	OffsetMicros int64             `json:"offset_micros"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

// SetAttribute adds or overrides a key-value attribute tag on the span.
func (s *Span) SetAttribute(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[key] = value
}

// AddEvent attaches a timestamped event milestone to the span.
func (s *Span) AddEvent(name string, attrs map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	offset := now.Sub(s.StartTime).Microseconds()
	if offset < 0 {
		offset = 0
	}
	s.Events = append(s.Events, SpanEvent{
		Name:         name,
		Timestamp:    now,
		OffsetMicros: offset,
		Attributes:   attrs,
	})
}

// TraceContext represents the W3C trace context associated with a single request.
type TraceContext struct {
	TraceID        string     `json:"trace_id"`
	SpanID         string     `json:"span_id"`        // Gateway root server span ID
	ParentSpanID   string     `json:"parent_span_id"` // Upstream caller's span ID if provided
	TraceFlags     string     `json:"trace_flags"`    // e.g. "01" (sampled)
	TraceState     string     `json:"trace_state,omitempty"`
	Sampled        bool       `json:"sampled"`
	Method         string     `json:"method"`
	Path           string     `json:"path"`
	StatusCode     int        `json:"status_code"`
	StartTime      time.Time  `json:"start_time"`
	DurationMicros int64      `json:"duration_micros"`
	Spans          []*Span    `json:"spans"`
	mu             sync.Mutex `json:"-"`
}

// Traceparent returns the canonical W3C traceparent header value (version 00).
func (tc *TraceContext) Traceparent() string {
	return fmt.Sprintf("00-%s-%s-%s", tc.TraceID, tc.SpanID, tc.TraceFlags)
}

// StartSpan creates and begins a new child span within this trace.
func (tc *TraceContext) StartSpan(name, kind string) *Span {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	parentID := tc.SpanID
	// If a previous span exists, nest under it or under root
	span := &Span{
		TraceID:      tc.TraceID,
		SpanID:       generateSpanID(),
		ParentSpanID: parentID,
		Name:         name,
		Kind:         kind,
		StartTime:    time.Now().UTC(),
		Attributes:   make(map[string]string),
	}
	tc.Spans = append(tc.Spans, span)
	return span
}

// EndSpan completes the span timing and records attributes and status code.
func (tc *TraceContext) EndSpan(span *Span, statusCode int, attrs map[string]string) {
	if span == nil {
		return
	}
	span.mu.Lock()
	span.EndTime = time.Now().UTC()
	span.DurationMicros = span.EndTime.Sub(span.StartTime).Microseconds()
	if span.DurationMicros < 0 {
		span.DurationMicros = 0
	}
	span.StatusCode = statusCode
	if span.Attributes == nil {
		span.Attributes = make(map[string]string)
	}
	for k, v := range attrs {
		span.Attributes[k] = v
	}
	span.mu.Unlock()
}

// SpanByName retrieves the first span matching the given name, if present.
func (tc *TraceContext) SpanByName(name string) *Span {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for _, s := range tc.Spans {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// TracingEngine: In-Memory Ring Buffer & Exporter
// ---------------------------------------------------------------------------

// TracingEngine manages W3C trace context extraction, lifecycle recording, and OpenTelemetry/Jaeger exports.
type TracingEngine struct {
	mu            sync.RWMutex
	maxTraces     int
	traces        []*TraceContext
	traceMap      map[string]*TraceContext
	head          int
	count         int
	samplingRate  float64 // 0.0 to 1.0 (1.0 = 100% sampled)
	slowThreshold time.Duration
	metrics       *MetricsCollector
}

// NewTracingEngine creates a high-performance distributed tracing manager with bounded ring buffer memory.
func NewTracingEngine(maxTraces int, metrics *MetricsCollector) *TracingEngine {
	if maxTraces <= 0 {
		maxTraces = 5000
	}
	return &TracingEngine{
		maxTraces:     maxTraces,
		traces:        make([]*TraceContext, maxTraces),
		traceMap:      make(map[string]*TraceContext, maxTraces),
		samplingRate:  1.0, // 100% sampling default
		slowThreshold: 50 * time.Millisecond,
		metrics:       metrics,
	}
}

// SetSamplingRate updates the dynamic trace sampling probability (0.0 to 1.0).
func (te *TracingEngine) SetSamplingRate(rate float64) {
	te.mu.Lock()
	defer te.mu.Unlock()
	if rate < 0.0 {
		rate = 0.0
	} else if rate > 1.0 {
		rate = 1.0
	}
	te.samplingRate = rate
}

// ExtractOrStartTrace extracts W3C traceparent from request headers or generates a new trace.
func (te *TracingEngine) ExtractOrStartTrace(r *http.Request) *TraceContext {
	rawTP := strings.TrimSpace(r.Header.Get("traceparent"))
	rawState := strings.TrimSpace(r.Header.Get("tracestate"))

	var traceID, parentSpanID, flags string
	sampled := true

	if rawTP != "" {
		matches := w3cTraceparentRegex.FindStringSubmatch(strings.ToLower(rawTP))
		if len(matches) == 4 && matches[1] != "00000000000000000000000000000000" && matches[2] != "0000000000000000" {
			traceID = matches[1]
			parentSpanID = matches[2]
			flags = matches[3]
			sampled = (flags == "01")
		}
	}

	// Fallback to X-Request-ID if exactly 32 hex characters
	if traceID == "" {
		xrid := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if len(xrid) == 32 && isHex(xrid) && xrid != "00000000000000000000000000000000" {
			traceID = strings.ToLower(xrid)
		}
	}

	// Generate fresh trace if absent or invalid
	if traceID == "" {
		traceID = generateTraceID()
		flags = "01"
		sampled = true
	}

	if flags == "" {
		flags = "01"
	}

	rootSpanID := generateSpanID()

	// Append or initialize tracestate
	if rawState == "" {
		rawState = "aeitron=gateway"
	} else if !strings.Contains(rawState, "aeitron=") {
		rawState = rawState + ",aeitron=gateway"
	}

	tc := &TraceContext{
		TraceID:      traceID,
		SpanID:       rootSpanID,
		ParentSpanID: parentSpanID,
		TraceFlags:   flags,
		TraceState:   rawState,
		Sampled:      sampled,
		Method:       r.Method,
		Path:         r.URL.Path,
		StartTime:    time.Now().UTC(),
		Spans:        make([]*Span, 0, 8),
	}

	return tc
}

// RecordTrace commits a completed trace context to the circular ring buffer.
func (te *TracingEngine) RecordTrace(tc *TraceContext) {
	if tc == nil {
		return
	}

	tc.mu.Lock()
	tc.DurationMicros = time.Since(tc.StartTime).Microseconds()
	if tc.DurationMicros < 0 {
		tc.DurationMicros = 0
	}
	tc.mu.Unlock()

	te.mu.Lock()
	// Evict existing entry if overwriting ring buffer slot
	if te.count >= te.maxTraces {
		oldest := te.traces[te.head]
		if oldest != nil {
			delete(te.traceMap, oldest.TraceID)
		}
	} else {
		te.count++
	}

	te.traces[te.head] = tc
	te.traceMap[tc.TraceID] = tc
	te.head = (te.head + 1) % te.maxTraces
	te.mu.Unlock()

	// Update Telemetry Metrics
	if te.metrics != nil {
		te.metrics.RecordTrace()
		for _, s := range tc.Spans {
			te.metrics.RecordSpan(s.Name)
		}
		if tc.DurationMicros >= te.slowThreshold.Microseconds() {
			te.metrics.RecordSlowTrace()
		}
	}
}

// GetTrace retrieves a trace by its 32-character hexadecimal trace ID.
func (te *TracingEngine) GetTrace(traceID string) (*TraceContext, bool) {
	te.mu.RLock()
	defer te.mu.RUnlock()
	tc, exists := te.traceMap[strings.ToLower(traceID)]
	return tc, exists
}

// RecentTraces returns the most recent traces matching optional filter criteria.
func (te *TracingEngine) RecentTraces(limit int, minDurationMs int, statusFilter int) []*TraceContext {
	te.mu.RLock()
	defer te.mu.RUnlock()

	if limit <= 0 || limit > 500 {
		limit = 50
	}

	results := make([]*TraceContext, 0, limit)
	minDurationMicros := int64(minDurationMs) * 1000

	// Traverse ring buffer in reverse chronological order
	for i := 0; i < te.count; i++ {
		idx := (te.head - 1 - i + te.maxTraces) % te.maxTraces
		tc := te.traces[idx]
		if tc == nil {
			continue
		}

		if minDurationMicros > 0 && tc.DurationMicros < minDurationMicros {
			continue
		}
		if statusFilter > 0 && tc.StatusCode != statusFilter {
			continue
		}

		results = append(results, tc)
		if len(results) >= limit {
			break
		}
	}

	return results
}

// Stats returns operational tracing buffer statistics.
type TracingStats struct {
	CapturedTraces  int     `json:"captured_traces"`
	MaxCapacity     int     `json:"max_capacity"`
	SamplingRate    float64 `json:"sampling_rate"`
	SlowThresholdMs int64   `json:"slow_threshold_ms"`
	SlowTracesTotal uint64  `json:"slow_traces_total"`
}

func (te *TracingEngine) Stats() TracingStats {
	te.mu.RLock()
	defer te.mu.RUnlock()
	var slowCount uint64
	if te.metrics != nil {
		slowCount = te.metrics.SlowTracesTotal()
	}
	return TracingStats{
		CapturedTraces:  te.count,
		MaxCapacity:     te.maxTraces,
		SamplingRate:    te.samplingRate,
		SlowThresholdMs: te.slowThreshold.Milliseconds(),
		SlowTracesTotal: slowCount,
	}
}

// SetSlowThreshold updates the duration threshold for classifying a trace as slow (default 50ms).
func (te *TracingEngine) SetSlowThreshold(d time.Duration) {
	te.mu.Lock()
	defer te.mu.Unlock()
	if d > 0 {
		te.slowThreshold = d
	}
}

// SlowThreshold returns the current slow trace threshold duration.
func (te *TracingEngine) SlowThreshold() time.Duration {
	te.mu.RLock()
	defer te.mu.RUnlock()
	return te.slowThreshold
}

// SlowTraces returns recent traces exceeding the slow threshold duration.
func (te *TracingEngine) SlowTraces(limit int) []*TraceContext {
	te.mu.RLock()
	thresholdMs := int(te.slowThreshold.Milliseconds())
	te.mu.RUnlock()
	return te.RecentTraces(limit, thresholdMs, 0)
}

// ---------------------------------------------------------------------------
// OpenTelemetry (OTLP) & Jaeger Standard JSON Exporters
// ---------------------------------------------------------------------------

// ExportOTLPFormat transforms a TraceContext into the standard OpenTelemetry (OTLP) v1 JSON schema.
func (te *TracingEngine) ExportOTLPFormat(tc *TraceContext) map[string]any {
	if tc == nil {
		return nil
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	var otlpSpans []map[string]any
	for _, s := range tc.Spans {
		var attrs []map[string]any
		s.mu.Lock()
		for k, v := range s.Attributes {
			attrs = append(attrs, map[string]any{
				"key": k,
				"value": map[string]any{
					"stringValue": v,
				},
			})
		}

		var events []map[string]any
		for _, ev := range s.Events {
			var evAttrs []map[string]any
			for ek, evVal := range ev.Attributes {
				evAttrs = append(evAttrs, map[string]any{
					"key": ek,
					"value": map[string]any{
						"stringValue": evVal,
					},
				})
			}
			events = append(events, map[string]any{
				"timeUnixNano": fmt.Sprintf("%d", ev.Timestamp.UnixNano()),
				"name":         ev.Name,
				"attributes":   evAttrs,
			})
		}

		otlpSpan := map[string]any{
			"traceId":           s.TraceID,
			"spanId":            s.SpanID,
			"parentSpanId":      s.ParentSpanID,
			"name":              s.Name,
			"kind":              otlpKindCode(s.Kind),
			"startTimeUnixNano": fmt.Sprintf("%d", s.StartTime.UnixNano()),
			"endTimeUnixNano":   fmt.Sprintf("%d", s.EndTime.UnixNano()),
			"attributes":        attrs,
			"events":            events,
			"status": map[string]any{
				"code": otlpStatusCode(s.StatusCode),
			},
		}
		s.mu.Unlock()
		otlpSpans = append(otlpSpans, otlpSpan)
	}

	return map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{
							"key":   "service.name",
							"value": map[string]any{"stringValue": "aeitron-api-gateway"},
						},
						{
							"key":   "telemetry.sdk.language",
							"value": map[string]any{"stringValue": "go"},
						},
					},
				},
				"scopeSpans": []map[string]any{
					{
						"scope": map[string]any{
							"name":    "github.com/aeitron/api/tracing",
							"version": "1.0.0",
						},
						"spans": otlpSpans,
					},
				},
			},
		},
	}
}

// ExportJaegerFormat converts a TraceContext into Jaeger standard UI/Ingestion trace JSON format.
func (te *TracingEngine) ExportJaegerFormat(tc *TraceContext) map[string]any {
	if tc == nil {
		return nil
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	var jaegerSpans []map[string]any
	for _, s := range tc.Spans {
		s.mu.Lock()
		var tags []map[string]any
		for k, v := range s.Attributes {
			tags = append(tags, map[string]any{
				"key":   k,
				"type":  "string",
				"value": v,
			})
		}
		tags = append(tags, map[string]any{
			"key":   "http.status_code",
			"type":  "int64",
			"value": s.StatusCode,
		})

		var logs []map[string]any
		for _, ev := range s.Events {
			var fields []map[string]any
			for ek, evVal := range ev.Attributes {
				fields = append(fields, map[string]any{
					"key":   ek,
					"type":  "string",
					"value": evVal,
				})
			}
			logs = append(logs, map[string]any{
				"timestamp": ev.Timestamp.UnixMicro(),
				"fields":    fields,
			})
		}

		jaegerSpan := map[string]any{
			"traceID":       s.TraceID,
			"spanID":        s.SpanID,
			"operationName": s.Name,
			"references": []map[string]any{
				{
					"refType": "CHILD_OF",
					"traceID": s.TraceID,
					"spanID":  s.ParentSpanID,
				},
			},
			"startTime": s.StartTime.UnixMicro(),
			"duration":  s.DurationMicros,
			"tags":      tags,
			"logs":      logs,
			"processID": "p1",
		}
		s.mu.Unlock()
		jaegerSpans = append(jaegerSpans, jaegerSpan)
	}

	return map[string]any{
		"data": []map[string]any{
			{
				"traceID": tc.TraceID,
				"spans":   jaegerSpans,
				"processes": map[string]any{
					"p1": map[string]any{
						"serviceName": "aeitron-api-gateway",
						"tags": []map[string]any{
							{"key": "hostname", "type": "string", "value": "edge-gateway"},
						},
					},
				},
			},
		},
	}
}

// ExportZipkinFormat converts a TraceContext into Zipkin v2 JSON format.
func (te *TracingEngine) ExportZipkinFormat(tc *TraceContext) []map[string]any {
	if tc == nil {
		return nil
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	var zipkinSpans []map[string]any
	for _, s := range tc.Spans {
		s.mu.Lock()
		tags := make(map[string]string)
		for k, v := range s.Attributes {
			tags[k] = v
		}
		tags["http.status_code"] = fmt.Sprintf("%d", s.StatusCode)

		spanData := map[string]any{
			"traceId":   s.TraceID,
			"id":        s.SpanID,
			"name":      s.Name,
			"timestamp": s.StartTime.UnixMicro(),
			"duration":  s.DurationMicros,
			"kind":      s.Kind,
			"localEndpoint": map[string]any{
				"serviceName": "aeitron-api-gateway",
			},
			"tags": tags,
		}
		if s.ParentSpanID != "" {
			spanData["parentId"] = s.ParentSpanID
		}
		s.mu.Unlock()
		zipkinSpans = append(zipkinSpans, spanData)
	}

	return zipkinSpans
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func generateTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		now := time.Now().UnixNano()
		binary.BigEndian.PutUint64(b[0:8], uint64(now))
		binary.BigEndian.PutUint64(b[8:16], traceCounter.Add(1))
	}
	// W3C trace-id must not be all zeros
	if b == [16]byte{} {
		b[15] = 1
	}
	return hex.EncodeToString(b[:])
}

func generateSpanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:], traceCounter.Add(1))
	}
	// W3C span-id must not be all zeros
	if b == [8]byte{} {
		b[7] = 1
	}
	return hex.EncodeToString(b[:])
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func otlpKindCode(kind string) int {
	switch strings.ToUpper(kind) {
	case "INTERNAL":
		return 1
	case "SERVER":
		return 2
	case "CLIENT":
		return 3
	case "PRODUCER":
		return 4
	case "CONSUMER":
		return 5
	default:
		return 1
	}
}

func otlpStatusCode(code int) int {
	if code >= 200 && code < 400 {
		return 1 // STATUS_CODE_OK
	}
	if code >= 400 {
		return 2 // STATUS_CODE_ERROR
	}
	return 0 // STATUS_CODE_UNSET
}
