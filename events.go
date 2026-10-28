package apigateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// InfrastructureEvent represents a real-time event for infrastructure lifecycle tasks.
type InfrastructureEvent struct {
	ID        string          `json:"id"`
	Topic     string          `json:"topic"`     // e.g. "compute.instances", "dns.health", "cluster.deployments", "webhooks.deliveries"
	Type      string          `json:"type"`      // e.g. "instance.provisioning", "dns.failover_triggered"
	TenantID  string          `json:"tenant_id"` // tenant-isolated or "system" / "public"
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

type eventSubscriber struct {
	id       string
	tenantID string
	topics   map[string]bool
	wildcard bool
	ch       chan InfrastructureEvent
}

// EventStreamEngine coordinates real-time Server-Sent Events (SSE) broadcasting,
// ring-buffer replay for reconnecting clients, and topic filtering.
type EventStreamEngine struct {
	mu                sync.RWMutex
	subscribers       map[string]*eventSubscriber
	ringBuffer        []InfrastructureEvent
	ringCapacity      int
	ringHead          int
	ringCount         int
	metrics           *MetricsCollector
	heartbeatInterval time.Duration
}

// NewEventStreamEngine initializes an SSE engine with ring buffer capacity.
func NewEventStreamEngine(bufferCapacity int, metrics *MetricsCollector) *EventStreamEngine {
	if bufferCapacity <= 0 {
		bufferCapacity = 1000
	}
	return &EventStreamEngine{
		subscribers:       make(map[string]*eventSubscriber),
		ringBuffer:        make([]InfrastructureEvent, bufferCapacity),
		ringCapacity:      bufferCapacity,
		metrics:           metrics,
		heartbeatInterval: 15 * time.Second,
	}
}

// SetHeartbeatInterval overrides the default 15s keepalive ping interval (e.g. for testing).
func (e *EventStreamEngine) SetHeartbeatInterval(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.heartbeatInterval = d
}

// Publish broadcasts an infrastructure event to all matching active SSE subscribers
// and preserves it in the ring buffer for catch-up replay.
func (e *EventStreamEngine) Publish(event InfrastructureEvent) InfrastructureEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	if event.ID == "" {
		event.ID = fmt.Sprintf("evt_%d_%s", time.Now().UTC().UnixNano(), randomHex(6))
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.TenantID == "" {
		event.TenantID = "default"
	}
	if event.Topic == "" {
		event.Topic = "system"
	}

	// 1. Insert into circular ring buffer
	e.ringBuffer[e.ringHead] = event
	e.ringHead = (e.ringHead + 1) % e.ringCapacity
	if e.ringCount < e.ringCapacity {
		e.ringCount++
	}

	if e.metrics != nil {
		e.metrics.RecordSSEEventPublished()
	}

	// 2. Non-blocking fanout to all active matching subscribers
	for _, sub := range e.subscribers {
		if !e.matchesSubscriber(sub, event) {
			continue
		}

		select {
		case sub.ch <- event:
			if e.metrics != nil {
				e.metrics.RecordSSEEventDelivered()
			}
		default:
			// If client buffer is full, drop oldest and push current to prevent gateway stalls
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- event:
				if e.metrics != nil {
					e.metrics.RecordSSEEventDelivered()
				}
			default:
			}
		}
	}

	return event
}

// matchesSubscriber checks if a subscriber is eligible to receive an event.
func (e *EventStreamEngine) matchesSubscriber(sub *eventSubscriber, event InfrastructureEvent) bool {
	// Tenant isolation: subscriber receives events for their tenant or public/system broadcasts
	if sub.tenantID != "*" && sub.tenantID != "" && event.TenantID != "public" && event.TenantID != "*" && event.TenantID != sub.tenantID {
		return false
	}

	if sub.wildcard {
		return true
	}

	if sub.topics[event.Topic] || sub.topics[event.Type] {
		return true
	}

	// Prefix matching: e.g. "compute.*" matches "compute.instances"
	for topic := range sub.topics {
		if strings.HasSuffix(topic, ".*") {
			prefix := strings.TrimSuffix(topic, ".*")
			if strings.HasPrefix(event.Topic, prefix+".") || event.Topic == prefix {
				return true
			}
		}
	}

	return false
}

// GetRecentHistory retrieves recent events from the ring buffer in chronological order.
func (e *EventStreamEngine) GetRecentHistory(tenantID, topicFilter string, limit int) []InfrastructureEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 || limit > e.ringCount {
		limit = e.ringCount
	}

	var results []InfrastructureEvent
	// Reconstruct chronological order from circular buffer
	startIdx := (e.ringHead - e.ringCount + e.ringCapacity) % e.ringCapacity
	for i := 0; i < e.ringCount; i++ {
		idx := (startIdx + i) % e.ringCapacity
		item := e.ringBuffer[idx]

		// Filter by tenant and topic
		if tenantID != "*" && tenantID != "" && item.TenantID != "public" && item.TenantID != "*" && item.TenantID != tenantID {
			continue
		}
		if topicFilter != "" && topicFilter != "*" && item.Topic != topicFilter && !matchesEventPattern(topicFilter, item.Topic) {
			continue
		}

		results = append(results, item)
	}

	if len(results) > limit {
		results = results[len(results)-limit:]
	}
	return results
}

// ActiveSubscribersCount returns the number of active live SSE connections.
func (e *EventStreamEngine) ActiveSubscribersCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.subscribers)
}

// ServeHTTP handles incoming SSE connection requests, performs replay, and streams events.
func (e *EventStreamEngine) ServeHTTP(w http.ResponseWriter, r *http.Request, tenantID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported: flusher not implemented", http.StatusInternalServerError)
		return
	}

	// Parse requested topics: ?topics=compute.instances,dns.health or ?events=...
	topicsParam := r.URL.Query().Get("topics")
	if topicsParam == "" {
		topicsParam = r.URL.Query().Get("events")
	}

	topicMap := make(map[string]bool)
	wildcard := false
	if topicsParam == "" || topicsParam == "*" {
		wildcard = true
	} else {
		for _, t := range strings.Split(topicsParam, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed == "*" {
				wildcard = true
				break
			}
			if trimmed != "" {
				topicMap[trimmed] = true
			}
		}
	}

	subID := fmt.Sprintf("sub_%d_%s", time.Now().UnixNano(), randomHex(6))
	sub := &eventSubscriber{
		id:       subID,
		tenantID: tenantID,
		topics:   topicMap,
		wildcard: wildcard,
		ch:       make(chan InfrastructureEvent, 256),
	}

	// Register subscriber
	e.mu.Lock()
	e.subscribers[subID] = sub
	heartbeat := e.heartbeatInterval
	e.mu.Unlock()

	if e.metrics != nil {
		e.metrics.RecordSSEConnect()
	}

	defer func() {
		e.mu.Lock()
		delete(e.subscribers, subID)
		e.mu.Unlock()
		if e.metrics != nil {
			e.metrics.RecordSSEDisconnect()
		}
	}()

	// Standard RFC / W3C Server-Sent Events headers
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Aeitron-Stream", "active")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Initial greeting comment
	_, _ = fmt.Fprintf(w, ": connected to aeitron real-time event plane (stream=%s)\n\n", subID)
	flusher.Flush()

	// 1. Replay missed events if client specified Last-Event-ID
	lastEventID := r.Header.Get("Last-Event-ID")
	if lastEventID == "" {
		lastEventID = r.URL.Query().Get("last_event_id")
	}
	if lastEventID != "" {
		history := e.GetRecentHistory(tenantID, "*", 500)
		foundLast := false
		for _, ev := range history {
			if foundLast {
				if e.matchesSubscriber(sub, ev) {
					e.writeEvent(w, ev)
					flusher.Flush()
				}
			} else if ev.ID == lastEventID {
				foundLast = true
			}
		}
	}

	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Keepalive comment ping
			if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-sub.ch:
			if !ok {
				return
			}
			if err := e.writeEvent(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (e *EventStreamEngine) writeEvent(w http.ResponseWriter, ev InfrastructureEvent) error {
	dataBytes, err := json.Marshal(ev.Data)
	if err != nil {
		dataBytes = []byte("{}")
	}
	// W3C SSE event wire frame: use Topic for event name, fallback to Type
	eventName := ev.Topic
	if eventName == "" {
		eventName = ev.Type
	}
	// Sanitize against CRLF injection in SSE framing
	evID := strings.ReplaceAll(strings.ReplaceAll(ev.ID, "\r", ""), "\n", "")
	eventName = strings.ReplaceAll(strings.ReplaceAll(eventName, "\r", ""), "\n", "")
	_, err = fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", evID, eventName, string(dataBytes))
	return err
}

// Close disconnects all active subscribers.
func (e *EventStreamEngine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, sub := range e.subscribers {
		close(sub.ch)
	}
	e.subscribers = make(map[string]*eventSubscriber)
}
