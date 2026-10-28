package apigateway

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CircuitBreaker monitors upstream health and prevents cascading failures.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            string // "closed", "open", "half-open"
	consecutiveFails int
	failureThreshold int
	successCount     int
	successThreshold int
	cooldownDuration time.Duration
	trippedAt        time.Time
}

// NewCircuitBreaker creates a circuit breaker for an upstream service.
func NewCircuitBreaker(failureThreshold int, cooldown time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if cooldown <= 0 {
		cooldown = 10 * time.Second
	}
	return &CircuitBreaker{
		state:            "closed",
		failureThreshold: failureThreshold,
		successThreshold: 2,
		cooldownDuration: cooldown,
	}
}

// Allow returns true if requests are permitted to pass to the upstream.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now().UTC()
	if cb.state == "open" {
		if now.Sub(cb.trippedAt) > cb.cooldownDuration {
			cb.state = "half-open"
			cb.successCount = 0
			return true
		}
		return false
	}
	return true
}

// RecordResult updates circuit breaker status based on response status code.
func (cb *CircuitBreaker) RecordResult(statusCode int) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now().UTC()
	if statusCode >= 500 {
		cb.consecutiveFails++
		if cb.consecutiveFails >= cb.failureThreshold {
			cb.state = "open"
			cb.trippedAt = now
		}
	} else {
		cb.consecutiveFails = 0
		if cb.state == "half-open" {
			cb.successCount++
			if cb.successCount >= cb.successThreshold {
				cb.state = "closed"
				cb.consecutiveFails = 0
			}
		}
	}
}

// State returns current circuit status.
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// StateCode returns numeric circuit status: 0=closed, 1=half-open, 2=open.
func (cb *CircuitBreaker) StateCode() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case "closed":
		return 0
	case "half-open":
		return 1
	case "open":
		return 2
	default:
		return 0
	}
}

// ConsecutiveFails returns consecutive failure count.
func (cb *CircuitBreaker) ConsecutiveFails() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.consecutiveFails
}

// UpstreamProxy encapsulates load-balanced reverse proxying and circuit breaking for a specific upstream.
type UpstreamProxy struct {
	rule RouteRule
	pool *UpstreamPool
}

// NewUpstreamProxy creates an UpstreamProxy supporting single or multiple load-balanced targets.
func NewUpstreamProxy(rule RouteRule) (*UpstreamProxy, error) {
	var rawURLs []string
	if len(rule.UpstreamURLs) > 0 {
		rawURLs = rule.UpstreamURLs
	} else if rule.UpstreamURL != "" {
		for _, part := range strings.Split(rule.UpstreamURL, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				rawURLs = append(rawURLs, trimmed)
			}
		}
	}

	if len(rawURLs) == 0 {
		return nil, fmt.Errorf("no upstream URLs specified for path '%s'", rule.PathPrefix)
	}

	var parsedURLs []*url.URL
	for _, raw := range rawURLs {
		if err := ValidateSafeUpstreamURL(raw); err != nil {
			return nil, fmt.Errorf("unsafe upstream URL for route '%s': %w", rule.PathPrefix, err)
		}
		target, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream URL '%s': %w", raw, err)
		}
		parsedURLs = append(parsedURLs, target)
	}

	pool, err := NewUpstreamPool(rule, parsedURLs)
	if err != nil {
		return nil, err
	}

	return &UpstreamProxy{
		rule: rule,
		pool: pool,
	}, nil
}

func (up *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, ctx *TenantContext, reqID string) {
	node, err := up.pool.Pick()
	if err != nil {
		w.Header().Set("Retry-After", "5")
		WriteServiceUnavailable(w, r, "upstream service unavailable: no healthy backend nodes in pool")
		return
	}

	// Apply timeout if configured
	if up.rule.Timeout > 0 {
		var cancel context.CancelFunc
		ctxTimeout, cancelFunc := context.WithTimeout(r.Context(), up.rule.Timeout)
		cancel = cancelFunc
		defer cancel()
		r = r.WithContext(ctxTimeout)
	}

	// Inject Verified Context Headers to Upstream
	if ctx != nil {
		r.Header.Set("X-Tenant-ID", ctx.TenantID)
		r.Header.Set("X-Org-ID", ctx.OrgID)
		r.Header.Set("X-Project-ID", ctx.ProjectID)
		r.Header.Set("X-Actor-ID", ctx.ActorID)
		r.Header.Set("X-Actor-Role", ctx.Role)
		r.Header.Set("X-RateLimit-Tier", ctx.Tier)
	}
	r.Header.Set("X-Request-ID", reqID)
	r.Header.Set("X-Backend-Node", node.URLString())
	w.Header().Set("X-Backend-Node", node.URLString())

	// Ensure W3C distributed tracing context propagation to upstream
	if tp := r.Header.Get("traceparent"); tp != "" {
		r.Header.Set("traceparent", tp)
	}
	if ts := r.Header.Get("tracestate"); ts != "" {
		r.Header.Set("tracestate", ts)
	}

	node.activeConns.Add(1)
	node.totalRequests.Add(1)
	defer node.activeConns.Add(-1)

	node.reverseProxy.ServeHTTP(w, r)
}

// UpstreamURL returns the configured upstream target URL string (primary node).
func (up *UpstreamProxy) UpstreamURL() string {
	if up.pool != nil && len(up.pool.nodes) > 0 {
		return up.pool.nodes[0].URLString()
	}
	return up.rule.UpstreamURL
}

// CircuitBreaker returns the proxy circuit breaker instance (primary node).
func (up *UpstreamProxy) CircuitBreaker() *CircuitBreaker {
	if up.pool != nil && len(up.pool.nodes) > 0 {
		return up.pool.nodes[0].CircuitBreaker()
	}
	return nil
}

// Pool returns the underlying load-balanced upstream pool.
func (up *UpstreamProxy) Pool() *UpstreamPool {
	return up.pool
}

// Nodes returns all backend nodes in the pool.
func (up *UpstreamProxy) Nodes() []*UpstreamNode {
	if up.pool == nil {
		return nil
	}
	return up.pool.nodes
}

// Close gracefully shuts down background health check loops for this proxy.
func (up *UpstreamProxy) Close() {
	if up.pool != nil {
		up.pool.Close()
	}
}
