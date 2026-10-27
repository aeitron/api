package apigateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
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

// UpstreamProxy encapsulates reverse proxying and circuit breaking for a specific upstream.
type UpstreamProxy struct {
	rule           RouteRule
	targetURL      *url.URL
	reverseProxy   *httputil.ReverseProxy
	circuitBreaker *CircuitBreaker
}

// NewUpstreamProxy creates an UpstreamProxy.
func NewUpstreamProxy(rule RouteRule) (*UpstreamProxy, error) {
	target, err := url.Parse(rule.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL '%s': %w", rule.UpstreamURL, err)
	}

	cb := NewCircuitBreaker(5, 5*time.Second)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host

		// Strip prefix if requested
		if rule.StripPrefix {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, rule.PathPrefix)
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}
		}

		// Strip client spoofing attempts
		req.Header.Del("X-Forwarded-Host")
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		cb.RecordResult(resp.StatusCode)
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		cb.RecordResult(http.StatusBadGateway)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, `{"error":"upstream gateway error: %s"}`, err.Error())
	}

	return &UpstreamProxy{
		rule:           rule,
		targetURL:      target,
		reverseProxy:   proxy,
		circuitBreaker: cb,
	}, nil
}

func (up *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, ctx *TenantContext, reqID string) {
	if !up.circuitBreaker.Allow() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"upstream service unavailable: circuit breaker is open"}`))
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

	up.reverseProxy.ServeHTTP(w, r)
}
