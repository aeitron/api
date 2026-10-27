package apigateway

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// APIGateway is the centralized, high-performance API Gateway and routing proxy.
type APIGateway struct {
	mu            sync.RWMutex
	routes        []RouteRule
	proxies       map[string]*UpstreamProxy
	authenticator *Authenticator
	limiter       *TokenBucketLimiter
	auditSpooler  *AuditSpooler
	stats         GatewayStats
	startTime     time.Time
}

// NewAPIGateway initializes an APIGateway with default core services.
func NewAPIGateway(jwtSecret string) *APIGateway {
	gw := &APIGateway{
		proxies:       make(map[string]*UpstreamProxy),
		authenticator: NewAuthenticator(jwtSecret),
		limiter:       NewTokenBucketLimiter(),
		auditSpooler:  NewAuditSpooler(2000),
		stats: GatewayStats{
			StatusCodes:    make(map[int]int64),
			UpstreamStatus: make(map[string]string),
		},
		startTime: time.Now().UTC(),
	}

	// Register canonical Aeitron platform microservices
	defaultRoutes := []RouteRule{
		{PathPrefix: "/v1/auth", UpstreamURL: "http://127.0.0.1:9092", AllowAnonymous: true, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/identity", UpstreamURL: "http://127.0.0.1:9092", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/organizations", UpstreamURL: "http://127.0.0.1:9093", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/audit", UpstreamURL: "http://127.0.0.1:9094", AllowAnonymous: false, RequiredScopes: []string{"audit:read"}, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/databases", UpstreamURL: "http://127.0.0.1:9095", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/fleet", UpstreamURL: "http://127.0.0.1:9096", AllowAnonymous: false, RequiredScopes: []string{"fleet:read"}, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/billing", UpstreamURL: "http://127.0.0.1:8097", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/commerce", UpstreamURL: "http://127.0.0.1:8098", AllowAnonymous: true, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/dns", UpstreamURL: "http://127.0.0.1:8053", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/router", UpstreamURL: "http://127.0.0.1:9090", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/edge", UpstreamURL: "http://127.0.0.1:9091", AllowAnonymous: false, Timeout: 15 * time.Second},
	}

	for _, r := range defaultRoutes {
		_ = gw.RegisterRoute(r)
	}

	return gw
}

// Authenticator returns the gateway's authentication component.
func (gw *APIGateway) Authenticator() *Authenticator {
	return gw.authenticator
}

// AuditSpooler returns the gateway's audit spooler component.
func (gw *APIGateway) AuditSpooler() *AuditSpooler {
	return gw.auditSpooler
}

// RegisterRoute adds or updates a dynamic route rule.
func (gw *APIGateway) RegisterRoute(rule RouteRule) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	proxy, err := NewUpstreamProxy(rule)
	if err != nil {
		return err
	}

	gw.proxies[rule.PathPrefix] = proxy

	// Replace existing or append
	replaced := false
	for i, r := range gw.routes {
		if r.PathPrefix == rule.PathPrefix {
			gw.routes[i] = rule
			replaced = true
			break
		}
	}
	if !replaced {
		gw.routes = append(gw.routes, rule)
	}

	// Sort routes longest prefix first
	sort.Slice(gw.routes, func(i, j int) bool {
		return len(gw.routes[i].PathPrefix) > len(gw.routes[j].PathPrefix)
	})

	return nil
}

func (gw *APIGateway) matchRoute(path string) (*RouteRule, *UpstreamProxy) {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	for _, rule := range gw.routes {
		if strings.HasPrefix(path, rule.PathPrefix) {
			proxy := gw.proxies[rule.PathPrefix]
			ruleCopy := rule
			return &ruleCopy, proxy
		}
	}
	return nil, nil
}

func (gw *APIGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddInt64(&gw.stats.TotalRequests, 1)

	// 1. Security Headers & CORS
	ApplySecurityHeaders(w)
	if HandleCORS(w, r) {
		return
	}

	// 2. Request Correlation ID
	reqID := ExtractOrGenerateRequestID(r)
	w.Header().Set("X-Request-ID", reqID)

	// 3. Built-in Gateway Endpoints
	if r.URL.Path == "/healthz" || r.URL.Path == "/ready" {
		writeJSONResponse(w, http.StatusOK, map[string]string{
			"status":  "healthy",
			"service": "aeitron-api-gateway",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	if r.URL.Path == "/v1/gateway/routes" {
		gw.mu.RLock()
		routes := make([]RouteRule, len(gw.routes))
		copy(routes, gw.routes)
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{"routes": routes})
		return
	}
	if r.URL.Path == "/v1/gateway/stats" {
		gw.mu.RLock()
		st := gw.stats
		st.UptimeSeconds = int64(time.Since(gw.startTime).Seconds())
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, st)
		return
	}

	// 4. IP-Level Token Bucket Rate Limiting
	clientIP := extractClientIP(r)
	ipTier := DefaultRateLimits["ip_default"]
	allowed, remaining, retryAfter := gw.limiter.Allow("ip:"+clientIP, ipTier.RequestsPerSecond, ipTier.BurstCapacity)
	if !allowed {
		atomic.AddInt64(&gw.stats.RateLimitedCount, 1)
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"too many requests from this IP: rate limit exceeded"}`))
		return
	}

	// 5. Route Resolution
	rule, proxy := gw.matchRoute(r.URL.Path)
	if rule == nil || proxy == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"route not found on api-gateway"}`))
		return
	}

	// 6. Strip Client Identity Headers (Prevent Tenant Spoofing)
	r.Header.Del("X-Tenant-ID")
	r.Header.Del("X-Org-ID")
	r.Header.Del("X-Project-ID")
	r.Header.Del("X-Actor-ID")
	r.Header.Del("X-Actor-Role")

	var tenantCtx *TenantContext

	// 7. Authentication & Authorization
	if !rule.AllowAnonymous {
		ctx, err := gw.authenticator.AuthenticateRequest(r)
		if err != nil {
			atomic.AddInt64(&gw.stats.AuthFailedCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `{"error":"unauthorized: %s"}`, err.Error())
			return
		}

		// Check permission scopes
		if !CheckScopes(ctx.Scopes, rule.RequiredScopes) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden: insufficient permission scopes"}`))
			return
		}

		tenantCtx = ctx

		// 8. Tenant-Level Rate Limiting
		tierName := ctx.Tier
		if tierName == "" {
			tierName = "free"
		}
		tierConfig, exists := DefaultRateLimits[tierName]
		if !exists {
			tierConfig = DefaultRateLimits["free"]
		}

		tAllowed, tRemaining, tRetry := gw.limiter.Allow("tenant:"+ctx.TenantID, tierConfig.RequestsPerSecond, tierConfig.BurstCapacity)
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", tierConfig.BurstCapacity))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", tRemaining))

		if !tAllowed {
			atomic.AddInt64(&gw.stats.RateLimitedCount, 1)
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", tRetry.Seconds()))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"error":"rate limit exceeded for tenant '%s' on '%s' tier"}`, ctx.TenantID, tierName)
			return
		}
	} else {
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	}

	// 9. Forward via Reverse Proxy
	wrapper := NewResponseWriterWrapper(w)
	proxy.ServeHTTP(wrapper, r, tenantCtx, reqID)

	duration := time.Since(start)

	// 10. Record Stats
	gw.mu.Lock()
	gw.stats.StatusCodes[wrapper.StatusCode]++
	gw.mu.Unlock()

	// 11. Centralized Audit Logging on State Mutations
	if isMutationMethod(r.Method) && tenantCtx != nil {
		gw.auditSpooler.Spool(AuditRecord{
			RequestID:  reqID,
			TenantID:   tenantCtx.TenantID,
			ActorID:    tenantCtx.ActorID,
			Method:     r.Method,
			Path:       r.URL.Path,
			ClientIP:   clientIP,
			StatusCode: wrapper.StatusCode,
			DurationMs: duration.Milliseconds(),
			Timestamp:  time.Now().UTC(),
		})
	}
}

func extractClientIP(r *http.Request) string {
	xfwd := r.Header.Get("X-Forwarded-For")
	if xfwd != "" {
		parts := strings.Split(xfwd, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func isMutationMethod(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete
}

func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
