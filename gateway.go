package apigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
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
	idempotency   *IdempotencyEngine
	cache         *RFC9111CacheEngine
	stateAdapter  ClusterStateAdapter
	metrics       *MetricsCollector
	auditSpooler  *AuditSpooler
	webhookEngine *WebhookEngine
	eventEngine   *EventStreamEngine
	sandboxEngine *SandboxEngine
	tracingEngine *TracingEngine
	versioning    *VersioningPolicy
	stats         GatewayStats
	startTime     time.Time
}

// NewAPIGateway initializes an APIGateway with default core services.
func NewAPIGateway(jwtSecret string) *APIGateway {
	start := time.Now().UTC()
	metrics := NewMetricsCollector(start)
	gw := &APIGateway{
		proxies:       make(map[string]*UpstreamProxy),
		authenticator: NewAuthenticator(jwtSecret),
		limiter:       NewTokenBucketLimiter(),
		idempotency:   NewIdempotencyEngine(24 * time.Hour),
		cache:         NewRFC9111CacheEngine(10000, 64*1024*1024),
		metrics:       metrics,
		auditSpooler:  NewAuditSpooler(2000),
		webhookEngine: NewWebhookEngine(DefaultWebhookConfig(), metrics),
		eventEngine:   NewEventStreamEngine(1000, metrics),
		sandboxEngine: NewSandboxEngine(),
		tracingEngine: NewTracingEngine(10000, metrics),
		versioning:    NewVersioningPolicy(),
		stats: GatewayStats{
			StatusCodes:    make(map[int]int64),
			UpstreamStatus: make(map[string]string),
		},
		startTime: start,
	}
	gw.auditSpooler.SetOnDrop(metrics.RecordAuditDrop)
	gw.auditSpooler.SetOnFileError(metrics.RecordAuditFileError)

	// Pluggable Distributed State: in-memory by default, or auto-connect to Redis / KeyDB when REDIS_URL is configured
	var stateAdapter ClusterStateAdapter
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		if rAdapter, err := NewRedisStateAdapter(redisURL, DefaultRedisConfig(redisURL), metrics); err == nil {
			stateAdapter = rAdapter
			metrics.SetClusterMode("redis")
		} else {
			stateAdapter = NewMemoryStateAdapter()
			metrics.SetClusterMode("memory")
			metrics.RecordClusterError()
		}
	} else {
		stateAdapter = NewMemoryStateAdapter()
		metrics.SetClusterMode("memory")
	}

	gw.stateAdapter = stateAdapter
	gw.limiter.SetStateAdapter(stateAdapter)
	gw.idempotency.SetStateAdapter(stateAdapter)
	gw.cache.SetStateAdapter(stateAdapter)

	// Environment-configurable upstream backend targets (allows decoupled microservice topologies)
	commerceURL := getEnvBackendURL("AEITRON_COMMERCE_URL", "http://127.0.0.1:8098")
	billingURL := getEnvBackendURL("AEITRON_BILLING_URL", "http://127.0.0.1:8097")
	routerURL := getEnvBackendURL("AEITRON_ROUTER_URL", "http://127.0.0.1:9090")
	edgeURL := getEnvBackendURL("AEITRON_EDGE_URL", "http://127.0.0.1:9091")
	authURL := getEnvBackendURL("AEITRON_AUTH_URL", "http://127.0.0.1:9092")
	dnsURL := getEnvBackendURL("AEITRON_DNS_URL", "http://127.0.0.1:8053")
	securityURL := getEnvBackendURL("AEITRON_SECURITY_URL", "http://127.0.0.1:8054")
	dbURL := getEnvBackendURL("AEITRON_DATABASES_URL", "http://127.0.0.1:9095")
	fleetURL := getEnvBackendURL("AEITRON_FLEET_URL", "http://127.0.0.1:9096")
	statusURL := getEnvBackendURL("AEITRON_STATUS_URL", "http://127.0.0.1:3002")

	// Register canonical Aeitron platform microservices and product family routes
	defaultRoutes := []RouteRule{
		// Identity, Authentication, and Multi-Tenant RBAC
		{PathPrefix: "/v1/auth", UpstreamURL: authURL, AllowAnonymous: true, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/identity", UpstreamURL: authURL, AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/organizations", UpstreamURL: getEnvBackendURL("AEITRON_ORGS_URL", "http://127.0.0.1:9093"), AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/audit", UpstreamURL: getEnvBackendURL("AEITRON_AUDIT_URL", "http://127.0.0.1:9094"), AllowAnonymous: false, RequiredScopes: []string{"audit:read"}, Timeout: 15 * time.Second},

		// Sovereign Databases and Automated Backups
		{PathPrefix: "/v1/databases", UpstreamURL: dbURL, AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/backups", UpstreamURL: getEnvBackendURL("AEITRON_BACKUPS_URL", "http://127.0.0.1:9097"), AllowAnonymous: false, Timeout: 30 * time.Second},

		// Global Fleet Canary Orchestration
		{PathPrefix: "/v1/fleet", UpstreamURL: fleetURL, AllowAnonymous: false, RequiredScopes: []string{"fleet:read"}, Timeout: 15 * time.Second},

		// Real-time Metering, Telemetry, and Multi-channel Notifications
		{PathPrefix: "/v1/usage", UpstreamURL: getEnvBackendURL("AEITRON_USAGE_URL", "http://127.0.0.1:8099"), AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/notifications", UpstreamURL: getEnvBackendURL("AEITRON_NOTIFICATIONS_URL", "http://127.0.0.1:8100"), AllowAnonymous: false, Timeout: 10 * time.Second},

		// Financial Ledger, Invoicing, and Sovereign Billing
		{PathPrefix: "/v1/billing", UpstreamURL: billingURL, AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/commerce/orders", UpstreamURL: commerceURL, AllowAnonymous: false, RequiredScopes: []string{"orders:write"}, Timeout: 20 * time.Second},
		{PathPrefix: "/v1/commerce", UpstreamURL: commerceURL, AllowAnonymous: false, Timeout: 15 * time.Second},

		// Canonical Product Domains (Route directly with URL rewriting to commerce backend)
		{PathPrefix: "/v1/catalog", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/catalog", AllowAnonymous: true, CacheTTL: 60 * time.Second, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/orders", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/orders", AllowAnonymous: false, RequiredScopes: []string{"orders:write"}, Timeout: 20 * time.Second},
		{PathPrefix: "/v1/domains", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/domains", AllowAnonymous: true, CacheTTL: 30 * time.Second, Timeout: 20 * time.Second},
		{PathPrefix: "/v1/status", UpstreamURL: statusURL, AllowAnonymous: true, CacheTTL: 15 * time.Second, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/hosting", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/hosting", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/compute", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/compute", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/subscriptions", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/subscriptions", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/invoices", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/invoices", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/emails", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/emails", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/storage", UpstreamURL: commerceURL, RewritePrefix: "/v1/commerce/storage", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/inference", UpstreamURL: routerURL, AllowAnonymous: false, Timeout: 30 * time.Second},

		// Authoritative Anycast DNS, Global Traffic Director, Edge WAF, and Security
		{PathPrefix: "/v1/dns", UpstreamURL: dnsURL, AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/router", UpstreamURL: routerURL, AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/edge", UpstreamURL: edgeURL, AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/security", UpstreamURL: securityURL, AllowAnonymous: false, Timeout: 10 * time.Second},
	}

	for _, r := range defaultRoutes {
		_ = gw.RegisterRoute(r)
	}

	return gw
}

func getEnvBackendURL(envVar, defaultHostPort string) string {
	if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
		return val
	}
	return defaultHostPort
}

// Authenticator returns the gateway's authentication component.
func (gw *APIGateway) Authenticator() *Authenticator {
	return gw.authenticator
}

// Idempotency returns the gateway's idempotency engine component.
func (gw *APIGateway) Idempotency() *IdempotencyEngine {
	return gw.idempotency
}

// Cache returns the gateway's RFC 9111 edge caching engine component.
func (gw *APIGateway) Cache() *RFC9111CacheEngine {
	return gw.cache
}

// AuditSpooler returns the gateway's audit spooler component.
func (gw *APIGateway) AuditSpooler() *AuditSpooler {
	return gw.auditSpooler
}

// Metrics returns the gateway's Prometheus operational metrics collector.
func (gw *APIGateway) Metrics() *MetricsCollector {
	return gw.metrics
}

// WebhookEngine returns the gateway's asynchronous webhook engine.
func (gw *APIGateway) WebhookEngine() *WebhookEngine {
	return gw.webhookEngine
}

// SetWebhookEngine replaces the gateway's webhook engine (e.g. for testing with custom timing).
func (gw *APIGateway) SetWebhookEngine(engine *WebhookEngine) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.webhookEngine != nil {
		gw.webhookEngine.Close()
	}
	gw.webhookEngine = engine
}

// EventEngine returns the gateway's real-time Server-Sent Events engine.
func (gw *APIGateway) EventEngine() *EventStreamEngine {
	return gw.eventEngine
}

// SetEventEngine replaces the gateway's event stream engine (e.g. for testing).
func (gw *APIGateway) SetEventEngine(engine *EventStreamEngine) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.eventEngine != nil {
		gw.eventEngine.Close()
	}
	gw.eventEngine = engine
}

// TracingEngine returns the gateway's distributed tracing engine.
func (gw *APIGateway) TracingEngine() *TracingEngine {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.tracingEngine
}

// SandboxEngine returns the gateway's live test mode sandbox engine.
func (gw *APIGateway) SandboxEngine() *SandboxEngine {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.sandboxEngine
}

// Versioning returns the gateway's versioning and evolution policy manager.
func (gw *APIGateway) Versioning() *VersioningPolicy {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.versioning
}

// SetTracingEngine replaces the gateway's distributed tracing engine.
func (gw *APIGateway) SetTracingEngine(engine *TracingEngine) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.tracingEngine = engine
}

// StateAdapter returns the active distributed cluster state adapter.
func (gw *APIGateway) StateAdapter() ClusterStateAdapter {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.stateAdapter
}

// SetStateAdapter overrides the cluster state adapter and updates subordinate engines.
func (gw *APIGateway) SetStateAdapter(adapter ClusterStateAdapter) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.stateAdapter != nil && gw.stateAdapter != adapter {
		_ = gw.stateAdapter.Close()
	}
	gw.stateAdapter = adapter
	if adapter != nil {
		gw.metrics.SetClusterMode(adapter.Name())
	}
	gw.limiter.SetStateAdapter(adapter)
	gw.idempotency.SetStateAdapter(adapter)
	gw.cache.SetStateAdapter(adapter)
}

// Proxies returns a snapshot mapping of registered path prefixes to upstream proxies.
func (gw *APIGateway) Proxies() map[string]*UpstreamProxy {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	res := make(map[string]*UpstreamProxy, len(gw.proxies))
	for k, v := range gw.proxies {
		res[k] = v
	}
	return res
}

// Close gracefully shuts down all upstream pool health check loops, webhook workers, and cluster state connections.
func (gw *APIGateway) Close() {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	for _, proxy := range gw.proxies {
		if proxy != nil {
			proxy.Close()
		}
	}
	if gw.webhookEngine != nil {
		gw.webhookEngine.Close()
	}
	if gw.eventEngine != nil {
		gw.eventEngine.Close()
	}
	if gw.auditSpooler != nil {
		gw.auditSpooler.Close()
	}
	if gw.stateAdapter != nil {
		_ = gw.stateAdapter.Close()
	}
}

// RegisterRoute adds or updates a dynamic route rule.
func (gw *APIGateway) RegisterRoute(rule RouteRule) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if strings.TrimSpace(rule.PathPrefix) == "" {
		return errors.New("route path prefix cannot be empty")
	}

	// SSRF Protection: Validate upstream URLs against cloud metadata endpoints
	var urlsToCheck []string
	if len(rule.UpstreamURLs) > 0 {
		urlsToCheck = rule.UpstreamURLs
	} else if rule.UpstreamURL != "" {
		for _, part := range strings.Split(rule.UpstreamURL, ",") {
			if t := strings.TrimSpace(part); t != "" {
				urlsToCheck = append(urlsToCheck, t)
			}
		}
	}
	for _, raw := range urlsToCheck {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid upstream URL '%s': %w", raw, err)
		}
		host := u.Hostname()
		if host == "169.254.169.254" || host == "metadata.google.internal" || host == "instance-data" {
			return fmt.Errorf("upstream URL '%s' attempts to access prohibited cloud instance metadata", raw)
		}
		isProd := os.Getenv("AEITRON_ENV") == "production" || os.Getenv("AEITRON_DEV_MODE") == "false"
		if isProd {
			if err := ValidateSafeTargetURL(raw); err != nil {
				return fmt.Errorf("unsafe upstream URL '%s': %w", raw, err)
			}
		}
	}

	// If updating an existing route, gracefully close the old pool's health checks
	if oldProxy, exists := gw.proxies[rule.PathPrefix]; exists && oldProxy != nil {
		oldProxy.Close()
	}

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

func (gw *APIGateway) matchRoute(rawPath string) (*RouteRule, *UpstreamProxy) {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	// Clean path to prevent path-traversal confusion (e.g. /v1/auth/../billing)
	cleanPath := path.Clean(rawPath)
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	for _, rule := range gw.routes {
		prefix := strings.TrimSuffix(rule.PathPrefix, "/")
		if prefix == "" {
			if cleanPath == "/" || strings.HasPrefix(cleanPath, "/") {
				proxy := gw.proxies[rule.PathPrefix]
				ruleCopy := rule
				return &ruleCopy, proxy
			}
			continue
		}
		// Strict segment matching: exact prefix or boundary with trailing slash
		if cleanPath == prefix || strings.HasPrefix(cleanPath, prefix+"/") {
			proxy := gw.proxies[rule.PathPrefix]
			ruleCopy := rule
			return &ruleCopy, proxy
		}
	}
	return nil, nil
}

// authorizeAdminRequest validates operator/admin credentials for internal gateway diagnostic endpoints.
// In production (AEITRON_ENV=production or AEITRON_DEV_MODE=false), unauthenticated access fails closed with 401 Unauthorized.
// When credentials are provided in any environment, test/sandbox keys (Livemode == false) are strictly forbidden (403 Forbidden).
// The caller must possess the "admin" or "operator" role, or explicit "gateway:admin" scope.
func (gw *APIGateway) authorizeMetricsScrape(r *http.Request) bool {
	// 1. Dedicated metrics bearer secret token (e.g. Prometheus Kubernetes Secret or Scraper secret)
	expectedMetricsToken := os.Getenv("AEITRON_METRICS_TOKEN")
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if expectedMetricsToken != "" {
		if authHeader == "Bearer "+expectedMetricsToken || r.Header.Get("X-Metrics-Token") == expectedMetricsToken {
			return true
		}
	}

	// 2. Standard Admin/Operator JWT credentials or API Key with metrics:read or gateway:admin scope
	if authCtx, err := gw.authenticator.AuthenticateRequest(r); err == nil && authCtx != nil {
		if authCtx.Role == "admin" || authCtx.Role == "operator" {
			return true
		}
		for _, s := range authCtx.Scopes {
			if s == "metrics:read" || s == "gateway:admin" || s == "*" {
				return true
			}
		}
	}

	// 3. Loopback scraper permitted if explicitly opted in
	clientIP := extractClientIP(r)
	if (clientIP == "127.0.0.1" || clientIP == "::1") && strings.EqualFold(os.Getenv("AEITRON_ALLOW_LOOPBACK_METRICS"), "true") {
		return true
	}

	return false
}

func (gw *APIGateway) authorizeAdminRequest(w http.ResponseWriter, r *http.Request) (*TenantContext, bool) {
	isProd := strings.EqualFold(os.Getenv("AEITRON_ENV"), "production") || strings.EqualFold(os.Getenv("AEITRON_DEV_MODE"), "false")
	authCtx, authErr := gw.authenticator.AuthenticateRequest(r)

	if authErr != nil || authCtx == nil {
		if isProd {
			WriteUnauthorized(w, r, "unauthorized: administrative endpoint requires authenticated operator credentials")
			return nil, false
		}
		// In dev/test mode without credentials, allow local test convenience
		return &TenantContext{
			TenantID: "system_dev",
			Role:     "operator",
			ActorID:  "act_dev_local",
			Scopes:   []string{"gateway:admin"},
			Livemode: true,
		}, true
	}

	// 1. Strict Security Invariant: Test and sandbox keys (Livemode == false) can NEVER access administrative routes!
	if !authCtx.Livemode {
		WriteForbidden(w, r, "forbidden: test and sandbox credentials cannot access administrative operations")
		return nil, false
	}

	// 2. Validate role & permissions: caller must have operator/admin role, or explicit gateway:admin scope
	hasAdminRole := authCtx.Role == "admin" || authCtx.Role == "operator"
	hasAdminScope := false
	for _, s := range authCtx.Scopes {
		if s == "gateway:admin" {
			hasAdminScope = true
			break
		}
	}
	if !hasAdminRole && !hasAdminScope {
		WriteForbidden(w, r, "forbidden: administrative operation requires operator or admin role or gateway:admin scope")
		return nil, false
	}

	return authCtx, true
}

func (gw *APIGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddInt64(&gw.stats.TotalRequests, 1)
	gw.metrics.IncInFlight()
	defer gw.metrics.DecInFlight()

	// Distributed Tracing: Extract or Start W3C Trace Context
	tc := gw.tracingEngine.ExtractOrStartTrace(r)
	rootSpan := tc.StartSpan("gateway.ingress", "SERVER")
	rootSpan.SetAttribute("http.method", r.Method)
	rootSpan.SetAttribute("http.target", r.URL.Path)
	rootSpan.SetAttribute("http.client_ip", extractClientIP(r))

	// Inject W3C Trace Context headers into incoming request and downstream response
	w.Header().Set("traceparent", tc.Traceparent())
	if tc.TraceState != "" {
		w.Header().Set("tracestate", tc.TraceState)
	}
	r.Header.Set("traceparent", tc.Traceparent())
	if tc.TraceState != "" {
		r.Header.Set("tracestate", tc.TraceState)
	}

	// Transparent on-the-fly streaming response compression (RFC 1952 / RFC 1951)
	cw := NewCompressingResponseWriter(w, r, DefaultMinCompressLength)
	defer func() {
		_ = cw.Close()
		if cw.Encoding() != "" {
			gw.metrics.RecordCompression(cw.UncompressedBytes(), cw.CompressedBytes(), cw.Encoding())
		}
		if tc != nil && rootSpan != nil {
			status := cw.StatusCode()
			tc.EndSpan(rootSpan, status, map[string]string{
				"http.status_code": fmt.Sprintf("%d", status),
			})
			tc.StatusCode = status
			gw.tracingEngine.RecordTrace(tc)
		}
	}()
	w = cw

	// 1. Security Headers & CORS
	ApplySecurityHeaders(w)
	if HandleCORS(w, r) {
		gw.metrics.RecordRequest(r.Method, "/cors", http.StatusNoContent, time.Since(start))
		return
	}

	// 2. Request Correlation ID
	reqID := ExtractOrGenerateRequestID(r)
	w.Header().Set("X-Request-ID", reqID)
	rootSpan.SetAttribute("http.request_id", reqID)

	// Stripe-Grade Date-Based API Version Negotiation (Aeitron-Version: YYYY-MM-DD)
	apiVersion, vMeta, vErr := gw.versioning.Negotiate(r)
	if vErr != nil {
		tc.EndSpan(rootSpan, http.StatusBadRequest, map[string]string{"error": vErr.Error()})
		gw.metrics.RecordRequest(r.Method, "/version_negotiation", http.StatusBadRequest, time.Since(start))
		WriteBadRequest(w, r, vErr.Error(), "INVALID_API_VERSION")
		return
	}
	gw.versioning.ApplyHeaders(w, apiVersion, vMeta)
	rootSpan.SetAttribute("api.version", apiVersion)
	if vMeta != nil && vMeta.IsDeprecated {
		rootSpan.SetAttribute("api.deprecated", "true")
	}

	// Livemode header detection (defaults to true for live production keys, false for test sandbox)
	if gw.sandboxEngine != nil && gw.sandboxEngine.IsSandbox(r, nil) {
		w.Header().Set("Aeitron-Livemode", "false")
	} else {
		w.Header().Set("Aeitron-Livemode", "true")
	}

	// Built-in Distributed Tracing Endpoints (/v1/gateway/traces)
	if gw.handleTraceEndpoints(w, r, start) {
		return
	}

	// 3. Built-in Gateway Endpoints & Documentation
	if ServeDocs(w, r) || ServeWebhookPortal(w, r) {
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/metrics" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		isProd := strings.EqualFold(os.Getenv("AEITRON_ENV"), "production") || strings.EqualFold(os.Getenv("AEITRON_DEV_MODE"), "false")
		if isProd && !gw.authorizeMetricsScrape(r) {
			WriteUnauthorized(w, r, "unauthorized: /metrics endpoint requires authenticated scraper credentials in production")
			gw.metrics.RecordRequest(r.Method, "/metrics", http.StatusUnauthorized, time.Since(start))
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(gw.metrics.RenderPrometheus(gw.Proxies())))
		}
		gw.metrics.RecordRequest(r.Method, "/metrics", http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/healthz" {
		writeJSONResponse(w, http.StatusOK, map[string]string{
			"status":  "healthy",
			"service": "aeitron-api-gateway",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/ready" {
		// Deep readiness probe: verify cluster state adapter connectivity
		gw.mu.RLock()
		adapter := gw.stateAdapter
		gw.mu.RUnlock()

		ready := true
		statusMsg := "ready"
		adapterName := "memory"

		if adapter != nil {
			adapterName = adapter.Name()
			pingCtx, pingCancel := context.WithTimeout(r.Context(), 1*time.Second)
			err := adapter.Ping(pingCtx)
			pingCancel()
			if err != nil {
				ready = false
				statusMsg = fmt.Sprintf("state cluster %s unreachable: %v", adapterName, err)
			}
		}

		if !ready {
			WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", statusMsg, "NOT_READY")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusServiceUnavailable, time.Since(start))
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status":  "ready",
			"service": "aeitron-api-gateway",
			"adapter": adapterName,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/v1/gateway/routes" {
		if _, ok := gw.authorizeAdminRequest(w, r); !ok {
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
			return
		}
		gw.mu.RLock()
		routes := make([]RouteRule, len(gw.routes))
		copy(routes, gw.routes)
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{"routes": routes})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/v1/gateway/stats" {
		if _, ok := gw.authorizeAdminRequest(w, r); !ok {
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
			return
		}
		gw.mu.RLock()
		st := gw.stats
		st.UptimeSeconds = int64(time.Since(gw.startTime).Seconds())
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, st)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/v1/gateway/upstreams" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if _, ok := gw.authorizeAdminRequest(w, r); !ok {
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
			return
		}
		gw.mu.RLock()
		upstreamsData := make(map[string]interface{})
		for prefix, proxy := range gw.proxies {
			if proxy != nil && proxy.Pool() != nil {
				pool := proxy.Pool()
				var nodeList []map[string]interface{}
				healthyCount := 0
				for _, n := range pool.Nodes() {
					isH := n.IsHealthy()
					if isH {
						healthyCount++
					}
					nodeList = append(nodeList, map[string]interface{}{
						"url":                  n.URLString(),
						"healthy":              n.healthy.Load(),
						"is_routable":          isH,
						"active_connections":   n.ActiveConnections(),
						"total_requests":       n.TotalRequests(),
						"circuit_breaker":      n.CircuitBreaker().State(),
						"consecutive_failures": n.ConsecutiveFailures(),
						"latency_micros":       n.lastLatencyMic.Load(),
						"last_checked_unix":    n.lastChecked.Load(),
					})
				}
				upstreamsData[prefix] = map[string]interface{}{
					"algorithm":     pool.Algorithm(),
					"total_nodes":   len(pool.Nodes()),
					"healthy_nodes": healthyCount,
					"nodes":         nodeList,
				}
			}
		}
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"upstreams": upstreamsData,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if (r.URL.Path == "/v1/gateway/cache/purge" || r.URL.Path == "/v1/gateway/cache") && (r.Method == http.MethodPost || r.Method == http.MethodDelete) {
		isProd := os.Getenv("AEITRON_ENV") == "production" || os.Getenv("AEITRON_DEV_MODE") == "false"
		actorID := "system_operator"
		tenantID := "system"

		// Enforce authentication & admin authorization
		authCtx, authErr := gw.authenticator.AuthenticateRequest(r)
		if authErr == nil && authCtx != nil {
			actorID = authCtx.ActorID
			tenantID = authCtx.TenantID
			// If not superuser (*), require admin role, operator role, or cache:purge scope
			if !CheckScopes(authCtx.Scopes, []string{"cache:purge"}) && authCtx.Role != "admin" && authCtx.Role != "operator" {
				WriteForbidden(w, r, "forbidden: cache purge requires admin role or cache:purge scope")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
				return
			}
		} else if isProd {
			WriteUnauthorized(w, r, "unauthorized: administrative cache purge requires authenticated operator")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
			return
		}

		var purgeReq struct {
			Prefix   string `json:"prefix"`
			PurgeAll bool   `json:"purge_all"`
		}
		_ = json.NewDecoder(r.Body).Decode(&purgeReq)
		evicted := 0
		if purgeReq.PurgeAll || (purgeReq.Prefix == "" && r.Method == http.MethodDelete) {
			evicted = gw.cache.PurgeAll()
		} else if purgeReq.Prefix != "" {
			evicted = gw.cache.InvalidatePrefix(purgeReq.Prefix)
		}
		gw.metrics.RecordCacheOp("PURGE")

		// Spool audit event for administrative mutation
		gw.auditSpooler.Spool(AuditRecord{
			RequestID:  reqID,
			TenantID:   tenantID,
			ActorID:    actorID,
			Method:     r.Method,
			Path:       r.URL.Path,
			ClientIP:   extractClientIP(r),
			StatusCode: http.StatusOK,
			DurationMs: time.Since(start).Milliseconds(),
			Timestamp:  time.Now().UTC(),
		})

		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status":        "purged",
			"evicted_count": evicted,
			"remaining":     gw.cache.Size(),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}

	// 4. Built-in Cluster State Telemetry (/v1/gateway/cluster)
	if r.URL.Path == "/v1/gateway/cluster" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if _, ok := gw.authorizeAdminRequest(w, r); !ok {
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
			return
		}
		gw.mu.RLock()
		adapter := gw.stateAdapter
		gw.mu.RUnlock()

		mode := "memory"
		status := "standalone"
		var pingLatencyMicros int64
		var addr string
		if adapter != nil {
			mode = adapter.Name()
			pStart := time.Now()
			ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
			err := adapter.Ping(ctx)
			cancel()
			pingLatencyMicros = time.Since(pStart).Microseconds()
			if err == nil {
				if mode == "redis" {
					status = "connected"
				} else {
					status = "standalone"
				}
			} else {
				status = "degraded"
			}
			if rAdapter, ok := adapter.(*RedisStateAdapter); ok {
				addr = rAdapter.cfg.Addr
			}
		}

		resp := map[string]interface{}{
			"mode":                mode,
			"status":              status,
			"ping_latency_micros": pingLatencyMicros,
			"cluster_errors":      gw.metrics.ClusterErrors(),
		}
		if addr != "" {
			resp["redis_addr"] = addr
		}

		writeJSONResponse(w, http.StatusOK, resp)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}

	// 5. IP-Level Token Bucket Rate Limiting (Protects all internal and proxy routes against IP floods)
	clientIP := extractClientIP(r)
	ipTier := DefaultRateLimits["ip_default"]
	rlSpan := tc.StartSpan("gateway.ratelimit", "INTERNAL")
	rlSpan.SetAttribute("ratelimit.key", "ip:"+clientIP)
	allowed, ipRemaining, retryAfter := gw.limiter.Allow("ip:"+clientIP, ipTier.RequestsPerSecond, ipTier.BurstCapacity)
	if !allowed {
		tc.EndSpan(rlSpan, http.StatusTooManyRequests, map[string]string{"ratelimit.allowed": "false"})
		atomic.AddInt64(&gw.stats.RateLimitedCount, 1)
		gw.metrics.RecordRateLimit("ip")
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusTooManyRequests, time.Since(start))
		WriteRateLimited(w, r, "too many requests from this IP: rate limit exceeded", int(retryAfter.Seconds()))
		return
	}
	tc.EndSpan(rlSpan, http.StatusOK, map[string]string{"ratelimit.allowed": "true"})

	// 5.1. Built-in Webhook Engine Endpoints (/v1/webhooks/...)
	if gw.handleWebhookEndpoints(w, r, start) {
		return
	}

	// 5.2. Built-in Real-Time Events Engine Endpoints (/v1/events/...)
	if gw.handleEventEndpoints(w, r, start) {
		return
	}

	// 5.3. Built-in Sandbox Simulation Endpoints (/v1/sandbox/...)
	if strings.HasPrefix(r.URL.Path, "/v1/sandbox") || strings.HasPrefix(r.URL.Path, "/sandbox") {
		var tCtx *TenantContext
		if authCtx, err := gw.authenticator.AuthenticateRequest(r); err == nil {
			tCtx = authCtx
		}
		if gw.sandboxEngine.HandleSandboxSimulation(w, r, tCtx, reqID) {
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
			return
		}
	}

	// 5.4. Built-in Local Fast Token Issuance (/v1/auth/token)
	if r.URL.Path == "/v1/auth/token" && r.Method == http.MethodPost {
		var tokenReq struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			APIKey       string `json:"api_key"`
		}
		bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		if err == nil {
			_ = json.Unmarshal(bodyBytes, &tokenReq)
			candidateKey := strings.TrimSpace(tokenReq.APIKey)
			if candidateKey == "" {
				WriteBadRequest(w, r, "api_key is required", "MISSING_API_KEY")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
				return
			}
			tenantCtx, vErr := gw.authenticator.validateAPIKey(candidateKey)
			if vErr != nil {
				WriteUnauthorized(w, r, "invalid api_key")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
				return
			}
			livemodeVal := tenantCtx.Livemode
			token, tErr := gw.authenticator.GenerateSignedToken(JWTClaims{
				Sub:       tenantCtx.ActorID,
				TenantID:  tenantCtx.TenantID,
				OrgID:     tenantCtx.OrgID,
				ProjectID: tenantCtx.ProjectID,
				Role:      tenantCtx.Role,
				Scopes:    tenantCtx.Scopes,
				Tier:      tenantCtx.Tier,
				Livemode:  &livemodeVal,
				Exp:       time.Now().Add(1 * time.Hour).Unix(),
			})
			if tErr != nil {
				WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "failed to generate token", "TOKEN_GEN_ERROR")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusInternalServerError, time.Since(start))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]interface{}{
				"access_token": token,
				"token_type":   "Bearer",
				"expires_in":   3600,
				"tenant_id":    tenantCtx.TenantID,
				"tier":         tenantCtx.Tier,
				"livemode":     tenantCtx.Livemode,
			})
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
			return
		}
	}

	// 6. Route Resolution
	rule, proxy := gw.matchRoute(r.URL.Path)
	if rule == nil || proxy == nil {
		gw.metrics.RecordRequest(r.Method, "/unmatched", http.StatusNotFound, time.Since(start))
		WriteNotFound(w, r, "route not found on api-gateway")
		return
	}

	// Enforce Body Size Limiting
	maxBody := int64(10 * 1024 * 1024) // 10MB default
	if rule.MaxBodyBytes > 0 {
		maxBody = rule.MaxBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	// 7. Strip Client Identity Headers (Prevent Tenant Spoofing)
	r.Header.Del("X-Tenant-ID")
	r.Header.Del("X-Org-ID")
	r.Header.Del("X-Project-ID")
	r.Header.Del("X-Actor-ID")
	r.Header.Del("X-Actor-Role")

	// 8. Authentication & Authorization Policy
	requiresAuth := !rule.AllowAnonymous

	var tenantCtx *TenantContext

	if requiresAuth {
		authSpan := tc.StartSpan("gateway.auth", "INTERNAL")
		ctx, err := gw.authenticator.AuthenticateRequest(r)
		if err != nil {
			tc.EndSpan(authSpan, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			atomic.AddInt64(&gw.stats.AuthFailedCount, 1)
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusUnauthorized, time.Since(start))
			WriteUnauthorized(w, r, fmt.Sprintf("unauthorized: %s", err.Error()))
			return
		}

		// Check permission scopes
		if !CheckScopes(ctx.Scopes, rule.RequiredScopes) {
			tc.EndSpan(authSpan, http.StatusForbidden, map[string]string{"error": "insufficient_scopes"})
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusForbidden, time.Since(start))
			WriteForbidden(w, r, "forbidden: insufficient permission scopes")
			return
		}

		tenantCtx = ctx
		w.Header().Set("Aeitron-Livemode", strconv.FormatBool(ctx.Livemode))
		tc.EndSpan(authSpan, http.StatusOK, map[string]string{
			"tenant_id": ctx.TenantID,
			"role":      ctx.Role,
			"tier":      ctx.Tier,
			"livemode":  strconv.FormatBool(ctx.Livemode),
		})

		// 9. Tenant-Level Rate Limiting
		tierName, tierConfig := ResolveRateLimitTier(ctx.Tier)

		tenantRlSpan := tc.StartSpan("gateway.ratelimit", "INTERNAL")
		tenantRlSpan.SetAttribute("ratelimit.key", "tenant:"+ctx.TenantID)
		tAllowed, tRemaining, tRetry := gw.limiter.Allow("tenant:"+ctx.TenantID, tierConfig.RequestsPerSecond, tierConfig.BurstCapacity)
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", tierConfig.BurstCapacity))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", tRemaining))

		if !tAllowed {
			tc.EndSpan(tenantRlSpan, http.StatusTooManyRequests, map[string]string{"ratelimit.allowed": "false"})
			atomic.AddInt64(&gw.stats.RateLimitedCount, 1)
			gw.metrics.RecordRateLimit(tierName)
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusTooManyRequests, time.Since(start))
			WriteRateLimited(w, r, fmt.Sprintf("rate limit exceeded for tenant '%s' on '%s' tier", ctx.TenantID, tierName), int(tRetry.Seconds()))
			return
		}
		tc.EndSpan(tenantRlSpan, http.StatusOK, map[string]string{"ratelimit.allowed": "true"})
	} else {
		// Optional authentication on anonymous read routes: if caller provided credentials, extract and populate tenant context
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			if ctx, err := gw.authenticator.AuthenticateRequest(r); err == nil && ctx != nil {
				tenantCtx = ctx
				w.Header().Set("Aeitron-Livemode", strconv.FormatBool(ctx.Livemode))
			}
		}
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", ipRemaining))
	}

	// 10. Stripe-grade Idempotency-Key Engine (Mutation Protection)
	var (
		idempKey    string
		isIdempReq  bool
		bodyBytes   []byte
		scopeTenant string
		idempSpan   *Span
	)

	if isMutationMethod(r.Method) {
		idempKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempKey == "" {
			idempKey = strings.TrimSpace(r.Header.Get("X-Idempotency-Key"))
		}
	}

	if idempKey != "" {
		idempSpan = tc.StartSpan("gateway.idempotency", "INTERNAL")
		idempSpan.SetAttribute("idempotency.key", idempKey)
		if err := ValidateIdempotencyKey(idempKey); err != nil {
			tc.EndSpan(idempSpan, http.StatusBadRequest, map[string]string{"error": err.Error()})
			gw.metrics.RecordIdempotencyOp("INVALID")
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusBadRequest, time.Since(start))
			WriteBadRequest(w, r, fmt.Sprintf("invalid idempotency key: %s", err.Error()), "INVALID_IDEMPOTENCY_KEY")
			return
		}

		scopeTenant = clientIP
		if tenantCtx != nil && tenantCtx.TenantID != "" {
			scopeTenant = tenantCtx.TenantID
		}

		// Read and restore request body for payload fingerprinting
		var readErr error
		bodyBytes, readErr = io.ReadAll(r.Body)
		if readErr != nil {
			tc.EndSpan(idempSpan, http.StatusBadRequest, map[string]string{"error": "read_error"})
			gw.metrics.RecordIdempotencyOp("READ_ERROR")
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusBadRequest, time.Since(start))
			WriteBadRequest(w, r, "unable to read request body for idempotency validation", "INVALID_REQUEST_BODY")
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		reqURI := r.URL.Path
		if r.URL.RawQuery != "" {
			reqURI = r.URL.Path + "?" + r.URL.RawQuery
		}

		rec, isReplay, acqErr := gw.idempotency.AcquireOrReplay(scopeTenant, idempKey, r.Method, reqURI, bodyBytes, 2*time.Second)
		if acqErr != nil {
			if errors.Is(acqErr, ErrClusterUnavailable) {
				tc.EndSpan(idempSpan, http.StatusServiceUnavailable, map[string]string{"error": "cluster_unavailable"})
				gw.metrics.RecordIdempotencyOp("CLUSTER_UNAVAILABLE")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusServiceUnavailable, time.Since(start))
				WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "cluster state store unreachable (fail-closed mode)", "CLUSTER_UNAVAILABLE")
				return
			}
			if errors.Is(acqErr, ErrIdempotencyMismatch) {
				tc.EndSpan(idempSpan, http.StatusConflict, map[string]string{"error": "mismatch"})
				gw.metrics.RecordIdempotencyOp("CONFLICT")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusConflict, time.Since(start))
				WriteConflict(w, r, "keys with identical idempotency values must send identical request parameters", "IDEMPOTENCY_KEY_MISMATCH")
				return
			}
			if errors.Is(acqErr, ErrIdempotencyInFlight) {
				tc.EndSpan(idempSpan, http.StatusConflict, map[string]string{"error": "in_flight"})
				gw.metrics.RecordIdempotencyOp("IN_FLIGHT")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusConflict, time.Since(start))
				w.Header().Set("Retry-After", "1")
				WriteConflict(w, r, "a request with this idempotency key is currently in progress", "IDEMPOTENCY_KEY_IN_FLIGHT")
				return
			}
			tc.EndSpan(idempSpan, http.StatusBadRequest, map[string]string{"error": acqErr.Error()})
			gw.metrics.RecordIdempotencyOp("ERROR")
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusBadRequest, time.Since(start))
			WriteBadRequest(w, r, acqErr.Error(), "IDEMPOTENCY_ERROR")
			return
		}

		if isReplay && rec != nil {
			tc.EndSpan(idempSpan, rec.StatusCode, map[string]string{"idempotency.replayed": "true"})
			// Replay cached response
			w.Header().Set("Idempotent-Replayed", "true")
			for k, v := range rec.Headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(rec.StatusCode)
			_, _ = w.Write(rec.ResponseBody)

			gw.mu.Lock()
			gw.stats.StatusCodes[rec.StatusCode]++
			gw.mu.Unlock()

			gw.metrics.RecordIdempotencyOp("REPLAYED")
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, rec.StatusCode, time.Since(start))
			return
		}

		tc.EndSpan(idempSpan, http.StatusOK, map[string]string{"idempotency.status": "acquired"})
		isIdempReq = true
	}

	// 11. RFC 9111 Edge Caching & ETag Validation (304 Not Modified)
	var (
		cacheKey        string
		isCacheEligible bool
	)

	cacheable, bypassLookup := gw.cache.IsRequestCacheable(r)
	if cacheable && rule.CacheTTL > 0 {
		isCacheEligible = true
		cacheScope := "public@" + apiVersion
		if tenantCtx != nil {
			cacheScope = tenantCtx.TenantID + "@" + apiVersion
		}

		cacheKey = gw.cache.NormalizeKey(cacheScope, r.Method, r.URL.Path, r.URL.RawQuery)
		cacheSpan := tc.StartSpan("gateway.cache", "INTERNAL")
		cacheSpan.SetAttribute("cache.key", cacheKey)

		if !bypassLookup {
			entry, hit := gw.cache.Lookup(cacheKey)
			if hit && entry != nil {
				// Conditional validation for 304 Not Modified
				if gw.cache.ValidateConditional(r, entry) {
					tc.EndSpan(cacheSpan, http.StatusNotModified, map[string]string{"cache.status": "304_NOT_MODIFIED"})
					w.Header().Set("ETag", entry.ETag)
					if entry.LastModified != "" {
						w.Header().Set("Last-Modified", entry.LastModified)
					}
					w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(entry.TTL.Seconds())))
					w.Header().Set("Age", fmt.Sprintf("%d", entry.AgeSeconds()))
					w.Header().Set("X-Cache", "HIT")
					w.WriteHeader(http.StatusNotModified)

					gw.mu.Lock()
					gw.stats.StatusCodes[http.StatusNotModified]++
					gw.mu.Unlock()

					gw.metrics.RecordCacheOp("304_NOT_MODIFIED")
					gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusNotModified, time.Since(start))
					return
				}

				// Cache Hit (Full 200 OK)
				tc.EndSpan(cacheSpan, entry.StatusCode, map[string]string{"cache.status": "HIT"})
				for k, v := range entry.Headers {
					w.Header().Set(k, v)
				}
				w.Header().Set("ETag", entry.ETag)
				if entry.LastModified != "" {
					w.Header().Set("Last-Modified", entry.LastModified)
				}
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(entry.TTL.Seconds())))
				w.Header().Set("Age", fmt.Sprintf("%d", entry.AgeSeconds()))
				w.Header().Set("X-Cache", "HIT")
				addVaryHeader(w, "Accept-Encoding")
				addVaryHeader(w, HeaderAeitronVersion)

				// Pre-compressed Cache Hit: serve cached Gzip bytes directly with zero CPU overhead
				if SelectEncoding(r.Header.Get("Accept-Encoding")) == EncodingGzip && len(entry.GzipBody) > 0 {
					w.Header().Set("Content-Encoding", EncodingGzip)
					w.Header().Del("Content-Length")
					w.WriteHeader(entry.StatusCode)
					if r.Method != http.MethodHead {
						_, _ = w.Write(entry.GzipBody)
					}
					gw.metrics.RecordCompression(int64(len(entry.Body)), int64(len(entry.GzipBody)), EncodingGzip)
				} else {
					w.WriteHeader(entry.StatusCode)
					if r.Method != http.MethodHead {
						_, _ = w.Write(entry.Body)
					}
				}

				gw.mu.Lock()
				gw.stats.StatusCodes[entry.StatusCode]++
				gw.mu.Unlock()

				gw.metrics.RecordCacheOp("HIT")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, entry.StatusCode, time.Since(start))
				return
			}
		}
		tc.EndSpan(cacheSpan, 0, map[string]string{"cache.status": "MISS"})
	}

	// 12. Forward via Reverse Proxy (or Sandbox Simulation if in live test mode)
	wrapper := NewResponseWriterWrapper(w)
	if isIdempReq || isCacheEligible {
		wrapper.BodyBuffer = &bytes.Buffer{}
	}
	if isCacheEligible {
		w.Header().Set("X-Cache", "MISS")
		gw.metrics.RecordCacheOp("MISS")
	}

	if gw.sandboxEngine != nil && gw.sandboxEngine.IsSandbox(r, tenantCtx) && gw.sandboxEngine.HandleSandboxSimulation(wrapper, r, tenantCtx, reqID) {
		// Sandboxed simulation executed without touching real infrastructure
		w.Header().Set("Aeitron-Livemode", "false")
	} else {
		upSpan := tc.StartSpan("gateway.upstream", "CLIENT")
		upSpan.SetAttribute("upstream.route", rule.PathPrefix)
		upSpan.SetAttribute("upstream.url", proxy.UpstreamURL())
		// Send child span traceparent to upstream
		r.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-%s", tc.TraceID, upSpan.SpanID, tc.TraceFlags))

		proxy.ServeHTTP(wrapper, r, tenantCtx, reqID)

		upAttrs := map[string]string{
			"http.status_code": fmt.Sprintf("%d", wrapper.StatusCode),
		}
		if bNode := wrapper.Header().Get("X-Backend-Node"); bNode != "" {
			upAttrs["backend.node"] = bNode
		}
		tc.EndSpan(upSpan, wrapper.StatusCode, upAttrs)
	}

	duration := time.Since(start)

	// RFC 9111 Cache Population on successful read
	if isCacheEligible && wrapper.StatusCode == http.StatusOK {
		if gw.cache.IsResponseCacheable(wrapper.StatusCode, r.Header, wrapper.Header()) {
			ttl := gw.cache.ParseUpstreamTTL(wrapper.Header(), rule.CacheTTL)
			if ttl > 0 {
				gw.cache.Store(cacheKey, r.URL.Path, wrapper.StatusCode, wrapper.Header(), wrapper.BodyBuffer.Bytes(), ttl)
				gw.metrics.RecordCacheOp("STORE")
			}
		}
	}

	// RFC 9111 Section 4.4 Invalidation on successful state mutations
	if isMutationMethod(r.Method) && wrapper.StatusCode >= 200 && wrapper.StatusCode < 400 {
		gw.cache.InvalidatePrefix(r.URL.Path)
		if rule.PathPrefix != "" {
			gw.cache.InvalidatePrefix(rule.PathPrefix)
		}
	}

	// Complete or abort idempotency lock based on response code
	if isIdempReq {
		if wrapper.StatusCode < 500 {
			gw.idempotency.Complete(scopeTenant, idempKey, wrapper.StatusCode, wrapper.Header(), wrapper.BodyBuffer.Bytes())
			gw.metrics.RecordIdempotencyOp("NEW")
		} else {
			// Server faults (5xx) do not lock or cache, allowing safe retry
			gw.idempotency.Abort(scopeTenant, idempKey)
			gw.metrics.RecordIdempotencyOp("ABORTED")
		}
	}

	// 13. Record Metrics and Stats
	gw.metrics.RecordRequest(r.Method, rule.PathPrefix, wrapper.StatusCode, duration)

	gw.mu.Lock()
	gw.stats.StatusCodes[wrapper.StatusCode]++
	gw.mu.Unlock()

	// 13. Centralized Audit Logging on State Mutations
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

// extractClientIP extracts and validates the client IP address.
// Forwarding headers (X-Forwarded-For, X-Real-IP) are ONLY trusted if the immediate peer (RemoteAddr)
// matches a configured trusted proxy in AEITRON_TRUSTED_PROXIES (e.g. "127.0.0.1,10.0.0.0/8,172.16.0.0/12").
// If the immediate peer is untrusted or no trusted proxies are configured, RemoteAddr is strictly used.
func extractClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	remoteIP := net.ParseIP(remoteHost)

	trustedProxiesEnv := os.Getenv("AEITRON_TRUSTED_PROXIES")
	if trustedProxiesEnv != "" && remoteIP != nil {
		if isPeerTrustedProxy(remoteIP, trustedProxiesEnv) {
			// Peer is a trusted proxy: parse X-Forwarded-For from right to left (most recent untrusted hop)
			if xfwd := r.Header.Get("X-Forwarded-For"); xfwd != "" {
				parts := strings.Split(xfwd, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					cand := strings.TrimSpace(parts[i])
					if candIP := net.ParseIP(cand); candIP != nil {
						if !isPeerTrustedProxy(candIP, trustedProxiesEnv) {
							return candIP.String()
						}
					}
				}
				if firstIP := net.ParseIP(strings.TrimSpace(parts[0])); firstIP != nil {
					return firstIP.String()
				}
			}
			if xreal := r.Header.Get("X-Real-IP"); xreal != "" {
				if realIP := net.ParseIP(strings.TrimSpace(xreal)); realIP != nil {
					return realIP.String()
				}
			}
		}
	}

	if remoteIP != nil {
		return remoteIP.String()
	}
	return remoteHost
}

func isPeerTrustedProxy(ip net.IP, trustedConfig string) bool {
	for _, entry := range strings.Split(trustedConfig, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(entry); err == nil && ipNet != nil {
			if ipNet.Contains(ip) {
				return true
			}
		} else if parsed := net.ParseIP(entry); parsed != nil {
			if parsed.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func isMutationMethod(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete
}

func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func maskWebhookSecret(s string) string {
	if s == "" {
		return ""
	}
	return "whsec_****************"
}

func (gw *APIGateway) handleWebhookEndpoints(w http.ResponseWriter, r *http.Request, start time.Time) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/webhooks") && !strings.HasPrefix(r.URL.Path, "/webhooks") {
		return false
	}

	// 0. Developer Portal HUD (/v1/webhooks/portal or /webhooks/portal)
	if (r.URL.Path == "/v1/webhooks/portal" || r.URL.Path == "/webhooks/portal" || r.URL.Path == "/portal") && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(webhookPortalHTML))
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	authCtx, authErr := gw.authenticator.AuthenticateRequest(r)
	if authErr != nil || authCtx == nil {
		WriteUnauthorized(w, r, "unauthorized: authentication required for webhook operations")
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
		return true
	}
	tenantID := authCtx.TenantID

	// Enforce tenant-tier token bucket rate limits
	tierName, tierLimits := ResolveRateLimitTier(authCtx.Tier)
	allowed, _, retryAfter := gw.limiter.Allow("tenant:"+tenantID+":webhooks", tierLimits.RequestsPerSecond, tierLimits.BurstCapacity)
	if !allowed {
		gw.metrics.RecordRateLimit(tierName)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusTooManyRequests, time.Since(start))
		WriteRateLimited(w, r, "rate limit exceeded for tier "+tierName, int(retryAfter.Seconds()))
		return true
	}

	canRead := authCtx.Role == "admin" || authCtx.Role == "operator" || CheckScopes(authCtx.Scopes, []string{"webhooks:read"})
	canWrite := authCtx.Role == "admin" || authCtx.Role == "operator" || CheckScopes(authCtx.Scopes, []string{"webhooks:write"})

	// 0.5. POST /v1/webhooks/test (Interactive Webhook Simulation Engine)
	if r.URL.Path == "/v1/webhooks/test" && r.Method == http.MethodPost {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		var testReq struct {
			URL       string          `json:"url"`
			Secret    string          `json:"secret"`
			EventType string          `json:"event_type"`
			Data      json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&testReq); err != nil {
			WriteBadRequest(w, r, fmt.Sprintf("invalid test payload: %v", err), "INVALID_PAYLOAD")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		res, err := gw.webhookEngine.TestWebhook(r.Context(), testReq.URL, testReq.Secret, testReq.EventType, testReq.Data)
		if err != nil {
			WriteBadRequest(w, r, err.Error(), "TEST_FAILED")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		writeJSONResponse(w, http.StatusOK, res)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 1. POST /v1/webhooks/subscriptions (Create subscription)
	if r.URL.Path == "/v1/webhooks/subscriptions" && r.Method == http.MethodPost {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		var req CreateSubscriptionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteBadRequest(w, r, fmt.Sprintf("invalid request payload: %v", err), "INVALID_PAYLOAD")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		sub, err := gw.webhookEngine.CreateSubscription(tenantID, req)
		if err != nil {
			WriteBadRequest(w, r, err.Error(), "INVALID_SUBSCRIPTION")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
			"subscription": sub,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusCreated, time.Since(start))
		return true
	}

	// 1.5. POST /v1/webhooks/subscriptions/{id}/rotate-secret (Rotate HMAC secret)
	if strings.HasPrefix(r.URL.Path, "/v1/webhooks/subscriptions/") && strings.HasSuffix(r.URL.Path, "/rotate-secret") && r.Method == http.MethodPost {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/webhooks/subscriptions/"), "/rotate-secret")
		newSecret, err := gw.webhookEngine.RotateSecret(tenantID, id)
		if err != nil {
			WriteNotFound(w, r, "webhook subscription not found")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
			return true
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status": "rotated",
			"id":     id,
			"secret": newSecret,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 2. GET /v1/webhooks/subscriptions (List subscriptions - secret redacted)
	if r.URL.Path == "/v1/webhooks/subscriptions" && r.Method == http.MethodGet {
		if !canRead {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:read'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		subs := gw.webhookEngine.ListSubscriptions(tenantID)
		maskedSubs := make([]*WebhookSubscription, len(subs))
		for i, s := range subs {
			cp := *s
			cp.Secret = maskWebhookSecret(cp.Secret)
			maskedSubs[i] = &cp
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"subscriptions": maskedSubs,
			"count":         len(maskedSubs),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 3. GET /v1/webhooks/subscriptions/{id} (Get subscription by ID - secret redacted)
	if strings.HasPrefix(r.URL.Path, "/v1/webhooks/subscriptions/") && !strings.HasSuffix(r.URL.Path, "/rotate-secret") && r.Method == http.MethodGet {
		if !canRead {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:read'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/webhooks/subscriptions/")
		sub, err := gw.webhookEngine.GetSubscription(tenantID, id)
		if err != nil {
			WriteNotFound(w, r, "webhook subscription not found")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
			return true
		}
		subCopy := *sub
		subCopy.Secret = maskWebhookSecret(subCopy.Secret)
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"subscription": &subCopy,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 4. DELETE /v1/webhooks/subscriptions/{id} (Delete subscription by ID)
	if strings.HasPrefix(r.URL.Path, "/v1/webhooks/subscriptions/") && r.Method == http.MethodDelete {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/webhooks/subscriptions/")
		err := gw.webhookEngine.DeleteSubscription(tenantID, id)
		if err != nil {
			WriteNotFound(w, r, "webhook subscription not found")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
			return true
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status": "deleted",
			"id":     id,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 5. POST /v1/webhooks/dispatch (Dispatch asynchronous cloud event notification)
	if r.URL.Path == "/v1/webhooks/dispatch" && r.Method == http.MethodPost {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		var event WebhookEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			WriteBadRequest(w, r, fmt.Sprintf("invalid event payload: %v", err), "INVALID_PAYLOAD")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		if event.TenantID != "" && event.TenantID != tenantID {
			if authCtx.Role != "admin" && authCtx.Role != "operator" {
				WriteForbidden(w, r, "forbidden: cross-tenant webhook dispatch is forbidden")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
				return true
			}
		} else {
			event.TenantID = tenantID
		}
		deliveries, err := gw.webhookEngine.Dispatch(event)
		if err != nil {
			WriteBadRequest(w, r, err.Error(), "DISPATCH_FAILED")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		if gw.eventEngine != nil {
			for _, d := range deliveries {
				delJSON, _ := json.Marshal(d)
				gw.eventEngine.Publish(InfrastructureEvent{
					ID:        d.ID,
					Topic:     "webhooks.deliveries",
					TenantID:  event.TenantID,
					Type:      "webhook.delivery.scheduled",
					Data:      delJSON,
					Timestamp: time.Now().UTC(),
				})
			}
		}
		writeJSONResponse(w, http.StatusAccepted, map[string]interface{}{
			"status":     "dispatched",
			"event_id":   event.ID,
			"event_type": event.Type,
			"deliveries": deliveries,
			"count":      len(deliveries),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusAccepted, time.Since(start))
		return true
	}

	// 6. GET /v1/webhooks/deliveries (List delivery history)
	if r.URL.Path == "/v1/webhooks/deliveries" && r.Method == http.MethodGet {
		if !canRead {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:read'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		deliveries := gw.webhookEngine.ListDeliveries(tenantID)
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"deliveries": deliveries,
			"count":      len(deliveries),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 7. GET /v1/webhooks/dead-letter (List dead letter queue)
	if r.URL.Path == "/v1/webhooks/dead-letter" && r.Method == http.MethodGet {
		if !canRead {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:read'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		deadLetters := gw.webhookEngine.ListDeadLetters(tenantID)
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"dead_letters": deadLetters,
			"count":        len(deadLetters),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 8. POST /v1/webhooks/dead-letter/retry (Redeliver failed webhook from DLQ)
	if r.URL.Path == "/v1/webhooks/dead-letter/retry" && r.Method == http.MethodPost {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'webhooks:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		var retryReq struct {
			DeliveryID string `json:"delivery_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&retryReq); err != nil {
			WriteBadRequest(w, r, fmt.Sprintf("invalid retry payload: %v", err), "INVALID_PAYLOAD")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		if retryReq.DeliveryID == "" {
			WriteBadRequest(w, r, "delivery_id is required", "MISSING_DELIVERY_ID")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		del, err := gw.webhookEngine.Redeliver(tenantID, retryReq.DeliveryID)
		if err != nil {
			if errors.Is(err, ErrWebhookDeadLetterNotFound) {
				WriteNotFound(w, r, err.Error())
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
				return true
			}
			WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", err.Error(), "INTERNAL_ERROR")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusInternalServerError, time.Since(start))
			return true
		}
		if gw.eventEngine != nil {
			delJSON, _ := json.Marshal(del)
			gw.eventEngine.Publish(InfrastructureEvent{
				ID:        del.ID,
				Topic:     "webhooks.dead_letter",
				TenantID:  tenantID,
				Type:      "webhook.delivery.redelivered",
				Data:      delJSON,
				Timestamp: time.Now().UTC(),
			})
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status":   "redelivery_scheduled",
			"delivery": del,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	WriteNotFound(w, r, "webhook endpoint not found")
	gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
	return true
}

func (gw *APIGateway) handleEventEndpoints(w http.ResponseWriter, r *http.Request, start time.Time) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/events") && !strings.HasPrefix(r.URL.Path, "/events") {
		return false
	}

	authCtx, authErr := gw.authenticator.AuthenticateRequest(r)
	if authErr != nil || authCtx == nil {
		WriteUnauthorized(w, r, "unauthorized: authentication required for event operations")
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
		return true
	}
	tenantID := authCtx.TenantID

	// Enforce tenant-tier token bucket rate limits
	tierName, tierLimits := ResolveRateLimitTier(authCtx.Tier)
	allowed, _, retryAfter := gw.limiter.Allow("tenant:"+tenantID+":events", tierLimits.RequestsPerSecond, tierLimits.BurstCapacity)
	if !allowed {
		gw.metrics.RecordRateLimit(tierName)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusTooManyRequests, time.Since(start))
		WriteRateLimited(w, r, "rate limit exceeded for tier "+tierName, int(retryAfter.Seconds()))
		return true
	}

	canRead := authCtx.Role == "admin" || authCtx.Role == "operator" || CheckScopes(authCtx.Scopes, []string{"events:read"})
	canWrite := authCtx.Role == "admin" || authCtx.Role == "operator" || CheckScopes(authCtx.Scopes, []string{"events:write"})

	// 1. GET /v1/events/stream or /events/stream (Server-Sent Events Real-Time Streaming)
	if (r.URL.Path == "/v1/events/stream" || r.URL.Path == "/events/stream") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if !canRead {
			WriteForbidden(w, r, "forbidden: missing required scope 'events:read'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		if gw.eventEngine == nil {
			WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "events streaming engine is not initialized", "SERVICE_UNAVAILABLE")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusServiceUnavailable, time.Since(start))
			return true
		}
		gw.eventEngine.ServeHTTP(w, r, tenantID)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 2. POST /v1/events/publish or /events/publish (Broadcast event to real-time subscribers & history)
	if (r.URL.Path == "/v1/events/publish" || r.URL.Path == "/events/publish") && r.Method == http.MethodPost {
		if !canWrite {
			WriteForbidden(w, r, "forbidden: missing required scope 'events:write'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		if gw.eventEngine == nil {
			WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "events streaming engine is not initialized", "SERVICE_UNAVAILABLE")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusServiceUnavailable, time.Since(start))
			return true
		}
		var evt InfrastructureEvent
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			WriteBadRequest(w, r, fmt.Sprintf("invalid event payload: %v", err), "INVALID_PAYLOAD")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		if evt.TenantID != "" && evt.TenantID != tenantID {
			if authCtx.Role != "admin" && authCtx.Role != "operator" {
				WriteForbidden(w, r, "forbidden: cross-tenant event publishing is forbidden")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
				return true
			}
		} else {
			evt.TenantID = tenantID
		}
		if strings.TrimSpace(evt.Topic) == "" {
			WriteBadRequest(w, r, "topic field is required", "MISSING_TOPIC")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		if strings.TrimSpace(evt.Type) == "" {
			WriteBadRequest(w, r, "type field is required", "MISSING_TYPE")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		published := gw.eventEngine.Publish(evt)
		writeJSONResponse(w, http.StatusAccepted, map[string]interface{}{
			"status":    "published",
			"event_id":  published.ID,
			"topic":     published.Topic,
			"type":      published.Type,
			"timestamp": published.Timestamp,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusAccepted, time.Since(start))
		return true
	}

	// 3. GET /v1/events/history or /events/history (Query recent event ring buffer)
	if (r.URL.Path == "/v1/events/history" || r.URL.Path == "/events/history") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if !canRead {
			WriteForbidden(w, r, "forbidden: missing required scope 'events:read'")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
			return true
		}
		if gw.eventEngine == nil {
			WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", "events streaming engine is not initialized", "SERVICE_UNAVAILABLE")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusServiceUnavailable, time.Since(start))
			return true
		}
		topic := r.URL.Query().Get("topic")
		limitStr := r.URL.Query().Get("limit")
		limit := 50
		if limitStr != "" {
			if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
				limit = parsed
				if limit > 500 {
					limit = 500
				}
			}
		}
		history := gw.eventEngine.GetRecentHistory(tenantID, topic, limit)
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"events": history,
			"count":  len(history),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	WriteNotFound(w, r, "events endpoint not found")
	gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
	return true
}

func (gw *APIGateway) handleTraceEndpoints(w http.ResponseWriter, r *http.Request, start time.Time) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/gateway/traces") {
		return false
	}

	// Protect all internal distributed tracing endpoints with administrative authorization
	if _, ok := gw.authorizeAdminRequest(w, r); !ok {
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
		return true
	}

	// 1. GET /v1/gateway/traces (List recent traces)
	if r.URL.Path == "/v1/gateway/traces" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		var minDurationMs int
		if dStr := r.URL.Query().Get("min_duration_ms"); dStr != "" {
			if d, err := strconv.Atoi(dStr); err == nil && d > 0 {
				minDurationMs = d
			}
		}
		var statusFilter int
		if sStr := r.URL.Query().Get("status"); sStr != "" {
			if s, err := strconv.Atoi(sStr); err == nil && s > 0 {
				statusFilter = s
			}
		}

		traces := gw.tracingEngine.RecentTraces(limit, minDurationMs, statusFilter)
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"traces": traces,
			"count":  len(traces),
			"stats":  gw.tracingEngine.Stats(),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 2. GET /v1/gateway/traces/slow (List slow traces exceeding budget >50ms)
	if r.URL.Path == "/v1/gateway/traces/slow" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}
		slowTraces := gw.tracingEngine.SlowTraces(limit)
		stats := gw.tracingEngine.Stats()
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"slow_traces":         slowTraces,
			"count":               len(slowTraces),
			"slow_threshold_ms":   stats.SlowThresholdMs,
			"total_slow_detected": stats.SlowTracesTotal,
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 3. GET /v1/gateway/traces/stats (Tracing buffer telemetry)
	if r.URL.Path == "/v1/gateway/traces/stats" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		writeJSONResponse(w, http.StatusOK, gw.tracingEngine.Stats())
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 4. POST /v1/gateway/traces/config (Dynamic configuration of sampling rate and slow threshold)
	if r.URL.Path == "/v1/gateway/traces/config" && r.Method == http.MethodPost {
		isProd := os.Getenv("AEITRON_ENV") == "production" || os.Getenv("AEITRON_DEV_MODE") == "false"
		authCtx, authErr := gw.authenticator.AuthenticateRequest(r)
		if authErr == nil && authCtx != nil {
			if !CheckScopes(authCtx.Scopes, []string{"traces:admin"}) && authCtx.Role != "admin" && authCtx.Role != "operator" {
				WriteForbidden(w, r, "forbidden: updating trace config requires admin role or traces:admin scope")
				gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
				return true
			}
		} else if isProd {
			WriteUnauthorized(w, r, "unauthorized: trace config mutation requires authenticated operator")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusUnauthorized, time.Since(start))
			return true
		}

		var cfg struct {
			SamplingRate    *float64 `json:"sampling_rate"`
			SlowThresholdMs *int64   `json:"slow_threshold_ms"`
		}
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			WriteBadRequest(w, r, fmt.Sprintf("invalid config payload: %v", err), "INVALID_PAYLOAD")
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusBadRequest, time.Since(start))
			return true
		}
		if cfg.SamplingRate != nil {
			gw.tracingEngine.SetSamplingRate(*cfg.SamplingRate)
		}
		if cfg.SlowThresholdMs != nil && *cfg.SlowThresholdMs > 0 {
			gw.tracingEngine.SetSlowThreshold(time.Duration(*cfg.SlowThresholdMs) * time.Millisecond)
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status": "updated",
			"stats":  gw.tracingEngine.Stats(),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 5. GET /v1/gateway/traces/{trace_id}/export (Export in OTLP, Jaeger, or Zipkin format)
	if strings.HasSuffix(r.URL.Path, "/export") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		trimmed := strings.TrimPrefix(r.URL.Path, "/v1/gateway/traces/")
		traceID := strings.TrimSuffix(trimmed, "/export")
		tc, exists := gw.tracingEngine.GetTrace(traceID)
		if !exists {
			WriteNotFound(w, r, fmt.Sprintf("trace '%s' not found or expired from ring buffer", traceID))
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
			return true
		}

		format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
		switch format {
		case "jaeger":
			writeJSONResponse(w, http.StatusOK, gw.tracingEngine.ExportJaegerFormat(tc))
		case "zipkin":
			writeJSONResponse(w, http.StatusOK, gw.tracingEngine.ExportZipkinFormat(tc))
		default: // "otlp"
			writeJSONResponse(w, http.StatusOK, gw.tracingEngine.ExportOTLPFormat(tc))
		}
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	// 6. GET /v1/gateway/traces/{trace_id} (Detailed trace with all spans)
	if strings.HasPrefix(r.URL.Path, "/v1/gateway/traces/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		traceID := strings.TrimPrefix(r.URL.Path, "/v1/gateway/traces/")
		tc, exists := gw.tracingEngine.GetTrace(traceID)
		if !exists {
			WriteNotFound(w, r, fmt.Sprintf("trace '%s' not found or expired from ring buffer", traceID))
			gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
			return true
		}
		writeJSONResponse(w, http.StatusOK, tc)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return true
	}

	WriteNotFound(w, r, "trace endpoint not found")
	gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusNotFound, time.Since(start))
	return true
}
