package apigateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	idempotency   *IdempotencyEngine
	cache         *RFC9111CacheEngine
	metrics       *MetricsCollector
	auditSpooler  *AuditSpooler
	stats         GatewayStats
	startTime     time.Time
}

// NewAPIGateway initializes an APIGateway with default core services.
func NewAPIGateway(jwtSecret string) *APIGateway {
	start := time.Now().UTC()
	gw := &APIGateway{
		proxies:       make(map[string]*UpstreamProxy),
		authenticator: NewAuthenticator(jwtSecret),
		limiter:       NewTokenBucketLimiter(),
		idempotency:   NewIdempotencyEngine(24 * time.Hour),
		cache:         NewRFC9111CacheEngine(10000, 64*1024*1024),
		metrics:       NewMetricsCollector(start),
		auditSpooler:  NewAuditSpooler(2000),
		stats: GatewayStats{
			StatusCodes:    make(map[int]int64),
			UpstreamStatus: make(map[string]string),
		},
		startTime: start,
	}

	// Register canonical Aeitron platform microservices and product family routes
	defaultRoutes := []RouteRule{
		// Identity, Authentication, and Multi-Tenant RBAC
		{PathPrefix: "/v1/auth", UpstreamURL: "http://127.0.0.1:9092", AllowAnonymous: true, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/identity", UpstreamURL: "http://127.0.0.1:9092", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/organizations", UpstreamURL: "http://127.0.0.1:9093", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/audit", UpstreamURL: "http://127.0.0.1:9094", AllowAnonymous: false, RequiredScopes: []string{"audit:read"}, Timeout: 15 * time.Second},

		// Sovereign Databases and Automated Backups
		{PathPrefix: "/v1/databases", UpstreamURL: "http://127.0.0.1:9095", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/backups", UpstreamURL: "http://127.0.0.1:9097", AllowAnonymous: false, Timeout: 30 * time.Second},

		// Global Fleet Canary Orchestration
		{PathPrefix: "/v1/fleet", UpstreamURL: "http://127.0.0.1:9096", AllowAnonymous: false, RequiredScopes: []string{"fleet:read"}, Timeout: 15 * time.Second},

		// Real-time Metering, Telemetry, and Multi-channel Notifications
		{PathPrefix: "/v1/usage", UpstreamURL: "http://127.0.0.1:8099", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/notifications", UpstreamURL: "http://127.0.0.1:8100", AllowAnonymous: false, Timeout: 10 * time.Second},

		// Financial Ledger, Invoicing, and Sovereign Billing
		{PathPrefix: "/v1/billing", UpstreamURL: "http://127.0.0.1:8097", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/commerce", UpstreamURL: "http://127.0.0.1:8098", AllowAnonymous: true, Timeout: 15 * time.Second},

		// Canonical Product Domains (Route directly with URL rewriting to commerce backend)
		{PathPrefix: "/v1/catalog", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/catalog", AllowAnonymous: true, CacheTTL: 60 * time.Second, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/orders", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/orders", AllowAnonymous: false, Timeout: 20 * time.Second},
		{PathPrefix: "/v1/domains", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/domains", AllowAnonymous: true, CacheTTL: 30 * time.Second, Timeout: 20 * time.Second},
		{PathPrefix: "/v1/status", UpstreamURL: "http://127.0.0.1:3002", AllowAnonymous: true, CacheTTL: 15 * time.Second, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/hosting", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/hosting", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/compute", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/compute", AllowAnonymous: false, Timeout: 30 * time.Second},
		{PathPrefix: "/v1/subscriptions", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/subscriptions", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/invoices", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/invoices", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/emails", UpstreamURL: "http://127.0.0.1:8098", RewritePrefix: "/v1/commerce/emails", AllowAnonymous: false, Timeout: 15 * time.Second},

		// Authoritative Anycast DNS, Global Traffic Director, Edge WAF, and Security
		{PathPrefix: "/v1/dns", UpstreamURL: "http://127.0.0.1:8053", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/router", UpstreamURL: "http://127.0.0.1:9090", AllowAnonymous: false, Timeout: 10 * time.Second},
		{PathPrefix: "/v1/edge", UpstreamURL: "http://127.0.0.1:9091", AllowAnonymous: false, Timeout: 15 * time.Second},
		{PathPrefix: "/v1/security", UpstreamURL: "http://127.0.0.1:8054", AllowAnonymous: false, Timeout: 10 * time.Second},
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
	gw.metrics.IncInFlight()
	defer gw.metrics.DecInFlight()

	// 1. Security Headers & CORS
	ApplySecurityHeaders(w)
	if HandleCORS(w, r) {
		gw.metrics.RecordRequest(r.Method, "/cors", http.StatusNoContent, time.Since(start))
		return
	}

	// 2. Request Correlation ID
	reqID := ExtractOrGenerateRequestID(r)
	w.Header().Set("X-Request-ID", reqID)

	// 3. Built-in Gateway Endpoints & Documentation
	if ServeDocs(w, r) {
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/metrics" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(gw.metrics.RenderPrometheus(gw.Proxies())))
		}
		gw.metrics.RecordRequest(r.Method, "/metrics", http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/healthz" || r.URL.Path == "/ready" {
		writeJSONResponse(w, http.StatusOK, map[string]string{
			"status":  "healthy",
			"service": "aeitron-api-gateway",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/v1/gateway/routes" {
		gw.mu.RLock()
		routes := make([]RouteRule, len(gw.routes))
		copy(routes, gw.routes)
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{"routes": routes})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if r.URL.Path == "/v1/gateway/stats" {
		gw.mu.RLock()
		st := gw.stats
		st.UptimeSeconds = int64(time.Since(gw.startTime).Seconds())
		gw.mu.RUnlock()
		writeJSONResponse(w, http.StatusOK, st)
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}
	if (r.URL.Path == "/v1/gateway/cache/purge" || r.URL.Path == "/v1/gateway/cache") && (r.Method == http.MethodPost || r.Method == http.MethodDelete) {
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
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status":        "purged",
			"evicted_count": evicted,
			"remaining":     gw.cache.Size(),
		})
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
		return
	}

	// 4. Built-in Local Fast Token Issuance (/v1/auth/token)
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
				candidateKey = strings.TrimSpace(tokenReq.ClientID)
			}
			if candidateKey != "" {
				tenantCtx, vErr := gw.authenticator.validateAPIKey(candidateKey)
				if vErr == nil {
					token, tErr := gw.authenticator.GenerateSignedToken(JWTClaims{
						Sub:       tenantCtx.ActorID,
						TenantID:  tenantCtx.TenantID,
						OrgID:     tenantCtx.OrgID,
						ProjectID: tenantCtx.ProjectID,
						Role:      tenantCtx.Role,
						Scopes:    tenantCtx.Scopes,
						Tier:      tenantCtx.Tier,
						Exp:       time.Now().Add(1 * time.Hour).Unix(),
					})
					if tErr == nil {
						writeJSONResponse(w, http.StatusOK, map[string]interface{}{
							"access_token": token,
							"token_type":   "Bearer",
							"expires_in":   3600,
							"tenant_id":    tenantCtx.TenantID,
							"tier":         tenantCtx.Tier,
						})
						gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusOK, time.Since(start))
						return
					}
				}
			}
			// Reset body for upstream proxying if not handled locally
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	// 5. IP-Level Token Bucket Rate Limiting
	clientIP := extractClientIP(r)
	ipTier := DefaultRateLimits["ip_default"]
	allowed, remaining, retryAfter := gw.limiter.Allow("ip:"+clientIP, ipTier.RequestsPerSecond, ipTier.BurstCapacity)
	if !allowed {
		atomic.AddInt64(&gw.stats.RateLimitedCount, 1)
		gw.metrics.RecordRateLimit("ip")
		gw.metrics.RecordRequest(r.Method, r.URL.Path, http.StatusTooManyRequests, time.Since(start))
		WriteRateLimited(w, r, "too many requests from this IP: rate limit exceeded", int(retryAfter.Seconds()))
		return
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

	var tenantCtx *TenantContext

	// 8. Authentication & Authorization
	if !rule.AllowAnonymous {
		ctx, err := gw.authenticator.AuthenticateRequest(r)
		if err != nil {
			atomic.AddInt64(&gw.stats.AuthFailedCount, 1)
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusUnauthorized, time.Since(start))
			WriteUnauthorized(w, r, fmt.Sprintf("unauthorized: %s", err.Error()))
			return
		}

		// Check permission scopes
		if !CheckScopes(ctx.Scopes, rule.RequiredScopes) {
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusForbidden, time.Since(start))
			WriteForbidden(w, r, "forbidden: insufficient permission scopes")
			return
		}

		tenantCtx = ctx

		// 9. Tenant-Level Rate Limiting
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
			gw.metrics.RecordRateLimit(tierName)
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusTooManyRequests, time.Since(start))
			WriteRateLimited(w, r, fmt.Sprintf("rate limit exceeded for tenant '%s' on '%s' tier", ctx.TenantID, tierName), int(tRetry.Seconds()))
			return
		}
	} else {
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	}

	// 10. Stripe-grade Idempotency-Key Engine (Mutation Protection)
	var (
		idempKey    string
		isIdempReq  bool
		bodyBytes   []byte
		scopeTenant string
	)

	if isMutationMethod(r.Method) {
		idempKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempKey == "" {
			idempKey = strings.TrimSpace(r.Header.Get("X-Idempotency-Key"))
		}
	}

	if idempKey != "" {
		if err := ValidateIdempotencyKey(idempKey); err != nil {
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
			gw.metrics.RecordIdempotencyOp("READ_ERROR")
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusBadRequest, time.Since(start))
			WriteBadRequest(w, r, "unable to read request body for idempotency validation", "INVALID_REQUEST_BODY")
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		rec, isReplay, acqErr := gw.idempotency.AcquireOrReplay(scopeTenant, idempKey, r.Method, r.URL.Path, bodyBytes, 2*time.Second)
		if acqErr != nil {
			if errors.Is(acqErr, ErrIdempotencyMismatch) {
				gw.metrics.RecordIdempotencyOp("CONFLICT")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusConflict, time.Since(start))
				WriteConflict(w, r, "keys with identical idempotency values must send identical request parameters", "IDEMPOTENCY_KEY_MISMATCH")
				return
			}
			if errors.Is(acqErr, ErrIdempotencyInFlight) {
				gw.metrics.RecordIdempotencyOp("IN_FLIGHT")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusConflict, time.Since(start))
				w.Header().Set("Retry-After", "1")
				WriteConflict(w, r, "a request with this idempotency key is currently in progress", "IDEMPOTENCY_KEY_IN_FLIGHT")
				return
			}
			gw.metrics.RecordIdempotencyOp("ERROR")
			gw.metrics.RecordRequest(r.Method, rule.PathPrefix, http.StatusBadRequest, time.Since(start))
			WriteBadRequest(w, r, acqErr.Error(), "IDEMPOTENCY_ERROR")
			return
		}

		if isReplay && rec != nil {
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
		cacheScope := "public"
		if tenantCtx != nil && !rule.AllowAnonymous {
			cacheScope = tenantCtx.TenantID
		}

		cacheKey = gw.cache.NormalizeKey(cacheScope, r.Method, r.URL.Path, r.URL.RawQuery)

		if !bypassLookup {
			entry, hit := gw.cache.Lookup(cacheKey)
			if hit && entry != nil {
				// Conditional validation for 304 Not Modified
				if gw.cache.ValidateConditional(r, entry) {
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
				w.WriteHeader(entry.StatusCode)
				if r.Method != http.MethodHead {
					_, _ = w.Write(entry.Body)
				}

				gw.mu.Lock()
				gw.stats.StatusCodes[entry.StatusCode]++
				gw.mu.Unlock()

				gw.metrics.RecordCacheOp("HIT")
				gw.metrics.RecordRequest(r.Method, rule.PathPrefix, entry.StatusCode, time.Since(start))
				return
			}
		}
	}

	// 12. Forward via Reverse Proxy
	wrapper := NewResponseWriterWrapper(w)
	if isIdempReq || isCacheEligible {
		wrapper.BodyBuffer = &bytes.Buffer{}
	}
	if isCacheEligible {
		w.Header().Set("X-Cache", "MISS")
		gw.metrics.RecordCacheOp("MISS")
	}
	proxy.ServeHTTP(wrapper, r, tenantCtx, reqID)

	duration := time.Since(start)

	// RFC 9111 Cache Population on successful read
	if isCacheEligible && wrapper.StatusCode == http.StatusOK {
		if gw.cache.IsResponseCacheable(wrapper.StatusCode, wrapper.Header()) {
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
