package apigateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPIGateway_ReverseProxyAndRouting(t *testing.T) {
	// 1. Mock upstream servers
	authHit := int32(0)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authHit, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"auth_ok"}`))
	}))
	defer authServer.Close()

	dbHit := int32(0)
	var capturedTenantID, capturedActorID string
	dbServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&dbHit, 1)
		capturedTenantID = r.Header.Get("X-Tenant-ID")
		capturedActorID = r.Header.Get("X-Actor-ID")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"db_ok"}`))
	}))
	defer dbServer.Close()

	secret := "test-secret-key-32-bytes-long-aeitron"
	gw := NewAPIGateway(secret)

	// Override routes to point to mock servers
	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/auth",
		UpstreamURL:    authServer.URL,
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register auth route: %v", err)
	}

	err = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/databases",
		UpstreamURL:    dbServer.URL,
		AllowAnonymous: false,
	})
	if err != nil {
		t.Fatalf("failed to register db route: %v", err)
	}

	// 2. Test anonymous route (/v1/auth)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for anonymous auth route, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&authHit) != 1 {
		t.Fatalf("expected auth mock to be hit once, got %d", authHit)
	}

	// 3. Test protected route without token -> 401 Unauthorized
	req = httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}

	// 4. Test protected route with valid token -> 200 OK & Header injection
	token, err := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:       "usr_789",
		TenantID:  "tenant_corp",
		OrgID:     "org_123",
		ProjectID: "proj_456",
		Role:      "admin",
		Tier:      "pro",
		Exp:       time.Now().Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if capturedTenantID != "tenant_corp" {
		t.Errorf("expected upstream to receive X-Tenant-ID 'tenant_corp', got '%s'", capturedTenantID)
	}
	if capturedActorID != "usr_789" {
		t.Errorf("expected upstream to receive X-Actor-ID 'usr_789', got '%s'", capturedActorID)
	}
}

func TestAPIGateway_AuthenticationAndScopes(t *testing.T) {
	fleetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"fleet":"nodes_ok"}`))
	}))
	defer fleetServer.Close()

	secret := "test-secret-32-bytes-auth-scopes-gate"
	gw := NewAPIGateway(secret)

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/fleet",
		UpstreamURL:    fleetServer.URL,
		AllowAnonymous: false,
		RequiredScopes: []string{"fleet:read"},
	})

	// 1. Expired JWT -> 401
	expiredToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_old",
		TenantID: "tenant_old",
		Scopes:   []string{"fleet:read"},
		Exp:      time.Now().Add(-1 * time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/fleet/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rec.Code)
	}

	// 2. Tampered JWT signature -> 401
	validToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_good",
		TenantID: "tenant_good",
		Scopes:   []string{"fleet:read"},
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})
	parts := strings.Split(validToken, ".")
	tamperedToken := parts[0] + "." + parts[1] + ".tampered_signature"

	req = httptest.NewRequest(http.MethodGet, "/v1/fleet/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+tamperedToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for tampered signature, got %d", rec.Code)
	}

	// 3. Insufficient scope -> 403 Forbidden
	noScopeToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_noscope",
		TenantID: "tenant_noscope",
		Scopes:   []string{"database:read"}, // missing "fleet:read"
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	req = httptest.NewRequest(http.MethodGet, "/v1/fleet/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+noScopeToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing scope, got %d", rec.Code)
	}

	// 4. Scoped API Key authentication -> 200 OK
	apiKey := "aeitron_live_abc123secretkey456"
	gw.Authenticator().RegisterAPIKey(apiKey, &TenantContext{
		TenantID: "tenant_api_key",
		ActorID:  "service_account_ci",
		Role:     "service",
		Scopes:   []string{"fleet:read"},
		Tier:     "enterprise",
	})

	req = httptest.NewRequest(http.MethodGet, "/v1/fleet/nodes", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid API key, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestAPIGateway_HeaderSpoofingPrevention(t *testing.T) {
	var upstreamHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gw := NewAPIGateway("test-secret-spoof-prevention-32-chars")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/billing",
		UpstreamURL:    srv.URL,
		AllowAnonymous: false,
	})

	token, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_real_999",
		TenantID: "tenant_real_actual",
		Role:     "member",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/invoices", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Malicious attacker attempts to spoof tenant header
	req.Header.Set("X-Tenant-ID", "tenant_hacked_victim")
	req.Header.Set("X-Org-ID", "org_hacked_victim")
	req.Header.Set("X-Actor-Role", "super_admin")

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	if upstreamHeaders.Get("X-Tenant-ID") != "tenant_real_actual" {
		t.Fatalf("spoofing defense failed! Expected 'tenant_real_actual', got '%s'", upstreamHeaders.Get("X-Tenant-ID"))
	}
	if upstreamHeaders.Get("X-Actor-Role") != "member" {
		t.Fatalf("spoofing defense failed! Expected 'member', got '%s'", upstreamHeaders.Get("X-Actor-Role"))
	}
}

func TestAPIGateway_TokenBucketRateLimiting(t *testing.T) {
	limiter := NewTokenBucketLimiter()

	// Rate: 10 req/sec, capacity: 5 burst
	key := "test_ip:192.0.2.1"
	for i := 0; i < 5; i++ {
		allowed, rem, _ := limiter.Allow(key, 10, 5)
		if !allowed {
			t.Fatalf("request %d should have been allowed within burst capacity", i)
		}
		if rem != (4 - i) {
			t.Errorf("expected remaining %d, got %d", 4-i, rem)
		}
	}

	// 6th request immediately exceeds burst limit
	allowed, _, retryAfter := limiter.Allow(key, 10, 5)
	if allowed {
		t.Fatalf("6th request should have been rate limited")
	}
	if retryAfter <= 0 {
		t.Errorf("expected positive retry-after, got %v", retryAfter)
	}

	// Sleep 150ms -> should refill at least 1 token (10 per second = 1 every 100ms)
	time.Sleep(150 * time.Millisecond)
	allowed, _, _ = limiter.Allow(key, 10, 5)
	if !allowed {
		t.Fatalf("request after refill period should have been allowed")
	}
}

func TestAPIGateway_CircuitBreaker(t *testing.T) {
	callCount := int32(0)
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"database crashed"}`))
	}))
	defer failServer.Close()

	gw := NewAPIGateway("test-secret-breaker-32-bytes-test")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/fail",
		UpstreamURL:    failServer.URL,
		AllowAnonymous: true,
	})

	// Send 5 failing requests to trip circuit breaker threshold (5 fails)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/fail/test", nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 from upstream, got %d", rec.Code)
		}
	}

	initialHits := atomic.LoadInt32(&callCount)

	// 6th request should immediately trip circuit breaker and return 503 without hitting failServer
	req := httptest.NewRequest(http.MethodGet, "/v1/fail/test", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable when circuit breaker is open, got %d", rec.Code)
	}
	if atomic.LoadInt32(&callCount) != initialHits {
		t.Fatalf("circuit breaker did not protect upstream! Upstream was called while open")
	}
}

func TestAPIGateway_RequestIDAndAuditSpooling(t *testing.T) {
	mutateServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	}))
	defer mutateServer.Close()

	gw := NewAPIGateway("test-secret-audit-32-bytes-req-id")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/databases",
		UpstreamURL:    mutateServer.URL,
		AllowAnonymous: false,
	})

	token, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_auditor",
		TenantID: "tenant_audit_test",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	// 1. Post request (state mutation)
	req := httptest.NewRequest(http.MethodPost, "/v1/databases/provision", strings.NewReader(`{"name":"prod-db"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	customReqID := "req_custom_tracking_9876543210"
	req.Header.Set("X-Request-ID", customReqID)

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}
	if rec.Header().Get("X-Request-ID") != customReqID {
		t.Fatalf("expected X-Request-ID to be preserved as '%s', got '%s'", customReqID, rec.Header().Get("X-Request-ID"))
	}

	// Allow async audit spooler worker to process
	time.Sleep(50 * time.Millisecond)

	records := gw.AuditSpooler().GetRecords()
	if len(records) == 0 {
		t.Fatalf("expected at least 1 audit record for state mutation POST request")
	}

	lastRecord := records[len(records)-1]
	if lastRecord.RequestID != customReqID {
		t.Errorf("expected audit record RequestID '%s', got '%s'", customReqID, lastRecord.RequestID)
	}
	if lastRecord.Method != http.MethodPost {
		t.Errorf("expected audit record Method POST, got '%s'", lastRecord.Method)
	}
	if lastRecord.TenantID != "tenant_audit_test" {
		t.Errorf("expected audit record TenantID 'tenant_audit_test', got '%s'", lastRecord.TenantID)
	}
}

func TestAPIGateway_CORSAndHealth(t *testing.T) {
	gw := NewAPIGateway("test-secret-cors-health-32-bytes")

	// 1. Preflight OPTIONS request
	req := httptest.NewRequest(http.MethodOptions, "/v1/databases/instances", nil)
	req.Header.Set("Origin", "https://dashboard.aeitron.com")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for OPTIONS preflight, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://dashboard.aeitron.com" {
		t.Errorf("unexpected CORS origin: %s", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	// 2. Health check /ready
	req = httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /ready, got %d", rec.Code)
	}

	// 3. Gateway Stats /v1/gateway/stats
	req = httptest.NewRequest(http.MethodGet, "/v1/gateway/stats", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /v1/gateway/stats, got %d", rec.Code)
	}

	var stats GatewayStats
	body, _ := io.ReadAll(rec.Body)
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if stats.TotalRequests <= 0 {
		t.Errorf("expected stats.TotalRequests > 0, got %d", stats.TotalRequests)
	}
}

func TestAPIGateway_ProblemDetailsFormat(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-rfc7807-suite")

	// 1. Route Not Found -> 404 Problem Details
	req := httptest.NewRequest(http.MethodGet, "/v1/unknown-endpoint", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/problem+json") {
		t.Errorf("expected application/problem+json Content-Type, got %s", rec.Header().Get("Content-Type"))
	}

	var problem ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to unmarshal ProblemDetails: %v", err)
	}
	if problem.Status != 404 || problem.Title != "Not Found" || problem.Code != "NOT_FOUND" {
		t.Errorf("unexpected problem details: %+v", problem)
	}

	// 2. Unauthorized -> 401 Problem Details
	req = httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to unmarshal ProblemDetails: %v", err)
	}
	if problem.Status != 401 || problem.Title != "Unauthorized" || problem.Code != "UNAUTHORIZED" {
		t.Errorf("unexpected unauthorized problem details: %+v", problem)
	}
}

func TestAPIGateway_RouteRewriting(t *testing.T) {
	var capturedPath string
	commerceMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"available":true,"domain":"aeitron-cloud.com"}`))
	}))
	defer commerceMock.Close()

	gw := NewAPIGateway("test-secret-32-bytes-rewrite-gate")

	// Register rewritten route: /v1/domains -> /v1/commerce/domains
	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/domains",
		UpstreamURL:    commerceMock.URL,
		RewritePrefix:  "/v1/commerce/domains",
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register route: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/domains/search?query=aeitron", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if capturedPath != "/v1/commerce/domains/search" {
		t.Errorf("expected rewritten path '/v1/commerce/domains/search', got '%s'", capturedPath)
	}
}

func TestAPIGateway_FastTokenIssuance(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-token-issue")

	// Register API key
	testKey := "aeitron_live_secret_key_1234567890abcdef"
	gw.Authenticator().RegisterAPIKey(testKey, &TenantContext{
		TenantID:  "tenant_acme",
		OrgID:     "org_acme_corp",
		ProjectID: "proj_prod",
		ActorID:   "actor_service_worker",
		Role:      "admin",
		Scopes:    []string{"*"},
		Tier:      "enterprise",
	})

	// Exchange API key for JWT token
	reqBody := `{"api_key":"` + testKey + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for token exchange, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		TenantID    string `json:"tenant_id"`
		Tier        string `json:"tier"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokenResp.AccessToken == "" || tokenResp.TokenType != "Bearer" || tokenResp.TenantID != "tenant_acme" {
		t.Errorf("invalid token response: %+v", tokenResp)
	}

	// Verify the issued JWT with gateway authenticator
	testReq := httptest.NewRequest(http.MethodGet, "/dummy", nil)
	testReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	ctx, err := gw.Authenticator().AuthenticateRequest(testReq)
	if err != nil {
		t.Fatalf("failed to authenticate newly issued JWT: %v", err)
	}
	if ctx.TenantID != "tenant_acme" || ctx.Tier != "enterprise" {
		t.Errorf("unexpected claims in issued token: %+v", ctx)
	}
}

func TestAPIGateway_SSRFValidator(t *testing.T) {
	// Loopback rejection
	if err := ValidateSafeTargetURL("http://127.0.0.1:8080/metrics"); err == nil {
		t.Errorf("expected error for loopback 127.0.0.1")
	}

	// Cloud metadata IP rejection
	if err := ValidateSafeTargetURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Errorf("expected error for cloud metadata IP")
	}

	// Invalid scheme rejection
	if err := ValidateSafeTargetURL("ftp://malicious.com/payload"); err == nil {
		t.Errorf("expected error for ftp scheme")
	}

	// Safe public URL acceptance
	if err := ValidateSafeTargetURL("https://example.com/webhook"); err != nil {
		t.Errorf("unexpected error for valid public URL: %v", err)
	}
}

func TestAPIGateway_DomainValidator(t *testing.T) {
	validDomains := []string{"aeitron.com", "api.aeitron.com", "sub.domain.co.uk", "cloud-infra.io"}
	for _, d := range validDomains {
		if err := ValidateDomainName(d); err != nil {
			t.Errorf("expected domain '%s' to be valid, got: %v", d, err)
		}
	}

	invalidDomains := []string{"", "invalid domain with spaces", "https://aeitron.com", "domain..com", ".com"}
	for _, d := range invalidDomains {
		if err := ValidateDomainName(d); err == nil {
			t.Errorf("expected domain '%s' to be rejected as invalid", d)
		}
	}
}

func TestAPIGateway_DefaultProductRoutes(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-routes-check")

	expectedPrefixes := []string{
		"/v1/auth",
		"/v1/identity",
		"/v1/organizations",
		"/v1/audit",
		"/v1/databases",
		"/v1/backups",
		"/v1/fleet",
		"/v1/usage",
		"/v1/notifications",
		"/v1/billing",
		"/v1/commerce",
		"/v1/catalog",
		"/v1/orders",
		"/v1/domains",
		"/v1/hosting",
		"/v1/compute",
		"/v1/subscriptions",
		"/v1/invoices",
		"/v1/emails",
		"/v1/dns",
		"/v1/router",
		"/v1/edge",
		"/v1/security",
	}

	for _, prefix := range expectedPrefixes {
		rule, proxy := gw.matchRoute(prefix + "/test")
		if rule == nil || proxy == nil {
			t.Errorf("expected default route to match prefix '%s', got nil", prefix)
		}
	}
}

func TestAPIGateway_InteractiveDocsEndpoints(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-docs-suite")

	// 1. /docs endpoint (Scalar UI)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /docs, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("expected text/html for /docs, got %s", rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "@scalar/api-reference") || !strings.Contains(body, "Aeitron Global Infrastructure") {
		t.Errorf("expected Scalar documentation HTML content, got: %s", body[:min(len(body), 200)])
	}

	// 2. /scalar alias with trailing slash
	req = httptest.NewRequest(http.MethodGet, "/scalar/", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /scalar/, got %d", rec.Code)
	}

	// 3. /swagger endpoint (Swagger UI)
	req = httptest.NewRequest(http.MethodGet, "/swagger", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /swagger, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "swagger-ui-bundle.js") {
		t.Errorf("expected Swagger UI bundle script in response")
	}

	// 4. /openapi.yaml raw spec endpoint
	req = httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /openapi.yaml, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/yaml") {
		t.Errorf("expected text/yaml for /openapi.yaml, got %s", rec.Header().Get("Content-Type"))
	}
	yamlContent := rec.Body.String()
	if !strings.Contains(yamlContent, "openapi: 3.1.0") || !strings.Contains(yamlContent, "Aeitron Intelligent Global Edge") {
		t.Errorf("expected OpenAPI 3.1.0 YAML content in response")
	}
}

func TestAPIGateway_IdempotencyKey_Replay(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"order_id":"ord_9901","status":"provisioned"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-idempotency-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	idempKey := "ik_order_deploy_987654321"
	reqPayload := `{"plan":"vps-singapore-metal","cores":8}`

	// First Request: Must hit upstream and succeed
	req1 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(reqPayload))
	req1.Header.Set("Idempotency-Key", idempKey)
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on initial request, got %d", rec1.Code)
	}
	if rec1.Header().Get("Idempotent-Replayed") == "true" {
		t.Fatalf("initial request must not be marked as replayed")
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected upstream to be hit exactly 1 time, got %d", upstreamHits)
	}

	// Second Request: Network retry / duplicate submission with same key and payload
	req2 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(reqPayload))
	req2.Header.Set("Idempotency-Key", idempKey)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on replayed request, got %d", rec2.Code)
	}
	if rec2.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("expected Idempotent-Replayed header to be 'true'")
	}
	if rec2.Body.String() != `{"order_id":"ord_9901","status":"provisioned"}` {
		t.Fatalf("unexpected cached body: %s", rec2.Body.String())
	}
	// Crucial: Upstream was NOT hit a second time!
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream hits must still be 1 (double-charge prevented), got %d", upstreamHits)
	}

	// Third Request: Using X-Idempotency-Key header alias
	req3 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(reqPayload))
	req3.Header.Set("X-Idempotency-Key", idempKey)
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusCreated || rec3.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("expected 201 Created and Idempotent-Replayed on X-Idempotency-Key alias")
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream hits must still be 1, got %d", upstreamHits)
	}
}

func TestAPIGateway_IdempotencyKey_PayloadMismatchConflict(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-idempotency-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	idempKey := "ik_mismatch_check_88888888"

	// 1. Initial request with payload A
	req1 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"amount":100}`))
	req1.Header.Set("Idempotency-Key", idempKey)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first request, got %d", rec1.Code)
	}

	// 2. Reused key with payload B (Mismatch!)
	req2 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"amount":200}`))
	req2.Header.Set("Idempotency-Key", idempKey)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on payload mismatch, got %d", rec2.Code)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(rec2.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to decode RFC 7807 problem: %v", err)
	}
	if problem.Code != "IDEMPOTENCY_KEY_MISMATCH" {
		t.Errorf("expected code IDEMPOTENCY_KEY_MISMATCH, got %s", problem.Code)
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream should not be hit on conflict, hits: %d", upstreamHits)
	}
}

func TestAPIGateway_IdempotencyKey_InvalidFormat(t *testing.T) {
	gw := NewAPIGateway("secret-key-32-bytes-idempotency-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    "http://127.0.0.1:8098",
		AllowAnonymous: true,
	})

	invalidKeys := []string{
		"short",                     // < 8 characters
		"key with spaces in middle", // contains illegal spaces
		"key$$invalid%%characters",  // contains illegal symbols
		strings.Repeat("a", 129),    // > 128 characters
	}

	for _, k := range invalidKeys {
		req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", k)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for invalid key '%s', got %d", k, rec.Code)
		}
		var problem ProblemDetails
		_ = json.Unmarshal(rec.Body.Bytes(), &problem)
		if problem.Code != "INVALID_IDEMPOTENCY_KEY" {
			t.Errorf("expected INVALID_IDEMPOTENCY_KEY, got %s", problem.Code)
		}
	}
}

func TestAPIGateway_IdempotencyKey_ServerErrorDoesNotCache(t *testing.T) {
	attempt := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&attempt, 1)
		if cur == 1 {
			// First attempt fails with 500
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"db temporary outage"}`))
			return
		}
		// Second attempt succeeds with 200
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"recovered_and_created"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-idempotency-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/compute",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	idempKey := "ik_transient_failure_recovery_123"
	payload := `{"instance_type":"c3-highcpu-8"}`

	// 1. First attempt: 500 error from upstream
	req1 := httptest.NewRequest(http.MethodPost, "/v1/compute/instances", strings.NewReader(payload))
	req1.Header.Set("Idempotency-Key", idempKey)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from failing upstream, got %d", rec1.Code)
	}

	// 2. Client safely retries with the SAME idempotency key after transient failure
	req2 := httptest.NewRequest(http.MethodPost, "/v1/compute/instances", strings.NewReader(payload))
	req2.Header.Set("Idempotency-Key", idempKey)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on retry, got %d", rec2.Code)
	}
	if rec2.Body.String() != `{"status":"recovered_and_created"}` {
		t.Fatalf("expected successful recovered body on retry: %s", rec2.Body.String())
	}
	if atomic.LoadInt32(&attempt) != 2 {
		t.Fatalf("expected 2 attempts due to 5xx failure un-locking, got %d", attempt)
	}
}

func TestAPIGateway_IdempotencyKey_TenantIsolation(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		tenant := r.Header.Get("X-Tenant-ID")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tenant":"` + tenant + `"}`))
	}))
	defer upstream.Close()

	secret := "secret-key-32-bytes-tenant-isolation-suite"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: false,
	})

	// Generate tokens for Tenant A and Tenant B
	tokenA, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "user_a",
		TenantID: "tenant_alpha_111",
		Role:     "admin",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenB, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "user_b",
		TenantID: "tenant_bravo_222",
		Role:     "admin",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	sharedKey := "ik_identically_named_key_12345"

	// Tenant A request
	reqA := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"item":"license_a"}`))
	reqA.Header.Set("Authorization", "Bearer "+tokenA)
	reqA.Header.Set("Idempotency-Key", sharedKey)
	recA := httptest.NewRecorder()
	gw.ServeHTTP(recA, reqA)

	if recA.Code != http.StatusOK {
		t.Fatalf("expected 200 for Tenant A, got %d", recA.Code)
	}

	// Tenant B request with SAME idempotency key (must NOT collide or conflict)
	reqB := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"item":"license_b"}`))
	reqB.Header.Set("Authorization", "Bearer "+tokenB)
	reqB.Header.Set("Idempotency-Key", sharedKey)
	recB := httptest.NewRecorder()
	gw.ServeHTTP(recB, reqB)

	if recB.Code != http.StatusOK {
		t.Fatalf("expected 200 for Tenant B (tenant isolation must prevent key conflict), got %d", recB.Code)
	}

	if atomic.LoadInt32(&upstreamHits) != 2 {
		t.Fatalf("expected both tenants to reach upstream independently, got %d hits", upstreamHits)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
