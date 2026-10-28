package apigateway

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
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

func TestAPIGateway_RFC9111_CacheHitAndMiss(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=120")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"plans":[{"id":"vps-micro","price":5}]}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-cache-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// 1. First Request: Cache MISS, calls upstream
	req1 := httptest.NewRequest(http.MethodGet, "/v1/catalog/plans", nil)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first request, got %d", rec1.Code)
	}
	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache: MISS on first request, got %s", rec1.Header().Get("X-Cache"))
	}
	etag := rec1.Header().Get("ETag")
	if etag == "" || !strings.Contains(etag, "aei_") {
		t.Errorf("expected valid ETag header in response, got %s", etag)
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected upstream hits to be 1, got %d", upstreamHits)
	}

	// 2. Second Request: Cache HIT, served sub-millisecond without touching upstream
	req2 := httptest.NewRequest(http.MethodGet, "/v1/catalog/plans", nil)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on cached request, got %d", rec2.Code)
	}
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT on second request, got %s", rec2.Header().Get("X-Cache"))
	}
	if rec2.Header().Get("ETag") != etag {
		t.Errorf("expected matching ETag on hit, got %s", rec2.Header().Get("ETag"))
	}
	if rec2.Body.String() != `{"plans":[{"id":"vps-micro","price":5}]}` {
		t.Errorf("unexpected cached response body: %s", rec2.Body.String())
	}
	// Crucial: Upstream was NOT hit a second time!
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream hits must still be 1 after cache hit, got %d", upstreamHits)
	}
}

func TestAPIGateway_RFC9111_ETag304NotModified(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"domain":"aeitron.io","available":true}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-cache-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/domains",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
		CacheTTL:       30 * time.Second,
	})

	// 1. Initial request to populate cache and acquire ETag
	req1 := httptest.NewRequest(http.MethodGet, "/v1/domains/check?name=aeitron.io", nil)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	etag := rec1.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("expected ETag from first request")
	}

	// 2. Client sends conditional request with If-None-Match
	req2 := httptest.NewRequest(http.MethodGet, "/v1/domains/check?name=aeitron.io", nil)
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	// Must return 304 Not Modified with zero body bytes!
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified, got %d", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Fatalf("304 response must have empty body, got %d bytes", rec2.Body.Len())
	}
	if rec2.Header().Get("ETag") != etag {
		t.Errorf("expected ETag header preserved on 304, got %s", rec2.Header().Get("ETag"))
	}
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT on 304, got %s", rec2.Header().Get("X-Cache"))
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream hits must still be 1 (database/upstream saved from call), got %d", upstreamHits)
	}
}

func TestAPIGateway_RFC9111_QueryParameterCanonicalization(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":["server1"]}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-cache-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// 1. First order: ?limit=10&region=sgp
	req1 := httptest.NewRequest(http.MethodGet, "/v1/catalog/items?limit=10&region=sgp", nil)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	// 2. Permuted order: ?region=sgp&limit=10 (same semantic query!)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/catalog/items?region=sgp&limit=10", nil)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on canonicalized query request, got %d", rec2.Code)
	}
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT due to RFC 9111 query sorting, got %s", rec2.Header().Get("X-Cache"))
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream should not be hit on permuted query params, hits: %d", upstreamHits)
	}
}

func TestAPIGateway_RFC9111_ClientCacheBypass(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"live"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-cache-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/status",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
		CacheTTL:       30 * time.Second,
	})

	// Populate cache
	req1 := httptest.NewRequest(http.MethodGet, "/v1/status/summary", nil)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected 1 hit on first call")
	}

	// Client sends Cache-Control: no-cache (forces revalidation/bypass)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/status/summary", nil)
	req2.Header.Set("Cache-Control", "no-cache")
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on bypass, got %d", rec2.Code)
	}
	if atomic.LoadInt32(&upstreamHits) != 2 {
		t.Fatalf("upstream should be hit on Cache-Control: no-cache, hits: %d", upstreamHits)
	}
}

func TestAPIGateway_RFC9111_MutationInvalidation(t *testing.T) {
	upstreamHits := int32(0)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("secret-key-32-bytes-cache-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// 1. GET request caches resource
	req1 := httptest.NewRequest(http.MethodGet, "/v1/catalog/pricing", nil)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected 1 upstream hit")
	}

	// Verify cached
	if gw.Cache().Size() != 1 {
		t.Fatalf("expected cache size 1, got %d", gw.Cache().Size())
	}

	// 2. Successful POST mutation on catalog invalidates cache per RFC 9111 Section 4.4
	reqMut := httptest.NewRequest(http.MethodPost, "/v1/catalog/pricing", strings.NewReader(`{"new_price":10}`))
	recMut := httptest.NewRecorder()
	gw.ServeHTTP(recMut, reqMut)

	if recMut.Code != http.StatusOK {
		t.Fatalf("expected 200 on mutation, got %d", recMut.Code)
	}

	// Cache entry must have been evicted!
	if gw.Cache().Size() != 0 {
		t.Fatalf("expected cache size 0 after mutation invalidation, got %d", gw.Cache().Size())
	}

	// 3. Next GET request must be a MISS and re-fetch from upstream
	req3 := httptest.NewRequest(http.MethodGet, "/v1/catalog/pricing", nil)
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)

	if rec3.Header().Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache: MISS after invalidation, got %s", rec3.Header().Get("X-Cache"))
	}
	if atomic.LoadInt32(&upstreamHits) != 3 {
		t.Fatalf("expected 3 hits total, got %d", upstreamHits)
	}
}

func TestAPIGateway_RFC9111_CachePurgeEndpoint(t *testing.T) {
	gw := NewAPIGateway("secret-key-32-bytes-cache-suite")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    "http://127.0.0.1:8098",
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// Manually populate cache entries
	gw.Cache().Store("public:GET:/v1/catalog/items", "/v1/catalog/items", 200, http.Header{}, []byte(`{}`), 60*time.Second)
	gw.Cache().Store("public:GET:/v1/catalog/plans", "/v1/catalog/plans", 200, http.Header{}, []byte(`{}`), 60*time.Second)

	if gw.Cache().Size() != 2 {
		t.Fatalf("expected 2 items in cache, got %d", gw.Cache().Size())
	}

	// Call DELETE /v1/gateway/cache to purge all
	req := httptest.NewRequest(http.MethodDelete, "/v1/gateway/cache", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on cache purge, got %d", rec.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "purged" || resp["remaining"].(float64) != 0 {
		t.Fatalf("unexpected purge response: %v", resp)
	}
	if gw.Cache().Size() != 0 {
		t.Fatalf("cache should be empty after purge, got %d", gw.Cache().Size())
	}
}

func TestAPIGateway_PrometheusMetrics_Endpoint(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-32-bytes-long-aeitron")

	// 1. GET /metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /metrics, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Fatalf("expected OpenMetrics content type, got: %s", ct)
	}

	body := rec.Body.String()

	// Verify standard Prometheus headers and gauges
	expectedTokens := []string{
		"# HELP aeitron_api_requests_total",
		"# TYPE aeitron_api_requests_total counter",
		"# HELP aeitron_api_request_duration_seconds",
		"# TYPE aeitron_api_request_duration_seconds histogram",
		"# HELP aeitron_api_in_flight_requests",
		"# TYPE aeitron_api_in_flight_requests gauge",
		"# HELP aeitron_api_uptime_seconds",
		"# TYPE aeitron_api_uptime_seconds gauge",
		"# HELP aeitron_api_goroutines",
		"# TYPE aeitron_api_goroutines gauge",
		"# HELP aeitron_api_memory_alloc_bytes",
		"# TYPE aeitron_api_memory_alloc_bytes gauge",
		"aeitron_api_in_flight_requests",
		"aeitron_api_uptime_seconds",
		"aeitron_api_goroutines",
	}

	for _, token := range expectedTokens {
		if !strings.Contains(body, token) {
			t.Fatalf("metrics output missing expected token %q:\n%s", token, body)
		}
	}

	// 2. HEAD /metrics
	headReq := httptest.NewRequest(http.MethodHead, "/metrics", nil)
	headRec := httptest.NewRecorder()
	gw.ServeHTTP(headRec, headReq)

	if headRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for HEAD /metrics, got %d", headRec.Code)
	}
	if headRec.Body.Len() != 0 {
		t.Fatalf("expected empty body for HEAD /metrics, got %d bytes", headRec.Body.Len())
	}
}

func TestAPIGateway_PrometheusMetrics_CountersAndHistograms(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	gw := NewAPIGateway("test-secret-key-32-bytes-long-aeitron")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: true,
	})

	// Make 3 requests
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/catalog/items", nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
	}

	// Fetch /metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	metricsOutput := rec.Body.String()

	// Verify request counter for /v1/catalog route
	expectedReqTotal := `aeitron_api_requests_total{method="GET",route="/v1/catalog",status="200"} 3`
	if !strings.Contains(metricsOutput, expectedReqTotal) {
		t.Fatalf("missing expected request total counter:\nExpected: %s\nGot:\n%s", expectedReqTotal, metricsOutput)
	}

	// Verify histogram bucket counters
	if !strings.Contains(metricsOutput, `aeitron_api_request_duration_seconds_bucket{route="/v1/catalog",le="+Inf"} 3`) {
		t.Fatalf("missing +Inf histogram bucket in metrics:\n%s", metricsOutput)
	}
	if !strings.Contains(metricsOutput, `aeitron_api_request_duration_seconds_count{route="/v1/catalog"} 3`) {
		t.Fatalf("missing histogram count in metrics:\n%s", metricsOutput)
	}
	if !strings.Contains(metricsOutput, `aeitron_api_request_duration_seconds_sum{route="/v1/catalog"}`) {
		t.Fatalf("missing histogram sum in metrics:\n%s", metricsOutput)
	}
}

func TestAPIGateway_PrometheusMetrics_RateLimitAndCacheTelemetry(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `W/"item_etag_123"`)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"item":"test"}`))
	}))
	defer mockUpstream.Close()

	gw := NewAPIGateway("test-secret-key-32-bytes-long-aeitron")
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// 1. Initial request (Cache MISS & STORE)
	req := httptest.NewRequest(http.MethodGet, "/v1/catalog/item/1", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// 2. Second request (Cache HIT 200)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/catalog/item/1", nil)
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected cache HIT, got %s", rec2.Header().Get("X-Cache"))
	}

	// 3. Third request conditional (Cache HIT 304 Not Modified)
	req3 := httptest.NewRequest(http.MethodGet, "/v1/catalog/item/1", nil)
	req3.Header.Set("If-None-Match", `W/"item_etag_123"`)
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified, got %d", rec3.Code)
	}

	// 4. Trigger rate limit explicitly on gateway limiter
	gw.Metrics().RecordRateLimit("free")

	// 5. Trigger idempotency replay explicitly
	gw.Metrics().RecordIdempotencyOp("REPLAYED")

	// Scrape /metrics
	mReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	mRec := httptest.NewRecorder()
	gw.ServeHTTP(mRec, mReq)
	out := mRec.Body.String()

	// Verify Cache Telemetry
	if !strings.Contains(out, `aeitron_api_cache_operations_total{status="HIT"} 1`) {
		t.Fatalf("missing cache HIT counter in metrics:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_cache_operations_total{status="304_NOT_MODIFIED"} 1`) {
		t.Fatalf("missing cache 304 counter in metrics:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_cache_operations_total{status="MISS"} 1`) {
		t.Fatalf("missing cache MISS counter in metrics:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_cache_operations_total{status="STORE"} 1`) {
		t.Fatalf("missing cache STORE counter in metrics:\n%s", out)
	}

	// Verify Rate Limiting Telemetry
	if !strings.Contains(out, `aeitron_api_rate_limited_total{tier="free"} 1`) {
		t.Fatalf("missing rate limited counter in metrics:\n%s", out)
	}

	// Verify Idempotency Telemetry
	if !strings.Contains(out, `aeitron_api_idempotency_operations_total{status="REPLAYED"} 1`) {
		t.Fatalf("missing idempotency replay counter in metrics:\n%s", out)
	}

	// Verify Circuit Breaker Telemetry for registered upstream
	if !strings.Contains(out, `aeitron_api_circuit_breaker_state{route="/v1/catalog"`) {
		t.Fatalf("missing circuit breaker state in metrics:\n%s", out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestAPIGateway_LoadBalancer_RoundRobin(t *testing.T) {
	var hits [3]atomic.Int32
	servers := make([]*httptest.Server, 3)
	urls := make([]string, 3)
	for i := 0; i < 3; i++ {
		idx := i
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[idx].Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"node": %d}`, idx)))
		}))
		defer servers[i].Close()
		urls[i] = servers[i].URL
	}

	gw := NewAPIGateway("test-secret-32-bytes-long-key-xyz")
	defer gw.Close()

	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/multi-rr",
		UpstreamURLs:   urls,
		LoadBalancer:   AlgorithmRoundRobin,
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register multi-rr route: %v", err)
	}

	// Dispatch 9 requests sequentially
	for i := 0; i < 9; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/multi-rr/test", nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d failed with status %d: %s", i, rec.Code, rec.Body.String())
		}

		backendHeader := rec.Header().Get("X-Backend-Node")
		if backendHeader == "" {
			t.Fatalf("expected X-Backend-Node header in response")
		}
	}

	// Each node should receive exactly 3 requests (3 + 3 + 3 = 9)
	for i := 0; i < 3; i++ {
		if hits[i].Load() != 3 {
			t.Fatalf("node %d expected 3 hits, got %d", i, hits[i].Load())
		}
	}
}

func TestAPIGateway_LoadBalancer_LeastConnections(t *testing.T) {
	var node0Hits, node1Hits atomic.Int32
	node0Block := make(chan struct{})
	node0Started := make(chan struct{})
	defer func() {
		select {
		case <-node0Block:
		default:
			close(node0Block)
		}
	}()

	// Node 0 blocks on first request to simulate heavy/congested processing
	server0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node0Hits.Add(1)
		select {
		case <-node0Started:
		default:
			close(node0Started)
		}
		<-node0Block // wait until released
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"node": 0}`))
	}))
	defer server0.Close()

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node1Hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"node": 1}`))
	}))
	defer server1.Close()

	gw := NewAPIGateway("test-secret-32-bytes-long-key-xyz")
	defer gw.Close()

	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/least-conn",
		UpstreamURLs:   []string{server0.URL, server1.URL},
		LoadBalancer:   AlgorithmLeastConn,
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register least-conn route: %v", err)
	}

	// Launch long-running request on Node 0 in background
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/least-conn/slow", nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
	}()

	// Wait until Node 0 is actively serving (active connection count > 0)
	<-node0Started

	// Now send 5 subsequent fast requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/least-conn/fast", nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("fast request %d failed: %d", i, rec.Code)
		}
		if rec.Header().Get("X-Backend-Node") != server1.URL {
			t.Fatalf("expected request %d to be routed to server1 (least connections), got %s", i, rec.Header().Get("X-Backend-Node"))
		}
	}

	// Unblock Node 0
	close(node0Block)
	time.Sleep(20 * time.Millisecond)

	if node1Hits.Load() != 5 {
		t.Fatalf("expected node1 to handle 5 fast requests, got %d", node1Hits.Load())
	}
	if node0Hits.Load() != 1 {
		t.Fatalf("expected node0 to handle 1 slow request, got %d", node0Hits.Load())
	}
}

func TestAPIGateway_ActiveHealthCheck_PruningAndRecovery(t *testing.T) {
	var node0Healthy atomic.Bool
	node0Healthy.Store(true)

	server0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if node0Healthy.Load() {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"down"}`))
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"node": 0}`))
	}))
	defer server0.Close()

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"node": 1}`))
	}))
	defer server1.Close()

	gw := NewAPIGateway("test-secret-32-bytes-long-key-xyz")
	defer gw.Close()

	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/resilient",
		UpstreamURLs:   []string{server0.URL, server1.URL},
		LoadBalancer:   AlgorithmRoundRobin,
		AllowAnonymous: true,
		HealthCheck: HealthCheckConfig{
			Enabled:            true,
			Path:               "/healthz",
			Interval:           20 * time.Millisecond,
			Timeout:            100 * time.Millisecond,
			UnhealthyThreshold: 2,
			HealthyThreshold:   2,
		},
	})
	if err != nil {
		t.Fatalf("failed to register resilient route: %v", err)
	}

	proxy := gw.Proxies()["/v1/resilient"]
	pool := proxy.Pool()

	// Initial probe: both healthy
	pool.ProbeAll()
	if len(pool.HealthyNodes()) != 2 {
		t.Fatalf("expected 2 healthy nodes initially, got %d", len(pool.HealthyNodes()))
	}

	// 1. Simulate Node 0 failure
	node0Healthy.Store(false)
	// Probe twice to exceed UnhealthyThreshold (2)
	pool.ProbeAll()
	pool.ProbeAll()

	if len(pool.HealthyNodes()) != 1 {
		t.Fatalf("expected 1 healthy node after failure, got %d", len(pool.HealthyNodes()))
	}
	if pool.HealthyNodes()[0].URLString() != server1.URL {
		t.Fatalf("expected server1 to be the only healthy node")
	}

	// Send 4 requests: all 4 must seamlessly route to server1 with 0 user errors
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/resilient/data", nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d failed: %d", i, rec.Code)
		}
		if rec.Header().Get("X-Backend-Node") != server1.URL {
			t.Fatalf("expected traffic routed exclusively to server1, got %s", rec.Header().Get("X-Backend-Node"))
		}
	}

	// 2. Simulate Node 0 recovery
	node0Healthy.Store(true)
	// Probe twice to exceed HealthyThreshold (2)
	pool.ProbeAll()
	pool.ProbeAll()

	if len(pool.HealthyNodes()) != 2 {
		t.Fatalf("expected 2 healthy nodes after recovery, got %d", len(pool.HealthyNodes()))
	}
}

func TestAPIGateway_LoadBalancer_AllNodesDownFailClosed(t *testing.T) {
	server0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server0.Close()

	gw := NewAPIGateway("test-secret-32-bytes-long-key-xyz")
	defer gw.Close()

	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/all-down",
		UpstreamURLs:   []string{server0.URL},
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register route: %v", err)
	}

	// Manually mark node unhealthy and trip circuit breaker
	proxy := gw.Proxies()["/v1/all-down"]
	proxy.Pool().Nodes()[0].SetHealthy(false)
	for i := 0; i < 6; i++ {
		proxy.Pool().Nodes()[0].CircuitBreaker().RecordResult(503)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/all-down/check", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable when all nodes down, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no healthy backend nodes in pool") {
		t.Fatalf("unexpected error response: %s", rec.Body.String())
	}
}

func TestAPIGateway_UpstreamInspectionEndpoint(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s2.Close()

	gw := NewAPIGateway("test-secret-32-bytes-long-key-xyz")
	defer gw.Close()

	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/inspected",
		UpstreamURLs:   []string{s1.URL, s2.URL},
		LoadBalancer:   AlgorithmLeastConn,
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register route: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/gateway/upstreams", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /v1/gateway/upstreams, got %d", rec.Code)
	}

	var resp struct {
		Upstreams map[string]struct {
			Algorithm    string `json:"algorithm"`
			TotalNodes   int    `json:"total_nodes"`
			HealthyNodes int    `json:"healthy_nodes"`
			Nodes        []struct {
				URL     string `json:"url"`
				Healthy bool   `json:"healthy"`
			} `json:"nodes"`
		} `json:"upstreams"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse upstreams JSON: %v", err)
	}

	pool, exists := resp.Upstreams["/v1/inspected"]
	if !exists {
		t.Fatalf("missing /v1/inspected in upstreams endpoint response")
	}
	if pool.Algorithm != AlgorithmLeastConn {
		t.Fatalf("expected algorithm least_conn, got %s", pool.Algorithm)
	}
	if pool.TotalNodes != 2 || pool.HealthyNodes != 2 {
		t.Fatalf("expected 2 total and 2 healthy nodes, got %d / %d", pool.TotalNodes, pool.HealthyNodes)
	}
}

func TestAPIGateway_PrometheusMetrics_UpstreamNodeHealth(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s1.Close()

	gw := NewAPIGateway("test-secret-32-bytes-long-key-xyz")
	defer gw.Close()

	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/metrics-nodes",
		UpstreamURLs:   []string{s1.URL},
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register route: %v", err)
	}

	// Trigger request to increment requests count
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics-nodes/ping", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	// Scrape /metrics
	reqM := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recM := httptest.NewRecorder()
	gw.ServeHTTP(recM, reqM)

	out := recM.Body.String()
	if !strings.Contains(out, fmt.Sprintf(`aeitron_api_upstream_node_health{route="/v1/metrics-nodes",node="%s"} 1`, s1.URL)) {
		t.Fatalf("expected upstream node health in Prometheus metrics, got:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf(`aeitron_api_upstream_node_active_connections{route="/v1/metrics-nodes",node="%s"} 0`, s1.URL)) {
		t.Fatalf("expected upstream node active connections in Prometheus metrics, got:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf(`aeitron_api_upstream_node_requests_total{route="/v1/metrics-nodes",node="%s"} 1`, s1.URL)) {
		t.Fatalf("expected upstream node requests total in Prometheus metrics, got:\n%s", out)
	}
}

func TestAPIGateway_Compression_GzipStreaming(t *testing.T) {
	// Create large JSON payload (> 512 bytes)
	type CatalogItem struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Price       float64 `json:"price"`
	}
	var items []CatalogItem
	for i := 1; i <= 50; i++ {
		items = append(items, CatalogItem{
			ID:          fmt.Sprintf("item-%04d", i),
			Name:        fmt.Sprintf("High-Performance Edge Gateway Appliance Node %d", i),
			Description: "Enterprise-grade RFC 9111 edge caching, intelligent routing, and zero-trust WAF inspection.",
			Price:       299.99 * float64(i),
		})
	}
	rawBytes, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal items: %v", err)
	}
	if len(rawBytes) < 2000 {
		t.Fatalf("test payload should be substantial, got %d bytes", len(rawBytes))
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rawBytes)
	}))
	defer upstream.Close()

	gw := NewAPIGateway("compression-test-secret-32-bytes")
	defer gw.Close()

	err = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/compress-test",
		UpstreamURLs:   []string{upstream.URL},
		AllowAnonymous: true,
	})
	if err != nil {
		t.Fatalf("failed to register route: %v", err)
	}

	// 1. Client requests with Accept-Encoding: gzip
	req := httptest.NewRequest(http.MethodGet, "/v1/compress-test/items", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Check response headers
	encoding := rec.Header().Get("Content-Encoding")
	if encoding != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip, got %q", encoding)
	}
	vary := rec.Header().Get("Vary")
	if !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("expected Vary header to contain Accept-Encoding, got %q", vary)
	}

	// Verify compressed payload size is substantially smaller (high bandwidth savings)
	compressedSize := rec.Body.Len()
	if compressedSize >= len(rawBytes) {
		t.Fatalf("expected compression to reduce size: uncompressed=%d, compressed=%d", len(rawBytes), compressedSize)
	}
	ratio := float64(len(rawBytes)-compressedSize) / float64(len(rawBytes)) * 100
	if ratio < 50.0 {
		t.Errorf("expected >= 50%% compression ratio on JSON, got %.2f%%", ratio)
	}

	// Decompress and verify content integrity
	gzReader, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("failed to decompress gzip stream: %v", err)
	}

	if string(decompressed) != string(rawBytes) {
		t.Fatalf("decompressed payload mismatch! len decomp=%d, len raw=%d", len(decompressed), len(rawBytes))
	}
}

func TestAPIGateway_Compression_Deflate(t *testing.T) {
	largeData := strings.Repeat("aeitron-cloud-edge-infrastructure-gateway-deflate-test-line\n", 40)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeData))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("compression-test-secret-32-bytes")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/deflate-test",
		UpstreamURLs:   []string{upstream.URL},
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/deflate-test/data", nil)
	req.Header.Set("Accept-Encoding", "deflate")
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "deflate" {
		t.Fatalf("expected Content-Encoding: deflate, got %q", rec.Header().Get("Content-Encoding"))
	}

	flReader := flate.NewReader(rec.Body)
	defer flReader.Close()
	decompressed, err := io.ReadAll(flReader)
	if err != nil {
		t.Fatalf("failed to decompress flate stream: %v", err)
	}
	if string(decompressed) != largeData {
		t.Fatalf("decompressed deflate data mismatch")
	}
}

func TestAPIGateway_Compression_SmallPayloadIgnored(t *testing.T) {
	// Payload smaller than 512 bytes must NOT be compressed
	smallJSON := `{"status":"ok","msg":"tiny payload"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(smallJSON))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("compression-test-secret-32-bytes")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/small-test",
		UpstreamURLs:   []string{upstream.URL},
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/small-test/status", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("expected no Content-Encoding on tiny payload (< 512 bytes), got %q", enc)
	}
	if rec.Body.String() != smallJSON {
		t.Fatalf("expected raw body %q, got %q", smallJSON, rec.Body.String())
	}
}

func TestAPIGateway_Compression_IneligibleContentTypeIgnored(t *testing.T) {
	// Binary payload (application/octet-stream) should not be compressed
	binaryData := make([]byte, 2048)
	for i := range binaryData {
		binaryData[i] = byte(i % 256)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(binaryData)
	}))
	defer upstream.Close()

	gw := NewAPIGateway("compression-test-secret-32-bytes")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/binary-test",
		UpstreamURLs:   []string{upstream.URL},
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/binary-test/blob", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("expected no Content-Encoding on application/octet-stream, got %q", enc)
	}
	if rec.Body.Len() != len(binaryData) {
		t.Fatalf("expected raw bytes length %d, got %d", len(binaryData), rec.Body.Len())
	}
}

func TestAPIGateway_Compression_PrecompressedCacheHit(t *testing.T) {
	upstreamHits := int32(0)
	largeCatalogJSON := fmt.Sprintf(`{"catalog":[%s]}`, strings.Repeat(`{"sku":"AEI-EDGE-100","name":"UltraFast Anycast POP"},`, 25))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, s-maxage=60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(largeCatalogJSON))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("compression-test-secret-32-bytes")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/cached-catalog",
		UpstreamURLs:   []string{upstream.URL},
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// 1. First request primes cache (MISS -> stored with precompressed GzipBody)
	req1 := httptest.NewRequest(http.MethodGet, "/v1/cached-catalog/products", nil)
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec1.Code)
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", upstreamHits)
	}

	// 2. Second request with Accept-Encoding: gzip (Cache HIT serving precompressed bytes directly)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/cached-catalog/products", nil)
	req2.Header.Set("Accept-Encoding", "gzip, deflate")
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on cache hit, got %d", rec2.Code)
	}
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT, got %s", rec2.Header().Get("X-Cache"))
	}
	if rec2.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip on cache hit, got %q", rec2.Header().Get("Content-Encoding"))
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream should not be hit on cache hit, got %d", upstreamHits)
	}

	// Decompress and verify
	gzReader, err := gzip.NewReader(rec2.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader on cache hit: %v", err)
	}
	decompressed, err := io.ReadAll(gzReader)
	_ = gzReader.Close()
	if err != nil {
		t.Fatalf("failed to decompress cache hit body: %v", err)
	}
	if string(decompressed) != largeCatalogJSON {
		t.Fatalf("cache hit body mismatch")
	}

	// 3. Third request with Accept-Encoding: identity (Cache HIT serving uncompressed bytes)
	req3 := httptest.NewRequest(http.MethodGet, "/v1/cached-catalog/products", nil)
	req3.Header.Set("Accept-Encoding", "identity")
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec3.Code)
	}
	if rec3.Header().Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache: HIT, got %s", rec3.Header().Get("X-Cache"))
	}
	if enc := rec3.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("expected no Content-Encoding for client with identity encoding, got %q", enc)
	}
	if rec3.Body.String() != largeCatalogJSON {
		t.Fatalf("uncompressed cache hit body mismatch")
	}
	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("upstream should still have only 1 hit, got %d", upstreamHits)
	}
}

func TestAPIGateway_Compression_PrometheusMetrics(t *testing.T) {
	gw := NewAPIGateway("compression-test-secret-32-bytes")
	defer gw.Close()

	// Record sample compression metrics
	gw.metrics.RecordCompression(5000, 1200, "gzip")
	gw.metrics.RecordCompression(3000, 900, "deflate")

	if gw.metrics.CompressionSavings() != (5000-1200)+(3000-900) {
		t.Fatalf("expected savings %d, got %d", (5000-1200)+(3000-900), gw.metrics.CompressionSavings())
	}

	reqM := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recM := httptest.NewRecorder()
	gw.ServeHTTP(recM, reqM)

	out := recM.Body.String()
	if !strings.Contains(out, `aeitron_api_compressed_responses_total{encoding="gzip"} 1`) {
		t.Fatalf("expected gzip compression counter in Prometheus metrics, got:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_compressed_responses_total{encoding="deflate"} 1`) {
		t.Fatalf("expected deflate compression counter in Prometheus metrics, got:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf(`aeitron_api_compression_savings_bytes_total %d`, (5000-1200)+(3000-900))) {
		t.Fatalf("expected compression savings in Prometheus metrics, got:\n%s", out)
	}
}

func TestWebhook_HMACSigningAndVerification(t *testing.T) {
	signer := NewWebhookSigner(5 * time.Minute)
	secret := "whsec_test_secret_key_1234567890abcdef"
	payload := []byte(`{"id":"evt_1","type":"deployment.succeeded","tenant_id":"tenant_corp"}`)
	now := time.Now().UTC()

	sigHeader, tsStr := signer.Sign(secret, payload, now)
	if !strings.HasPrefix(sigHeader, "sha256=") {
		t.Fatalf("expected sha256= prefix in signature header, got %s", sigHeader)
	}

	// 1. Valid verification
	if err := signer.Verify(secret, payload, sigHeader, tsStr); err != nil {
		t.Fatalf("expected signature verification to pass, got error: %v", err)
	}

	// 2. Tampered payload
	tamperedPayload := []byte(`{"id":"evt_1","type":"deployment.failed","tenant_id":"tenant_corp"}`)
	if err := signer.Verify(secret, tamperedPayload, sigHeader, tsStr); err == nil {
		t.Fatal("expected signature verification to fail on tampered payload, but succeeded")
	}

	// 3. Wrong secret
	if err := signer.Verify("whsec_wrong_secret", payload, sigHeader, tsStr); err == nil {
		t.Fatal("expected signature verification to fail on wrong secret, but succeeded")
	}

	// 4. Clock skew exceeding tolerance (> 5 min)
	oldTime := now.Add(-10 * time.Minute)
	_, oldTsStr := signer.Sign(secret, payload, oldTime)
	if err := signer.Verify(secret, payload, sigHeader, oldTsStr); err == nil {
		t.Fatal("expected clock skew rejection for 10-minute-old timestamp, but succeeded")
	}
}

func TestWebhook_SubscriptionManagement(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes")
	defer gw.Close()

	// 1. Reject unsafe URL (SSRF defense against cloud metadata IP)
	subReqJSON := `{"url":"http://169.254.169.254/latest/meta-data","events":["deployment.*"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/subscriptions", strings.NewReader(subReqJSON))
	req.Header.Set("X-Tenant-ID", "tenant_alpha")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for SSRF cloud metadata URL, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 2. Register valid webhook subscription
	validSubJSON := `{"url":"https://example.com/webhooks","events":["deployment.*","invoice.paid"]}`
	req = httptest.NewRequest(http.MethodPost, "/v1/webhooks/subscriptions", strings.NewReader(validSubJSON))
	req.Header.Set("X-Tenant-ID", "tenant_alpha")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for valid subscription, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var createResp struct {
		Subscription WebhookSubscription `json:"subscription"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !strings.HasPrefix(createResp.Subscription.ID, "sub_") {
		t.Fatalf("expected sub_ prefix for subscription ID, got %s", createResp.Subscription.ID)
	}
	if !strings.HasPrefix(createResp.Subscription.Secret, "whsec_") {
		t.Fatalf("expected whsec_ prefix for auto-generated secret, got %s", createResp.Subscription.Secret)
	}
	subID := createResp.Subscription.ID

	// 3. Retrieve subscription by ID
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions/"+subID, nil)
	req.Header.Set("X-Tenant-ID", "tenant_alpha")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK retrieving subscription, got %d", rec.Code)
	}

	// 4. List subscriptions
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions", nil)
	req.Header.Set("X-Tenant-ID", "tenant_alpha")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK listing subscriptions, got %d", rec.Code)
	}
	var listResp struct {
		Subscriptions []WebhookSubscription `json:"subscriptions"`
		Count         int                   `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse subscriptions list: %v", err)
	}
	if listResp.Count != 1 || len(listResp.Subscriptions) != 1 {
		t.Fatalf("expected 1 subscription, got count=%d len=%d", listResp.Count, len(listResp.Subscriptions))
	}

	// 5. Delete subscription
	req = httptest.NewRequest(http.MethodDelete, "/v1/webhooks/subscriptions/"+subID, nil)
	req.Header.Set("X-Tenant-ID", "tenant_alpha")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK deleting subscription, got %d", rec.Code)
	}

	// 6. Verify deleted (404)
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions/"+subID, nil)
	req.Header.Set("X-Tenant-ID", "tenant_alpha")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found after deletion, got %d", rec.Code)
	}
}

func TestWebhook_AsynchronousDelivery(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	var mu sync.Mutex
	var receivedSig, receivedTs, receivedDelID, receivedEvtType, receivedUA string
	var receivedPayload []byte
	receivedCh := make(chan struct{}, 1)

	webhookListener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedSig = r.Header.Get("X-Aeitron-Signature")
		receivedTs = r.Header.Get("X-Aeitron-Timestamp")
		receivedDelID = r.Header.Get("X-Aeitron-Delivery-ID")
		receivedEvtType = r.Header.Get("X-Aeitron-Event-Type")
		receivedUA = r.Header.Get("User-Agent")
		receivedPayload, _ = io.ReadAll(r.Body)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	}))
	defer webhookListener.Close()

	gw := NewAPIGateway("test-secret-32-bytes")
	defer gw.Close()

	// Configure fast engine for test
	cfg := WebhookConfig{
		MaxRetries:        3,
		InitialBackoff:    10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		HTTPTimeout:       2 * time.Second,
		Workers:           2,
		QueueSize:         100,
	}
	engine := NewWebhookEngine(cfg, gw.Metrics())
	gw.SetWebhookEngine(engine)

	// Create subscription pointing to mock webhook listener
	sub, err := engine.CreateSubscription("tenant_beta", CreateSubscriptionRequest{
		URL:    webhookListener.URL,
		Events: []string{"deployment.*"},
		Secret: "whsec_custom_secret_1234567890abcdef",
	})
	if err != nil {
		t.Fatalf("failed to create subscription: %v", err)
	}

	// Dispatch event via API
	dispatchJSON := `{
		"type": "deployment.succeeded",
		"data": { "service": "edge-router", "version": "v2.4.1" }
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/dispatch", strings.NewReader(dispatchJSON))
	req.Header.Set("X-Tenant-ID", "tenant_beta")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on dispatch, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Wait for listener to receive the webhook
	select {
	case <-receivedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook listener to receive delivery")
	}

	// Verify headers
	mu.Lock()
	sig := receivedSig
	ts := receivedTs
	delID := receivedDelID
	evtType := receivedEvtType
	ua := receivedUA
	payload := append([]byte(nil), receivedPayload...)
	mu.Unlock()

	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("expected sha256= prefix in signature, got %s", sig)
	}
	if ts == "" {
		t.Fatal("expected timestamp header")
	}
	if !strings.HasPrefix(delID, "del_") {
		t.Fatalf("expected del_ prefix in delivery ID, got %s", delID)
	}
	if evtType != "deployment.succeeded" {
		t.Fatalf("expected event type deployment.succeeded, got %s", evtType)
	}
	if !strings.Contains(ua, "Aeitron-Webhook-Delivery") {
		t.Fatalf("expected User-Agent Aeitron-Webhook-Delivery, got %s", ua)
	}

	// Verify signature using the engine signer
	if err := engine.Signer().Verify(sub.Secret, payload, sig, ts); err != nil {
		t.Fatalf("signature verification failed on received payload: %v", err)
	}

	// Wait for worker to finish recording success status
	engine.WaitIdle(1 * time.Second)

	// Check delivery history via API
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/deliveries", nil)
	req.Header.Set("X-Tenant-ID", "tenant_beta")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK retrieving deliveries, got %d", rec.Code)
	}
	var delResp struct {
		Deliveries []WebhookDelivery `json:"deliveries"`
		Count      int               `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &delResp); err != nil {
		t.Fatalf("failed to decode deliveries: %v", err)
	}
	if delResp.Count != 1 || delResp.Deliveries[0].Status != "success" {
		t.Fatalf("expected 1 delivery with status success, got count=%d status=%s", delResp.Count, delResp.Deliveries[0].Status)
	}
}

func TestWebhook_ExponentialBackoffRetry(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	attempts := int32(0)
	doneCh := make(chan struct{}, 1)

	retryListener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := atomic.AddInt32(&attempts, 1)
		if att < 3 {
			// Fail first two attempts with HTTP 500
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"temporary error"}`))
			return
		}
		// Succeed on 3rd attempt
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"recovered"}`))
		select {
		case doneCh <- struct{}{}:
		default:
		}
	}))
	defer retryListener.Close()

	gw := NewAPIGateway("test-secret-32-bytes")
	defer gw.Close()

	// Short backoff for fast deterministic test
	cfg := WebhookConfig{
		MaxRetries:        3,
		InitialBackoff:    15 * time.Millisecond,
		BackoffMultiplier: 2.0,
		HTTPTimeout:       1 * time.Second,
		Workers:           2,
		QueueSize:         100,
	}
	engine := NewWebhookEngine(cfg, gw.Metrics())
	gw.SetWebhookEngine(engine)

	_, err := engine.CreateSubscription("tenant_retry", CreateSubscriptionRequest{
		URL:    retryListener.URL,
		Events: []string{"invoice.paid"},
	})
	if err != nil {
		t.Fatalf("failed to create subscription: %v", err)
	}

	_, err = engine.Dispatch(WebhookEvent{
		Type:     "invoice.paid",
		TenantID: "tenant_retry",
		Data:     []byte(`{"invoice_id":"inv_999","amount":5000}`),
	})
	if err != nil {
		t.Fatalf("failed to dispatch event: %v", err)
	}

	// Wait for 3rd attempt to succeed
	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for retries, completed attempts=%d", atomic.LoadInt32(&attempts))
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("expected exactly 3 attempts (2 retries), got %d", attempts)
	}

	// Allow delivery state update to flush
	engine.WaitIdle(1 * time.Second)

	deliveries := engine.ListDeliveries("tenant_retry")
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery record, got %d", len(deliveries))
	}
	if deliveries[0].Status != "success" || deliveries[0].StatusCode != http.StatusOK {
		t.Fatalf("expected final status success with HTTP 200, got status=%s code=%d", deliveries[0].Status, deliveries[0].StatusCode)
	}
}

func TestWebhook_DeadLetterQueueAndRedelivery(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	listenerHealthy := atomic.Bool{}
	attempts := atomic.Int32{}
	recoveredCh := make(chan struct{}, 1)

	mockEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if !listenerHealthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"outage"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		select {
		case recoveredCh <- struct{}{}:
		default:
		}
	}))
	defer mockEndpoint.Close()

	gw := NewAPIGateway("test-secret-32-bytes")
	defer gw.Close()

	cfg := WebhookConfig{
		MaxRetries:        3,
		InitialBackoff:    10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		HTTPTimeout:       1 * time.Second,
		Workers:           2,
		QueueSize:         100,
	}
	engine := NewWebhookEngine(cfg, gw.Metrics())
	gw.SetWebhookEngine(engine)

	_, err := engine.CreateSubscription("tenant_dlq", CreateSubscriptionRequest{
		URL:    mockEndpoint.URL,
		Events: []string{"ddos.detected"},
	})
	if err != nil {
		t.Fatalf("failed to create subscription: %v", err)
	}

	// Dispatch event while listener is unhealthy
	_, err = engine.Dispatch(WebhookEvent{
		Type:     "ddos.detected",
		TenantID: "tenant_dlq",
		Data:     []byte(`{"target_zone":"sg-sin-1","peak_gbps":450}`),
	})
	if err != nil {
		t.Fatalf("failed to dispatch: %v", err)
	}

	// Wait for all 3 attempts to fail and land in DLQ
	engine.WaitIdle(2 * time.Second)

	// Verify DLQ via API
	req := httptest.NewRequest(http.MethodGet, "/v1/webhooks/dead-letter", nil)
	req.Header.Set("X-Tenant-ID", "tenant_dlq")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK listing dead letters, got %d", rec.Code)
	}
	var dlqResp struct {
		DeadLetters []DeadLetterItem `json:"dead_letters"`
		Count       int              `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dlqResp); err != nil {
		t.Fatalf("failed to parse DLQ response: %v", err)
	}
	if dlqResp.Count != 1 || len(dlqResp.DeadLetters) != 1 {
		t.Fatalf("expected 1 dead-letter item, got count=%d len=%d", dlqResp.Count, len(dlqResp.DeadLetters))
	}
	deadDeliveryID := dlqResp.DeadLetters[0].Delivery.ID

	// Now listener recovers
	listenerHealthy.Store(true)

	// Trigger redelivery via POST /v1/webhooks/dead-letter/retry
	retryBody := fmt.Sprintf(`{"delivery_id":"%s"}`, deadDeliveryID)
	req = httptest.NewRequest(http.MethodPost, "/v1/webhooks/dead-letter/retry", strings.NewReader(retryBody))
	req.Header.Set("X-Tenant-ID", "tenant_dlq")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on redelivery request, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Wait for redelivered item to reach mock server
	select {
	case <-recoveredCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for redelivered webhook to be received")
	}

	engine.WaitIdle(1 * time.Second)

	// Verify DLQ is now empty
	deadLetters := engine.ListDeadLetters("tenant_dlq")
	if len(deadLetters) != 0 {
		t.Fatalf("expected DLQ to be empty after successful redelivery, got %d items", len(deadLetters))
	}
}

func TestWebhook_PrometheusMetrics(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes")
	defer gw.Close()

	// Record sample webhook metrics
	gw.Metrics().RecordWebhookDispatched("deployment.succeeded")
	gw.Metrics().RecordWebhookDispatched("invoice.paid")
	gw.Metrics().RecordWebhookDelivery("success")
	gw.Metrics().RecordWebhookDelivery("retrying")
	gw.Metrics().RecordWebhookDelivery("dead_letter")
	gw.Metrics().RecordWebhookDLQ()
	gw.Metrics().SetWebhookActiveSubscriptions(4)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	out := rec.Body.String()
	if !strings.Contains(out, `aeitron_api_webhook_dispatched_total{event_type="deployment.succeeded"} 1`) {
		t.Fatalf("expected webhook dispatched metric, got:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_webhook_deliveries_total{status="success"} 1`) {
		t.Fatalf("expected webhook deliveries success metric, got:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_webhook_dlq_total 1`) {
		t.Fatalf("expected webhook DLQ metric, got:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_webhook_active_subscriptions 4`) {
		t.Fatalf("expected webhook active subscriptions metric, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Phase 4: Distributed State Adapter (Redis / KeyDB Cluster) Test Suite
// ---------------------------------------------------------------------------

type mockRedisServer struct {
	listener net.Listener
	addr     string
	mu       sync.Mutex
	data     map[string][]byte
	closed   atomic.Bool
}

func startMockRedisServer(t *testing.T) *mockRedisServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for mock redis: %v", err)
	}
	s := &mockRedisServer{
		listener: ln,
		addr:     ln.Addr().String(),
		data:     make(map[string][]byte),
	}
	go s.serve()
	return s
}

func (s *mockRedisServer) Close() {
	s.closed.Store(true)
	_ = s.listener.Close()
}

func (s *mockRedisServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *mockRedisServer) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		if s.closed.Load() {
			return
		}
		reply, err := readRESPReply(reader)
		if err != nil {
			return
		}

		args, ok := reply.([]any)
		if !ok || len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(fmt.Sprintf("%s", args[0]))
		switch cmd {
		case "PING":
			_, _ = writer.WriteString("+PONG\r\n")
		case "AUTH", "SELECT":
			_, _ = writer.WriteString("+OK\r\n")
		case "GET":
			if len(args) > 1 {
				k := fmt.Sprintf("%s", args[1])
				s.mu.Lock()
				val, exists := s.data[k]
				s.mu.Unlock()
				if !exists {
					_, _ = writer.WriteString("$-1\r\n")
				} else {
					_, _ = writer.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(val), val))
				}
			}
		case "SET":
			if len(args) > 2 {
				k := fmt.Sprintf("%s", args[1])
				v := []byte(fmt.Sprintf("%s", args[2]))
				s.mu.Lock()
				s.data[k] = v
				s.mu.Unlock()
				_, _ = writer.WriteString("+OK\r\n")
			}
		case "DEL":
			if len(args) > 1 {
				k := fmt.Sprintf("%s", args[1])
				s.mu.Lock()
				delete(s.data, k)
				s.mu.Unlock()
				_, _ = writer.WriteString(":1\r\n")
			}
		case "KEYS":
			pattern := "*"
			if len(args) > 1 {
				pattern = fmt.Sprintf("%s", args[1])
			}
			prefix := strings.TrimSuffix(pattern, "*")
			s.mu.Lock()
			var matched []string
			for k := range s.data {
				if strings.HasPrefix(k, prefix) {
					matched = append(matched, k)
				}
			}
			s.mu.Unlock()
			_, _ = writer.WriteString(fmt.Sprintf("*%d\r\n", len(matched)))
			for _, m := range matched {
				_, _ = writer.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(m), m))
			}
		case "EVAL":
			// Token-bucket EVAL script returns array: [allowed (1 or 0), remaining, retry_ms]
			_, _ = writer.WriteString("*3\r\n:1\r\n:9\r\n:0\r\n")
		default:
			_, _ = writer.WriteString("+OK\r\n")
		}
		_ = writer.Flush()
	}
}

func TestCluster_MemoryAdapter(t *testing.T) {
	adapter := NewMemoryStateAdapter()
	defer adapter.Close()

	if adapter.Name() != "memory" {
		t.Fatalf("expected adapter name memory, got %s", adapter.Name())
	}
	if err := adapter.Ping(context.Background()); err != nil {
		t.Fatalf("unexpected ping error on memory adapter: %v", err)
	}

	ctx := context.Background()

	// KV Get/Set/Delete
	if err := adapter.Set(ctx, "user:101", []byte("mahmud"), 10*time.Second); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	val, err := adapter.Get(ctx, "user:101")
	if err != nil || string(val) != "mahmud" {
		t.Fatalf("get failed: %v, val: %s", err, string(val))
	}
	if err := adapter.Delete(ctx, "user:101"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	_, err = adapter.Get(ctx, "user:101")
	if err == nil {
		t.Fatalf("expected error on missing key, got nil")
	}

	// DeletePrefix
	_ = adapter.Set(ctx, "cache:products:1", []byte("p1"), 10*time.Second)
	_ = adapter.Set(ctx, "cache:products:2", []byte("p2"), 10*time.Second)
	_ = adapter.Set(ctx, "cache:orders:1", []byte("o1"), 10*time.Second)
	deleted, err := adapter.DeletePrefix(ctx, "cache:products:")
	if err != nil || deleted != 2 {
		t.Fatalf("delete prefix failed: %v, count: %d", err, deleted)
	}

	// RateLimitAllow
	allowed, rem, wait, err := adapter.RateLimitAllow(ctx, "ip:1.2.3.4", 10.0, 5)
	if err != nil || !allowed || rem != 4 || wait != 0 {
		t.Fatalf("ratelimit allow failed: allowed=%v, rem=%d, wait=%v, err=%v", allowed, rem, wait, err)
	}

	// Idempotency Acquire / Complete
	acquired, existing, err := adapter.IdempotencyAcquire(ctx, "tenant:tx1", "hash1", 10*time.Second)
	if err != nil || !acquired || existing == nil {
		t.Fatalf("idempotency acquire failed: acquired=%v, err=%v", acquired, err)
	}
	// Second acquire should detect in-flight
	acquired2, _, _ := adapter.IdempotencyAcquire(ctx, "tenant:tx1", "hash1", 10*time.Second)
	if acquired2 {
		t.Fatal("second acquire should not have succeeded")
	}

	// Complete
	rec := existing
	rec.StatusCode = 200
	rec.ResponseBody = []byte("processed")
	if err := adapter.IdempotencyComplete(ctx, "tenant:tx1", rec, 10*time.Second); err != nil {
		t.Fatalf("idempotency complete failed: %v", err)
	}

	// Abort
	_ = adapter.Set(ctx, "tenant:tx2", []byte("temp"), 10*time.Second)
	if err := adapter.IdempotencyAbort(ctx, "tenant:tx2"); err != nil {
		t.Fatalf("abort failed: %v", err)
	}
}

func TestCluster_RESPWireProtocol(t *testing.T) {
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	// Write command: SET key value EX 60
	err := writeRESPCommand(writer, "SET", "cluster_key", "test_payload", "EX", "60")
	if err != nil {
		t.Fatalf("writeRESPCommand failed: %v", err)
	}
	_ = writer.Flush()

	expectedHeader := "*5\r\n$3\r\nSET\r\n$11\r\ncluster_key\r\n$12\r\ntest_payload\r\n$2\r\nEX\r\n$2\r\n60\r\n"
	if buf.String() != expectedHeader {
		t.Fatalf("unexpected RESP wire format:\n%q\nexpected:\n%q", buf.String(), expectedHeader)
	}

	// Parse reply
	reader := bufio.NewReader(strings.NewReader("+OK\r\n:42\r\n$5\r\nhello\r\n$-1\r\n*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"))
	r1, _ := readRESPReply(reader)
	if r1 != "OK" {
		t.Fatalf("expected OK, got %v", r1)
	}
	r2, _ := readRESPReply(reader)
	if r2 != int64(42) {
		t.Fatalf("expected 42, got %v", r2)
	}
	r3, _ := readRESPReply(reader)
	if r3 != "hello" {
		t.Fatalf("expected hello, got %v", r3)
	}
	r4, _ := readRESPReply(reader)
	if r4 != nil {
		t.Fatalf("expected nil for $-1, got %v", r4)
	}
	r5, _ := readRESPReply(reader)
	arr, ok := r5.([]any)
	if !ok || len(arr) != 2 || arr[0] != "foo" || arr[1] != "bar" {
		t.Fatalf("expected [foo bar], got %v", r5)
	}
}

func TestCluster_RedisAdapter_LiveMock(t *testing.T) {
	mockServer := startMockRedisServer(t)
	defer mockServer.Close()

	metrics := NewMetricsCollector(time.Now())
	adapter, err := NewRedisStateAdapter("redis://"+mockServer.addr, DefaultRedisConfig(mockServer.addr), metrics)
	if err != nil {
		t.Fatalf("failed to create redis state adapter: %v", err)
	}
	defer adapter.Close()

	if adapter.Name() != "redis" {
		t.Fatalf("expected name redis, got %s", adapter.Name())
	}

	ctx := context.Background()

	// Ping
	if err := adapter.Ping(ctx); err != nil {
		t.Fatalf("redis ping failed: %v", err)
	}

	// Set & Get
	if err := adapter.Set(ctx, "cluster:token", []byte("bearer-xyz"), 30*time.Second); err != nil {
		t.Fatalf("redis set failed: %v", err)
	}
	val, err := adapter.Get(ctx, "cluster:token")
	if err != nil || string(val) != "bearer-xyz" {
		t.Fatalf("redis get failed: %v, val: %s", err, string(val))
	}

	// Delete
	if err := adapter.Delete(ctx, "cluster:token"); err != nil {
		t.Fatalf("redis delete failed: %v", err)
	}

	// RateLimitAllow
	allowed, rem, wait, err := adapter.RateLimitAllow(ctx, "user:42", 100.0, 10)
	if err != nil || !allowed || rem != 9 || wait != 0 {
		t.Fatalf("redis ratelimit allow failed: allowed=%v, rem=%d, wait=%v, err=%v", allowed, rem, wait, err)
	}

	// Idempotency Lifecycle
	acquired, existing, err := adapter.IdempotencyAcquire(ctx, "idemp:req1", "hash123", 60*time.Second)
	if err != nil || !acquired || existing == nil {
		t.Fatalf("redis idempotency acquire failed: %v", err)
	}
	rec := existing
	rec.StatusCode = 201
	rec.ResponseBody = []byte(`{"created":true}`)
	if err := adapter.IdempotencyComplete(ctx, "idemp:req1", rec, 60*time.Second); err != nil {
		t.Fatalf("redis idempotency complete failed: %v", err)
	}
	if err := adapter.IdempotencyAbort(ctx, "idemp:req1"); err != nil {
		t.Fatalf("redis idempotency abort failed: %v", err)
	}
}

func TestCluster_RedisAdapter_FailOpen(t *testing.T) {
	mockServer := startMockRedisServer(t)
	metrics := NewMetricsCollector(time.Now())
	adapter, err := NewRedisStateAdapter("redis://"+mockServer.addr, DefaultRedisConfig(mockServer.addr), metrics)
	if err != nil {
		t.Fatalf("failed to create redis state adapter: %v", err)
	}
	defer adapter.Close()

	ctx := context.Background()
	_ = adapter.Set(ctx, "k1", []byte("v1"), 10*time.Second)

	// Terminate Redis mock server abruptly
	mockServer.Close()

	// Operations must fail-open to internal memory fallback without crashing or returning errors
	err = adapter.Set(ctx, "k2", []byte("v2"), 10*time.Second)
	if err != nil {
		t.Fatalf("expected fail-open set to succeed, got %v", err)
	}
	val, err := adapter.Get(ctx, "k2")
	if err != nil || string(val) != "v2" {
		t.Fatalf("expected fail-open get to retrieve from memory fallback, got val: %s, err: %v", string(val), err)
	}

	allowed, rem, _, err := adapter.RateLimitAllow(ctx, "ip:5.5.5.5", 10.0, 5)
	if err != nil || !allowed || rem != 4 {
		t.Fatalf("expected fail-open ratelimit to succeed via memory, allowed=%v, rem=%d, err=%v", allowed, rem, err)
	}

	acquired, _, err := adapter.IdempotencyAcquire(ctx, "idemp:failopen", "hashabc", 10*time.Second)
	if err != nil || !acquired {
		t.Fatalf("expected fail-open idempotency acquire to succeed via memory, acquired=%v, err=%v", acquired, err)
	}
}

func TestCluster_GatewayAutoDetection(t *testing.T) {
	// 1. Without REDIS_URL -> defaults to MemoryStateAdapter
	t.Setenv("REDIS_URL", "")
	gwMem := NewAPIGateway("jwt-secret")
	defer gwMem.Close()

	if gwMem.StateAdapter().Name() != "memory" {
		t.Fatalf("expected standalone memory adapter, got %s", gwMem.StateAdapter().Name())
	}

	// 2. With REDIS_URL -> auto-connects to RedisStateAdapter
	mockServer := startMockRedisServer(t)
	defer mockServer.Close()

	t.Setenv("REDIS_URL", "redis://"+mockServer.addr)
	gwRedis := NewAPIGateway("jwt-secret")
	defer gwRedis.Close()

	if gwRedis.StateAdapter().Name() != "redis" {
		t.Fatalf("expected distributed redis adapter, got %s", gwRedis.StateAdapter().Name())
	}
}

func TestCluster_EndpointAndTelemetry(t *testing.T) {
	// Standalone Gateway
	t.Setenv("REDIS_URL", "")
	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/gateway/cluster", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /v1/gateway/cluster, got %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse cluster JSON: %v", err)
	}
	if resp["mode"] != "memory" || resp["status"] != "standalone" {
		t.Fatalf("unexpected cluster telemetry: %v", resp)
	}

	// Connected Gateway
	mockServer := startMockRedisServer(t)
	defer mockServer.Close()

	t.Setenv("REDIS_URL", "redis://"+mockServer.addr)
	gwCluster := NewAPIGateway("jwt-secret")
	defer gwCluster.Close()

	req2 := httptest.NewRequest(http.MethodGet, "/v1/gateway/cluster", nil)
	rec2 := httptest.NewRecorder()
	gwCluster.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /v1/gateway/cluster, got %d", rec2.Code)
	}
	var resp2 map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to parse cluster JSON: %v", err)
	}
	if resp2["mode"] != "redis" || resp2["status"] != "connected" {
		t.Fatalf("unexpected connected cluster telemetry: %v", resp2)
	}
}

func TestCluster_PrometheusMetrics(t *testing.T) {
	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	gw.Metrics().SetClusterMode("redis")
	gw.Metrics().RecordClusterOp("get_hit")
	gw.Metrics().RecordClusterOp("set")
	gw.Metrics().RecordClusterError()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	out := rec.Body.String()
	if !strings.Contains(out, `aeitron_api_cluster_state_mode{mode="redis"} 1`) {
		t.Fatalf("missing cluster mode in metrics:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_cluster_state_ops_total{op="get_hit"} 1`) {
		t.Fatalf("missing cluster op in metrics:\n%s", out)
	}
	if !strings.Contains(out, `aeitron_api_cluster_state_errors_total 1`) {
		t.Fatalf("missing cluster error in metrics:\n%s", out)
	}
}

func TestCluster_MultiTierCache(t *testing.T) {
	mockServer := startMockRedisServer(t)
	defer mockServer.Close()

	t.Setenv("REDIS_URL", "redis://"+mockServer.addr)
	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	cacheEngine := gw.Cache()

	// Seed L2 directly via cluster adapter
	key := "public:GET:/v1/catalog"
	now := time.Now().UTC()
	l2Entry := CacheEntry{
		Key:        key,
		Path:       "/v1/catalog",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"products":["compute","vps"]}`),
		CachedAt:   now,
		ExpiresAt:  now.Add(60 * time.Second),
		TTL:        60 * time.Second,
		ETag:       `"l2-etag-123"`,
	}
	l2Data, _ := json.Marshal(l2Entry)
	_ = gw.StateAdapter().Set(context.Background(), "cache:"+key, l2Data, 60*time.Second)

	// L1 Cache is currently cold
	entry, hit := cacheEngine.Lookup(key)
	if !hit || entry == nil {
		t.Fatalf("expected cache lookup to hit L2 distributed cache and return entry")
	}
	if string(entry.Body) != `{"products":["compute","vps"]}` {
		t.Fatalf("unexpected entry body from L2: %s", string(entry.Body))
	}

	// Subsequent lookup hits L1 in-memory immediately
	entry2, hit2 := cacheEngine.Lookup(key)
	if !hit2 || entry2 == nil {
		t.Fatalf("expected L1 cache hit on second lookup")
	}

	// Purge via gateway invalidates both L1 and L2
	req := httptest.NewRequest(http.MethodDelete, "/v1/gateway/cache", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from cache purge, got %d", rec.Code)
	}

	_, hitAfterPurge := cacheEngine.Lookup(key)
	if hitAfterPurge {
		t.Fatal("expected cache miss after cluster purge")
	}
}

// ---------------------------------------------------------------------------
// Distributed Tracing Tests (W3C traceparent, OpenTelemetry & Jaeger)
// ---------------------------------------------------------------------------

func TestTracing_W3CGenerationAndPropagation(t *testing.T) {
	var upstreamReceivedTP, upstreamReceivedState string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedTP = r.Header.Get("traceparent")
		upstreamReceivedState = r.Header.Get("tracestate")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret-xyz-32-bytes-long")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/trace-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/trace-test/data", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// 1. Verify W3C traceparent format in client response
	respTP := rec.Header().Get("traceparent")
	if respTP == "" {
		t.Fatalf("expected traceparent header in gateway response")
	}
	tpRegex := regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
	matches := tpRegex.FindStringSubmatch(respTP)
	if len(matches) != 4 {
		t.Fatalf("traceparent header '%s' does not match W3C specification", respTP)
	}
	traceID := matches[1]
	flags := matches[3]
	if flags != "01" {
		t.Fatalf("expected sampled flag '01', got '%s'", flags)
	}

	respState := rec.Header().Get("tracestate")
	if !strings.Contains(respState, "aeitron=gateway") {
		t.Fatalf("expected tracestate to include 'aeitron=gateway', got '%s'", respState)
	}

	// 2. Verify W3C traceparent propagated to upstream with same trace-id and child span-id
	if upstreamReceivedTP == "" {
		t.Fatalf("expected upstream to receive propagated traceparent")
	}
	upMatches := tpRegex.FindStringSubmatch(upstreamReceivedTP)
	if len(upMatches) != 4 {
		t.Fatalf("upstream traceparent '%s' does not match W3C specification", upstreamReceivedTP)
	}
	if upMatches[1] != traceID {
		t.Fatalf("expected upstream traceID '%s' to match root traceID '%s'", upMatches[1], traceID)
	}
	if !strings.Contains(upstreamReceivedState, "aeitron=gateway") {
		t.Fatalf("expected upstream tracestate to include 'aeitron=gateway', got '%s'", upstreamReceivedState)
	}
}

func TestTracing_IncomingTraceparentPreserved(t *testing.T) {
	incomingTraceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingParentSpan := "00f067aa0ba902b7"
	incomingTP := fmt.Sprintf("00-%s-%s-01", incomingTraceID, incomingParentSpan)

	var upstreamReceivedTP string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedTP = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/trace-preserve",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/trace-preserve/item", nil)
	req.Header.Set("traceparent", incomingTP)
	req.Header.Set("tracestate", "congo=t61rcWkgMzE")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	respTP := rec.Header().Get("traceparent")
	if !strings.Contains(respTP, incomingTraceID) {
		t.Fatalf("expected gateway to preserve incoming trace ID '%s', got '%s'", incomingTraceID, respTP)
	}

	// Upstream should also receive the incoming trace ID
	if !strings.Contains(upstreamReceivedTP, incomingTraceID) {
		t.Fatalf("expected upstream to receive incoming trace ID '%s', got '%s'", incomingTraceID, upstreamReceivedTP)
	}
}

func TestTracing_MicrosecondSpansRecorded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret-testing-32-bytes-long")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: false,
		CacheTTL:       30 * time.Second,
	})

	// Generate authenticated token
	token, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "user-42",
		TenantID: "tenant-enterprise-99",
		Role:     "admin",
		Tier:     "enterprise",
		Exp:      time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/orders/123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	respTP := rec.Header().Get("traceparent")
	parts := strings.Split(respTP, "-")
	traceID := parts[1]

	// Query trace details via /v1/gateway/traces/{trace_id}
	traceReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/traces/"+traceID, nil)
	traceRec := httptest.NewRecorder()
	gw.ServeHTTP(traceRec, traceReq)

	if traceRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for trace detail query, got %d", traceRec.Code)
	}

	var tc TraceContext
	if err := json.Unmarshal(traceRec.Body.Bytes(), &tc); err != nil {
		t.Fatalf("failed to decode trace response: %v", err)
	}

	if tc.TraceID != traceID {
		t.Fatalf("expected traceID %s, got %s", traceID, tc.TraceID)
	}
	if tc.DurationMicros <= 0 {
		t.Fatalf("expected positive duration in microseconds, got %d", tc.DurationMicros)
	}

	// Verify tracked lifecycle spans: ingress, ratelimit, auth, cache, upstream
	spanNames := make(map[string]*Span)
	for _, s := range tc.Spans {
		spanNames[s.Name] = s
	}

	expectedSpans := []string{
		"gateway.ingress",
		"gateway.ratelimit",
		"gateway.auth",
		"gateway.cache",
		"gateway.upstream",
	}

	for _, name := range expectedSpans {
		s, ok := spanNames[name]
		if !ok {
			t.Errorf("expected span '%s' to be recorded in trace", name)
			continue
		}
		if s.DurationMicros < 0 {
			t.Errorf("span '%s' has invalid duration %d", name, s.DurationMicros)
		}
	}

	// Check auth span attributes
	authSpan := spanNames["gateway.auth"]
	if authSpan != nil {
		if authSpan.Attributes["tenant_id"] != "tenant-enterprise-99" {
			t.Fatalf("expected auth span tenant_id 'tenant-enterprise-99', got '%s'", authSpan.Attributes["tenant_id"])
		}
	}

	// Check upstream span attributes
	upSpan := spanNames["gateway.upstream"]
	if upSpan != nil {
		if upSpan.Attributes["upstream.route"] != "/v1/orders" {
			t.Fatalf("expected upstream span route '/v1/orders', got '%s'", upSpan.Attributes["upstream.route"])
		}
	}
}

func TestTracing_SlowTraceDetection(t *testing.T) {
	// Mock upstream with simulated 60ms delay (> 50ms default threshold)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(55 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"delay":"completed"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/slow-svc",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	initialSlow := gw.Metrics().SlowTracesTotal()

	req := httptest.NewRequest(http.MethodGet, "/v1/slow-svc/compute", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Verify slow trace metric incremented
	currentSlow := gw.Metrics().SlowTracesTotal()
	if currentSlow <= initialSlow {
		t.Fatalf("expected slow traces count to increment, initially %d, now %d", initialSlow, currentSlow)
	}

	// Verify query to /v1/gateway/traces/slow
	slowReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/traces/slow", nil)
	slowRec := httptest.NewRecorder()
	gw.ServeHTTP(slowRec, slowReq)

	if slowRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for slow traces endpoint, got %d", slowRec.Code)
	}

	var slowResp struct {
		SlowTraces []*TraceContext `json:"slow_traces"`
		Count      int             `json:"count"`
	}
	if err := json.Unmarshal(slowRec.Body.Bytes(), &slowResp); err != nil {
		t.Fatalf("failed to decode slow traces response: %v", err)
	}

	if slowResp.Count == 0 {
		t.Fatalf("expected at least 1 slow trace in /v1/gateway/traces/slow response")
	}
	if slowResp.SlowTraces[0].DurationMicros < 50000 {
		t.Fatalf("expected slow trace duration >= 50,000 micros (50ms), got %d", slowResp.SlowTraces[0].DurationMicros)
	}
}

func TestTracing_OpenTelemetryAndJaegerExport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"export":"test"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/export-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/export-test/run", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	respTP := rec.Header().Get("traceparent")
	traceID := strings.Split(respTP, "-")[1]

	// 1. Export in OpenTelemetry (OTLP) Format
	otlpReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/traces/"+traceID+"/export?format=otlp", nil)
	otlpRec := httptest.NewRecorder()
	gw.ServeHTTP(otlpRec, otlpReq)

	if otlpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for OTLP export, got %d", otlpRec.Code)
	}
	var otlpMap map[string]any
	if err := json.Unmarshal(otlpRec.Body.Bytes(), &otlpMap); err != nil {
		t.Fatalf("failed to unmarshal OTLP export: %v", err)
	}
	if _, ok := otlpMap["resourceSpans"]; !ok {
		t.Fatalf("expected 'resourceSpans' in OTLP export schema")
	}

	// 2. Export in Jaeger Format
	jaegerReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/traces/"+traceID+"/export?format=jaeger", nil)
	jaegerRec := httptest.NewRecorder()
	gw.ServeHTTP(jaegerRec, jaegerReq)

	if jaegerRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for Jaeger export, got %d", jaegerRec.Code)
	}
	var jaegerMap map[string]any
	if err := json.Unmarshal(jaegerRec.Body.Bytes(), &jaegerMap); err != nil {
		t.Fatalf("failed to unmarshal Jaeger export: %v", err)
	}
	dataList, ok := jaegerMap["data"].([]any)
	if !ok || len(dataList) == 0 {
		t.Fatalf("expected 'data' array in Jaeger export")
	}
	firstTrace := dataList[0].(map[string]any)
	if firstTrace["traceID"] != traceID {
		t.Fatalf("expected Jaeger traceID %s, got %v", traceID, firstTrace["traceID"])
	}
}

func TestTracing_ZipkinExport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"zipkin":"ok"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/zipkin-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/zipkin-test/check", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	respTP := rec.Header().Get("traceparent")
	traceID := strings.Split(respTP, "-")[1]

	zipkinReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/traces/"+traceID+"/export?format=zipkin", nil)
	zipkinRec := httptest.NewRecorder()
	gw.ServeHTTP(zipkinRec, zipkinReq)

	if zipkinRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for Zipkin export, got %d", zipkinRec.Code)
	}
	var zipkinSpans []map[string]any
	if err := json.Unmarshal(zipkinRec.Body.Bytes(), &zipkinSpans); err != nil {
		t.Fatalf("failed to decode Zipkin JSON spans: %v", err)
	}
	if len(zipkinSpans) == 0 {
		t.Fatalf("expected non-empty array of Zipkin spans")
	}
	if zipkinSpans[0]["traceId"] != traceID {
		t.Fatalf("expected Zipkin span traceId %s, got %v", traceID, zipkinSpans[0]["traceId"])
	}
}

func TestTracing_DynamicConfigurationAndStats(t *testing.T) {
	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	// 1. Initial Stats
	statsReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/traces/stats", nil)
	statsRec := httptest.NewRecorder()
	gw.ServeHTTP(statsRec, statsReq)

	if statsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for stats, got %d", statsRec.Code)
	}
	var stats TracingStats
	_ = json.Unmarshal(statsRec.Body.Bytes(), &stats)
	if stats.MaxCapacity != 10000 {
		t.Fatalf("expected max capacity 10,000, got %d", stats.MaxCapacity)
	}

	// 2. Dynamic Config Update: set sampling to 0.75 and slow threshold to 80ms
	cfgBody := `{"sampling_rate": 0.75, "slow_threshold_ms": 80}`
	cfgReq := httptest.NewRequest(http.MethodPost, "/v1/gateway/traces/config", strings.NewReader(cfgBody))
	cfgRec := httptest.NewRecorder()
	gw.ServeHTTP(cfgRec, cfgReq)

	if cfgRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for config update, got %d", cfgRec.Code)
	}

	var updateResp struct {
		Status string       `json:"status"`
		Stats  TracingStats `json:"stats"`
	}
	_ = json.Unmarshal(cfgRec.Body.Bytes(), &updateResp)
	if updateResp.Stats.SamplingRate != 0.75 {
		t.Fatalf("expected sampling rate 0.75, got %f", updateResp.Stats.SamplingRate)
	}
	if updateResp.Stats.SlowThresholdMs != 80 {
		t.Fatalf("expected slow threshold 80ms, got %d", updateResp.Stats.SlowThresholdMs)
	}
}

func TestTracing_PrometheusMetrics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"metrics":"tracing"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/metric-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/metric-test/sample", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	// Fetch /metrics
	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	gw.ServeHTTP(metricsRec, metricsReq)

	if metricsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d", metricsRec.Code)
	}

	output := metricsRec.Body.String()
	if !strings.Contains(output, "aeitron_api_traces_total") {
		t.Fatalf("expected 'aeitron_api_traces_total' in metrics output")
	}
	if !strings.Contains(output, "aeitron_api_spans_total{name=\"gateway.ingress\"}") {
		t.Fatalf("expected 'aeitron_api_spans_total{name=\"gateway.ingress\"}' in metrics output")
	}
	if !strings.Contains(output, "aeitron_api_slow_traces_total") {
		t.Fatalf("expected 'aeitron_api_slow_traces_total' in metrics output")
	}
}

func TestAPIGateway_Versioning_DefaultBaseline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/version-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/version-test/resource", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	version := rec.Header().Get("Aeitron-Version")
	if version != "2026-11-01" {
		t.Fatalf("expected default baseline version '2026-11-01', got %q", version)
	}
	vary := rec.Header().Get("Vary")
	if !strings.Contains(vary, "Aeitron-Version") {
		t.Fatalf("expected Vary header to contain Aeitron-Version, got %q", vary)
	}
	if rec.Header().Get("X-Aeitron-Deprecation-Date") != "" {
		t.Fatalf("did not expect deprecation header on baseline version")
	}
}

func TestAPIGateway_Versioning_ExplicitVersion(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/version-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/version-test/resource", nil)
	req.Header.Set("Aeitron-Version", "2026-06-01")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	version := rec.Header().Get("Aeitron-Version")
	if version != "2026-06-01" {
		t.Fatalf("expected version '2026-06-01', got %q", version)
	}
	if rec.Header().Get("X-Aeitron-Deprecation-Date") != "" {
		t.Fatalf("did not expect deprecation header on active 2026-06-01 version")
	}
}

func TestAPIGateway_Versioning_MalformedRejected(t *testing.T) {
	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/version-test/resource", nil)
	req.Header.Set("Aeitron-Version", "2026/11/01")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for malformed version date, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "YYYY-MM-DD") {
		t.Fatalf("expected error message to explain YYYY-MM-DD format, got %s", rec.Body.String())
	}
}

func TestAPIGateway_Versioning_UnsupportedRejected(t *testing.T) {
	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/version-test/resource", nil)
	req.Header.Set("Aeitron-Version", "2020-01-01")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for unsupported version, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "supported versions") {
		t.Fatalf("expected error message to list supported versions, got %s", rec.Body.String())
	}
}

func TestAPIGateway_Versioning_DeprecationHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"deprecated_compat_ok"}`))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/version-test",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/version-test/resource", nil)
	req.Header.Set("Aeitron-Version", "2026-01-01")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// Verify RFC 8594 / Stripe deprecation headers
	version := rec.Header().Get("Aeitron-Version")
	if version != "2026-01-01" {
		t.Fatalf("expected version '2026-01-01', got %q", version)
	}

	depDate := rec.Header().Get("X-Aeitron-Deprecation-Date")
	if depDate != "2027-01-01" {
		t.Fatalf("expected X-Aeitron-Deprecation-Date '2027-01-01', got %q", depDate)
	}

	sunset := rec.Header().Get("Sunset")
	if sunset == "" || !strings.Contains(sunset, "2027") {
		t.Fatalf("expected valid RFC 8594 Sunset header, got %q", sunset)
	}

	link := rec.Header().Get("Link")
	if !strings.Contains(link, "rel=\"deprecation\"") {
		t.Fatalf("expected Link header with rel=deprecation, got %q", link)
	}

	warning := rec.Header().Get("X-Aeitron-Warning")
	if !strings.Contains(warning, "2027-01-01") || !strings.Contains(warning, "deprecated") {
		t.Fatalf("expected deprecation warning header, got %q", warning)
	}
}

func TestAPIGateway_Versioning_CachePartitioning(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		ver := r.Header.Get("Aeitron-Version")
		if ver == "" {
			ver = "none"
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"version":"%s","call":%d}`, ver, callCount)))
	}))
	defer upstream.Close()

	gw := NewAPIGateway("jwt-secret")
	defer gw.Close()

	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/cache-version",
		UpstreamURL:    upstream.URL,
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	// 1. First request with baseline version (2026-11-01) -> Cache MISS, upstream call 1
	req1 := httptest.NewRequest(http.MethodGet, "/v1/cache-version/data", nil)
	req1.Header.Set("Aeitron-Version", "2026-11-01")
	rec1 := httptest.NewRecorder()
	gw.ServeHTTP(rec1, req1)
	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS on first request, got %q", rec1.Header().Get("X-Cache"))
	}

	// 2. Second request with same baseline version -> Cache HIT
	req2 := httptest.NewRequest(http.MethodGet, "/v1/cache-version/data", nil)
	req2.Header.Set("Aeitron-Version", "2026-11-01")
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req2)
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected HIT on second request with identical version, got %q", rec2.Header().Get("X-Cache"))
	}

	// 3. Third request with different version (2026-06-01) -> Cache MISS, upstream call 2 (partition isolated)
	req3 := httptest.NewRequest(http.MethodGet, "/v1/cache-version/data", nil)
	req3.Header.Set("Aeitron-Version", "2026-06-01")
	rec3 := httptest.NewRecorder()
	gw.ServeHTTP(rec3, req3)
	if rec3.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("expected MISS on third request with different version, got %q", rec3.Header().Get("X-Cache"))
	}
	if rec3.Header().Get("Aeitron-Version") != "2026-06-01" {
		t.Fatalf("expected version 2026-06-01, got %q", rec3.Header().Get("Aeitron-Version"))
	}
}

func TestSecurity_JWTHeaderValidationAndAlgNone(t *testing.T) {
	secret := "test-secret-32-bytes-auth-scopes-gate"
	gw := NewAPIGateway(secret)

	// 1. Attack: alg=none token
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","tenant_id":"t1","exp":9999999999}`))
	noneToken := noneHeader + "." + payload + "."

	req := httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	req.Header.Set("Authorization", "Bearer "+noneToken)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for alg=none, got %d", rec.Code)
	}

	// 2. Attack: unsupported alg=RS256
	rsHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	rsToken := rsHeader + "." + payload + ".somesig"
	req = httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	req.Header.Set("Authorization", "Bearer "+rsToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for alg=RS256, got %d", rec.Code)
	}

	// 3. Attack: missing exp timestamp (exp=0)
	noExpToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_no_exp",
		TenantID: "tenant_corp",
		Exp:      0,
	})
	req = httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	req.Header.Set("Authorization", "Bearer "+noExpToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing exp, got %d", rec.Code)
	}

	// 4. Attack: missing tenant_id claim
	noTenantToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_no_tenant",
		TenantID: "",
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	req = httptest.NewRequest(http.MethodGet, "/v1/databases/instances", nil)
	req.Header.Set("Authorization", "Bearer "+noTenantToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing tenant_id, got %d", rec.Code)
	}
}

func TestSecurity_RouteMatchingSegmentBoundary(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-auth-scopes-gate")

	// Verify route prefix isolation: /v1/auth is anonymous, but /v1/auth-malicious or /v1/auth_attack must NOT match /v1/auth
	rule, _ := gw.matchRoute("/v1/auth-malicious")
	if rule != nil && rule.PathPrefix == "/v1/auth" {
		t.Fatalf("security violation: /v1/auth-malicious must not match /v1/auth prefix")
	}

	// Verify path traversal cleaning: /v1/auth/../billing should resolve to /v1/billing, NOT /v1/auth
	rule, _ = gw.matchRoute("/v1/auth/../billing")
	if rule == nil || rule.PathPrefix != "/v1/billing" {
		t.Fatalf("expected /v1/auth/../billing to clean and match /v1/billing, got rule: %v", rule)
	}
}

func TestSecurity_SSRFUpstreamRegistration(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-auth-scopes-gate")

	// 1. Attempt to register cloud metadata IP
	err := gw.RegisterRoute(RouteRule{
		PathPrefix:  "/v1/exploit-metadata",
		UpstreamURL: "http://169.254.169.254/latest/meta-data",
	})
	if err == nil {
		t.Fatalf("expected RegisterRoute to reject 169.254.169.254, but succeeded")
	}

	// 2. Attempt to register metadata.google.internal
	err = gw.RegisterRoute(RouteRule{
		PathPrefix:  "/v1/exploit-gcp",
		UpstreamURL: "http://metadata.google.internal/computeMetadata/v1/",
	})
	if err == nil {
		t.Fatalf("expected RegisterRoute to reject metadata.google.internal, but succeeded")
	}
}

func TestSecurity_AdministrativeCachePurge(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-auth-scopes-gate")

	// 1. Operator with admin role can purge cache and spools audit record
	adminToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_admin",
		TenantID: "tenant_master",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodDelete, "/v1/gateway/cache", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin cache purge, got %d", rec.Code)
	}

	// Verify audit record was spooled
	time.Sleep(50 * time.Millisecond)
	records := gw.AuditSpooler().GetRecords()
	found := false
	for _, r := range records {
		if r.Path == "/v1/gateway/cache" && r.ActorID == "usr_admin" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected audit record for admin cache purge to be spooled")
	}

	// 2. Member with insufficient scope receives 403 Forbidden
	memberToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_member",
		TenantID: "tenant_regular",
		Role:     "member",
		Scopes:   []string{"billing:read"}, // missing cache:purge or admin
		Exp:      time.Now().Add(time.Hour).Unix(),
	})

	req = httptest.NewRequest(http.MethodDelete, "/v1/gateway/cache", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for member cache purge, got %d", rec.Code)
	}
}

func TestSecurity_CORSOriginAllowlist(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-auth-scopes-gate")

	// 1. Allowed Origin -> returns Allow-Origin and Vary: Origin
	req := httptest.NewRequest(http.MethodOptions, "/v1/databases/instances", nil)
	req.Header.Set("Origin", "https://dashboard.aeitron.com")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for allowed origin, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://dashboard.aeitron.com" {
		t.Fatalf("expected Access-Control-Allow-Origin to match, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
		t.Fatalf("expected Vary: Origin header to be set")
	}

	// 2. Disallowed Origin on OPTIONS preflight -> 403 Forbidden
	reqBad := httptest.NewRequest(http.MethodOptions, "/v1/databases/instances", nil)
	reqBad.Header.Set("Origin", "https://evil-phishing-attacker.com")
	recBad := httptest.NewRecorder()
	gw.ServeHTTP(recBad, reqBad)

	if recBad.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disallowed origin preflight, got %d", recBad.Code)
	}

	// 3. Disallowed Origin on GET request -> do NOT reflect origin header
	reqBadGet := httptest.NewRequest(http.MethodGet, "/ready", nil)
	reqBadGet.Header.Set("Origin", "https://evil-phishing-attacker.com")
	recBadGet := httptest.NewRecorder()
	gw.ServeHTTP(recBadGet, reqBadGet)

	if recBadGet.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("security violation: untrusted origin was reflected in Access-Control-Allow-Origin")
	}
}

func TestSecurity_AdminEndpointsProtectionInProduction(t *testing.T) {
	// Enable production mode for test
	t.Setenv("AEITRON_ENV", "production")

	gw := NewAPIGateway("test-secret-32-bytes-auth-scopes-gate")

	adminEndpoints := []string{
		"/v1/gateway/routes",
		"/v1/gateway/stats",
		"/v1/gateway/upstreams",
		"/v1/gateway/cluster",
		"/v1/gateway/traces",
	}

	// 1. Unauthenticated requests in production must fail closed with 401 Unauthorized
	for _, ep := range adminEndpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for unauthenticated production access to %s, got %d", ep, rec.Code)
		}
	}

	// 2. Regular member user must receive 403 Forbidden
	memberToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_regular",
		TenantID: "tenant_abc",
		Role:     "member",
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	for _, ep := range adminEndpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("Authorization", "Bearer "+memberToken)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for member access to %s, got %d", ep, rec.Code)
		}
	}

	// 3. Admin / operator user receives 200 OK
	adminToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "usr_operator",
		TenantID: "tenant_system",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	for _, ep := range adminEndpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for admin access to %s, got %d (body: %s)", ep, rec.Code, rec.Body.String())
		}
	}
}

func TestSecurity_NewUpstreamProxy_SSRFValidation(t *testing.T) {
	// Attempt to create proxy pointing to cloud metadata
	_, err := NewUpstreamProxy(RouteRule{
		PathPrefix:  "/v1/attack",
		UpstreamURL: "http://169.254.169.254/latest/meta-data",
	})
	if err == nil {
		t.Fatalf("expected NewUpstreamProxy to reject 169.254.169.254, but succeeded")
	}

	// Attempt to create proxy with unsupported protocol
	_, err = NewUpstreamProxy(RouteRule{
		PathPrefix:  "/v1/attack-ftp",
		UpstreamURL: "ftp://127.0.0.1:21/payload",
	})
	if err == nil {
		t.Fatalf("expected NewUpstreamProxy to reject ftp scheme, but succeeded")
	}
}

func TestSecurity_EphemeralRandomSecretWhenEmpty(t *testing.T) {
	// Calling NewAuthenticator with empty secret must generate random 32-byte secret, never a fixed string
	auth1 := NewAuthenticator("")
	auth2 := NewAuthenticator("")

	if len(auth1.jwtSecret) < 32 {
		t.Fatalf("expected generated secret to be >= 32 bytes, got %d", len(auth1.jwtSecret))
	}
	if string(auth1.jwtSecret) == string(auth2.jwtSecret) {
		t.Fatalf("ephemeral secrets must be random per instance, got identical secrets")
	}
	if string(auth1.jwtSecret) == "aeitron-default-secret-key-change-in-production-32bytes" {
		t.Fatalf("must not use predictable default fixed string")
	}
}
