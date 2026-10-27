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
