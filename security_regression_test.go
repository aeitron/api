package apigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSecurityRegression_TestAPIKeyPrivilegeEscalation verifies that test keys
// cannot escalate privileges or access administrative operations.
func TestSecurityRegression_TestAPIKeyPrivilegeEscalation(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-security-reg")
	defer gw.Close()

	// 1. Unregistered test key receives bounded non-admin scopes, NEVER wildcard "*"
	testKey := "aeitron_test_developer_hacker_key_999"
	authCtx, err := gw.Authenticator().validateAPIKey(testKey)
	if err != nil {
		t.Fatalf("expected sandbox developer key to resolve context: %v", err)
	}

	if authCtx.Role != "developer" {
		t.Fatalf("expected role 'developer', got '%s'", authCtx.Role)
	}
	if authCtx.Livemode {
		t.Fatalf("expected livemode to be false for test key, got true")
	}
	for _, s := range authCtx.Scopes {
		if s == "*" {
			t.Fatalf("CRITICAL SECURITY DEFECT: test key auto-provisioned with wildcard scope '*'!")
		}
		if s == "gateway:admin" {
			t.Fatalf("CRITICAL SECURITY DEFECT: test key assigned administrative scope 'gateway:admin'!")
		}
	}

	// 2. Test key attempting administrative endpoint (/v1/gateway/stats) must be rejected with 403 Forbidden
	req := httptest.NewRequest(http.MethodGet, "/v1/gateway/stats", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when test key accesses admin endpoint, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 3. Test key attempting /v1/gateway/upstreams must be rejected with 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/gateway/upstreams", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when test key accesses /v1/gateway/upstreams, got %d", rec.Code)
	}

	// 4. Test key attempting /v1/gateway/traces must be rejected with 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/gateway/traces", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when test key accesses /v1/gateway/traces, got %d", rec.Code)
	}

	// 5. /v1/auth/token rejecting client_id fallback without api_key
	badTokenReq := `{"client_id":"aeitron_test_some_random_id"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/token", strings.NewReader(badTokenReq))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when api_key is missing in /v1/auth/token, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 6. /v1/auth/token exchanging test key returns a token with livemode: false
	validTestTokenReq := `{"api_key":"` + testKey + `"}`
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/token", strings.NewReader(validTestTokenReq))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for test token exchange, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Livemode    *bool  `json:"livemode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("failed to parse token response: %v", err)
	}
	if tokenResp.Livemode == nil || *tokenResp.Livemode != false {
		t.Fatalf("expected token livemode to be explicitly false")
	}

	// 7. Token derived from test key still CANNOT access administrative endpoints
	req = httptest.NewRequest(http.MethodGet, "/v1/gateway/stats", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when token derived from test key accesses admin endpoint, got %d", rec.Code)
	}
}

// TestSecurityRegression_TenantIdentitySpoofing verifies strict tenant isolation
// and prevention of unauthenticated header spoofing in events and webhooks.
func TestSecurityRegression_TenantIdentitySpoofing(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-tenant-spoof")
	defer gw.Close()

	// 1. Unauthenticated access to /v1/events/stream must return 401 Unauthorized
	req := httptest.NewRequest(http.MethodGet, "/v1/events/stream", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated /v1/events/stream, got %d", rec.Code)
	}

	// 2. Spoofed X-Tenant-ID header without token must still return 401 Unauthorized
	req = httptest.NewRequest(http.MethodGet, "/v1/events/stream", nil)
	req.Header.Set("X-Tenant-ID", "tenant_victim")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY DEFECT: unauthenticated X-Tenant-ID header accepted on /v1/events/stream! Got %d", rec.Code)
	}

	// 3. Unauthenticated access to /v1/webhooks/subscriptions must return 401 Unauthorized
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions", nil)
	req.Header.Set("X-Tenant-ID", "tenant_victim")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY DEFECT: unauthenticated X-Tenant-ID header accepted on /v1/webhooks/subscriptions! Got %d", rec.Code)
	}

	// 4. Authenticate as tenant_attacker
	attackerTok, err := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "act_attacker",
		TenantID: "tenant_attacker",
		Role:     "developer",
		Scopes:   []string{"events:write", "webhooks:write"},
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	attackerAuth := "Bearer " + attackerTok

	// 5. Attacker attempts to publish event spoofing tenant_victim in request body -> 403 Forbidden
	spoofedEventJSON := `{
		"topic": "billing.invoices",
		"type": "invoice.paid",
		"tenant_id": "tenant_victim",
		"data": {"amount": 500000}
	}`
	req = httptest.NewRequest(http.MethodPost, "/v1/events/publish", strings.NewReader(spoofedEventJSON))
	req.Header.Set("Authorization", attackerAuth)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY DEFECT: tenant_attacker successfully published event as tenant_victim! Got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 6. Attacker attempts to dispatch webhook spoofing tenant_victim in request body -> 403 Forbidden
	spoofedWebhookJSON := `{
		"type": "deployment.failed",
		"tenant_id": "tenant_victim",
		"data": {"pod": "auth-core-0"}
	}`
	req = httptest.NewRequest(http.MethodPost, "/v1/webhooks/dispatch", strings.NewReader(spoofedWebhookJSON))
	req.Header.Set("Authorization", attackerAuth)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("CRITICAL SECURITY DEFECT: tenant_attacker successfully dispatched webhook as tenant_victim! Got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 7. Legitimate publish matching authenticated tenant succeeds (202 Accepted)
	legitEventJSON := `{
		"topic": "billing.invoices",
		"type": "invoice.paid",
		"tenant_id": "tenant_attacker",
		"data": {"amount": 100}
	}`
	req = httptest.NewRequest(http.MethodPost, "/v1/events/publish", strings.NewReader(legitEventJSON))
	req.Header.Set("Authorization", attackerAuth)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for legitimate tenant publish, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestSecurityRegression_RedisTLSAndFailClosed verifies rediss:// parsing and fail-closed semantics.
func TestSecurityRegression_RedisTLSAndFailClosed(t *testing.T) {
	// 1. parseRedisURL correctly identifies rediss:// scheme and assigns TLS
	addr, password, db, useTLS, err := parseRedisURL("rediss://:mysecretpassword@redis.cluster.aeitron.internal:6380/3")
	if err != nil {
		t.Fatalf("failed to parse rediss URL: %v", err)
	}
	if !useTLS {
		t.Fatalf("expected useTLS=true for rediss:// URL")
	}
	if addr != "redis.cluster.aeitron.internal:6380" {
		t.Fatalf("expected addr 'redis.cluster.aeitron.internal:6380', got '%s'", addr)
	}
	if password != "mysecretpassword" {
		t.Fatalf("expected password 'mysecretpassword', got '%s'", password)
	}
	if db != 3 {
		t.Fatalf("expected db=3, got %d", db)
	}

	// 2. Verify fail-closed mode when Redis is unreachable and FailClosed is configured
	cfg := RedisConfig{
		Addr:        "127.0.0.1:59999", // Unreachable port
		PoolSize:    5,
		DialTimeout: 20 * time.Millisecond,
		ReadTimeout: 20 * time.Millisecond,
		FailClosed:  true,
	}

	adapter := &RedisStateAdapter{
		cfg:      cfg,
		fallback: NewMemoryStateAdapter(),
		pool:     make(chan *redisConn, cfg.PoolSize),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// In fail-closed mode, Get must return ErrClusterUnavailable instead of falling back to memory
	_, getErr := adapter.Get(ctx, "test_cache_key")
	if getErr == nil || !strings.Contains(getErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable in fail-closed mode, got %v", getErr)
	}

	// In fail-closed mode, RateLimitAllow must fail closed (allowed=false and error)
	allowed, _, _, rlErr := adapter.RateLimitAllow(ctx, "test_rate_key", 10.0, 20)
	if allowed {
		t.Fatalf("expected allowed=false in fail-closed mode when redis drops")
	}
	if rlErr == nil || !strings.Contains(rlErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on rate limit in fail-closed mode, got %v", rlErr)
	}

	// In fail-closed mode, IdempotencyAcquire must fail closed
	acquired, _, idempErr := adapter.IdempotencyAcquire(ctx, "idemp_test_key", "hash123", time.Minute)
	if acquired {
		t.Fatalf("expected acquired=false in fail-closed mode when redis drops")
	}
	if idempErr == nil || !strings.Contains(idempErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on idempotency in fail-closed mode, got %v", idempErr)
	}

	// In fail-closed mode, Delete, DeletePrefix, and IdempotencyAbort must also fail closed
	delErr := adapter.Delete(ctx, "some_key")
	if delErr == nil || !strings.Contains(delErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on Delete in fail-closed mode, got %v", delErr)
	}

	_, delPrefErr := adapter.DeletePrefix(ctx, "some_prefix:")
	if delPrefErr == nil || !strings.Contains(delPrefErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on DeletePrefix in fail-closed mode, got %v", delPrefErr)
	}

	abortErr := adapter.IdempotencyAbort(ctx, "some_idemp_key")
	if abortErr == nil || !strings.Contains(abortErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on IdempotencyAbort in fail-closed mode, got %v", abortErr)
	}
}

// TestSecurityRegression_WebhookRedirectSSRF verifies that webhook delivery rejects HTTP redirects
// and does not follow them to internal or metadata IP addresses.
func TestSecurityRegression_WebhookRedirectSSRF(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	// Destination server returning 302 redirect to cloud metadata IP
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := NewSafeWebhookClient(2 * time.Second)
	req, err := http.NewRequest(http.MethodPost, redirectServer.URL, strings.NewReader(`{"test":true}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatalf("expected client to fail when following redirect, but it succeeded")
	}
	if !strings.Contains(err.Error(), "does not follow HTTP redirects") {
		t.Fatalf("expected redirect error message, got %v", err)
	}
}

// TestSecurityRegression_WebhooksAndEventsScopeDenial verifies that callers without granular
// scopes receive 403 Forbidden on events and webhooks endpoints.
func TestSecurityRegression_WebhooksAndEventsScopeDenial(t *testing.T) {
	gw := NewAPIGateway("test-secret-32-bytes-security-scopes")
	defer gw.Close()

	// Token with only billing:read (lacks webhooks:* and events:*)
	noScopeToken, err := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "user_limited",
		TenantID: "tenant_scope_test",
		Role:     "member",
		Scopes:   []string{"billing:read"},
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	authHeader := "Bearer " + noScopeToken

	// 1. GET /v1/webhooks/subscriptions without webhooks:read -> 403 Forbidden
	req := httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing webhooks:read, got %d", rec.Code)
	}

	// 2. POST /v1/webhooks/subscriptions without webhooks:write -> 403 Forbidden
	req = httptest.NewRequest(http.MethodPost, "/v1/webhooks/subscriptions", strings.NewReader(`{"url":"https://example.com/hook","events":["order.created"]}`))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing webhooks:write, got %d", rec.Code)
	}

	// 3. GET /v1/events/history without events:read -> 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/events/history", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing events:read, got %d", rec.Code)
	}

	// 4. POST /v1/events/publish without events:write -> 403 Forbidden
	req = httptest.NewRequest(http.MethodPost, "/v1/events/publish", strings.NewReader(`{"topic":"orders","type":"order.created","data":{"id":"1"}}`))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing events:write, got %d", rec.Code)
	}
}

// TestSecurityRegression_WebhookSecretMaskingAndRotation verifies secret redaction on GET
// and secure rotation via POST /v1/webhooks/subscriptions/{id}/rotate-secret.
func TestSecurityRegression_WebhookSecretMaskingAndRotation(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	mockReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockReceiver.Close()

	gw := NewAPIGateway("test-secret-32-bytes-security-masking")
	defer gw.Close()

	scopedToken, err := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "user_dev",
		TenantID: "tenant_masking_test",
		Role:     "developer",
		Scopes:   []string{"webhooks:read", "webhooks:write"},
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	authHeader := "Bearer " + scopedToken

	// 1. Create subscription -> returns unmasked secret once
	createBody := `{"url":"` + mockReceiver.URL + `","events":["tenant.provisioned"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/subscriptions", strings.NewReader(createBody))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on webhook create, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var createResp struct {
		Subscription WebhookSubscription `json:"subscription"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to parse create response: %v", err)
	}
	createdSecret := createResp.Subscription.Secret
	subID := createResp.Subscription.ID

	if !strings.HasPrefix(createdSecret, "whsec_") || strings.Contains(createdSecret, "******") {
		t.Fatalf("expected full unmasked secret on creation, got %s", createdSecret)
	}

	// 2. GET /v1/webhooks/subscriptions -> secret must be masked
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on list subscriptions, got %d", rec.Code)
	}
	var listResp struct {
		Subscriptions []WebhookSubscription `json:"subscriptions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}
	if len(listResp.Subscriptions) == 0 {
		t.Fatalf("expected at least 1 subscription")
	}
	if listResp.Subscriptions[0].Secret != "whsec_****************" {
		t.Fatalf("expected masked secret 'whsec_****************', got %s", listResp.Subscriptions[0].Secret)
	}

	// 3. GET /v1/webhooks/subscriptions/{id} -> secret must also be masked
	req = httptest.NewRequest(http.MethodGet, "/v1/webhooks/subscriptions/"+subID, nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get subscription by id, got %d", rec.Code)
	}
	var getResp struct {
		Subscription WebhookSubscription `json:"subscription"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to parse get response: %v", err)
	}
	if getResp.Subscription.Secret != "whsec_****************" {
		t.Fatalf("expected masked secret 'whsec_****************', got %s", getResp.Subscription.Secret)
	}

	// 4. Rotate secret via POST /v1/webhooks/subscriptions/{id}/rotate-secret
	req = httptest.NewRequest(http.MethodPost, "/v1/webhooks/subscriptions/"+subID+"/rotate-secret", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on rotate-secret, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var rotateResp struct {
		Status string `json:"status"`
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rotateResp); err != nil {
		t.Fatalf("failed to parse rotate response: %v", err)
	}
	if rotateResp.Status != "rotated" || rotateResp.ID != subID {
		t.Fatalf("unexpected rotate response metadata: %+v", rotateResp)
	}
	if !strings.HasPrefix(rotateResp.Secret, "whsec_") || rotateResp.Secret == createdSecret {
		t.Fatalf("expected new unmasked rotated secret distinct from original, got %s", rotateResp.Secret)
	}
}

// TestSecurityRegression_RedisFailClosedEndToEndRateLimiting verifies that TokenBucketLimiter.Allow()
// strictly fails closed when Redis is unavailable under AEITRON_CLUSTER_FAIL_CLOSED=true.
func TestSecurityRegression_RedisFailClosedEndToEndRateLimiting(t *testing.T) {
	cfg := RedisConfig{
		Addr:        "127.0.0.1:59998", // Unreachable port
		PoolSize:    5,
		DialTimeout: 20 * time.Millisecond,
		ReadTimeout: 20 * time.Millisecond,
		FailClosed:  true,
	}
	adapter := &RedisStateAdapter{
		cfg:      cfg,
		fallback: NewMemoryStateAdapter(),
		pool:     make(chan *redisConn, cfg.PoolSize),
	}

	limiter := NewTokenBucketLimiter()
	limiter.SetStateAdapter(adapter)

	// In fail-closed mode, when Redis drops, Allow() MUST NOT fall back to local memory and permit traffic
	allowed, remaining, _ := limiter.Allow("tenant:ratelimit_failclosed_test", 10.0, 20)
	if allowed {
		t.Fatalf("CRITICAL: TokenBucketLimiter allowed request in fail-closed mode when redis cluster was unreachable!")
	}
	if remaining != 0 {
		t.Fatalf("expected remaining=0 in fail-closed rate limit drop, got %d", remaining)
	}

	// Also verify Set and IdempotencyComplete fail closed
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	setErr := adapter.Set(ctx, "k", []byte("val"), time.Minute)
	if setErr == nil || !strings.Contains(setErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on Set in fail-closed mode, got %v", setErr)
	}

	idempCompErr := adapter.IdempotencyComplete(ctx, "k", &IdempotencyRecord{Key: "k"}, time.Minute)
	if idempCompErr == nil || !strings.Contains(idempCompErr.Error(), ErrClusterUnavailable.Error()) {
		t.Fatalf("expected ErrClusterUnavailable on IdempotencyComplete in fail-closed mode, got %v", idempCompErr)
	}
}

// TestSecurityRegression_UnknownTierRateLimiting verifies that unknown or missing tiers
// are safely resolved and bounded to the restricted "free" tier rather than bypassing rate limiting.
func TestSecurityRegression_UnknownTierRateLimiting(t *testing.T) {
	tierName, tierCfg := ResolveRateLimitTier("unknown_tier_hacker")
	if tierName != "free" {
		t.Fatalf("expected unknown tier to resolve to 'free', got %s", tierName)
	}
	if tierCfg.BurstCapacity != 10 || tierCfg.RequestsPerSecond != 1.0 {
		t.Fatalf("expected free tier limits (1 rps, 10 burst), got %+v", tierCfg)
	}

	tierName2, _ := ResolveRateLimitTier("")
	if tierName2 != "free" {
		t.Fatalf("expected empty tier to resolve to 'free', got %s", tierName2)
	}

	limiter := NewTokenBucketLimiter()
	// Test non-positive rate or capacity: must be bounded to safe defaults
	for i := 0; i < 15; i++ {
		allowed, _, _ := limiter.Allow("unknown_test_key", 0, 0)
		if i >= 10 && allowed {
			t.Fatalf("expected requests beyond burst 10 to be rate-limited, but request %d was allowed", i)
		}
	}
}

// TestSecurityRegression_CustomWebhookClientSSRFDefense verifies that passing a custom http.Client
// still enforces strict no-redirect policy and connection-time SSRF defenses.
func TestSecurityRegression_CustomWebhookClientSSRFDefense(t *testing.T) {
	customClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns: 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Integrator mistakenly tries to permit redirects
		},
	}

	cfg := WebhookConfig{
		HTTPClient:  customClient,
		HTTPTimeout: 2 * time.Second,
	}
	_ = NewWebhookEngine(cfg, nil)

	// Verify that custom client's CheckRedirect was hardened
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	err := customClient.CheckRedirect(req, []*http.Request{req})
	if err == nil || !strings.Contains(err.Error(), "does not follow HTTP redirects") {
		t.Fatalf("expected custom client CheckRedirect to be overridden with SSRF defense error, got %v", err)
	}
}

// TestSecurityRegression_ProductionMetricsEndpointAuthentication verifies that /metrics
// requires authenticated credentials in production mode.
func TestSecurityRegression_ProductionMetricsEndpointAuthentication(t *testing.T) {
	t.Setenv("AEITRON_ENV", "production")
	t.Setenv("AEITRON_METRICS_TOKEN", "super-secret-metrics-token-999")

	gw := NewAPIGateway("test-secret-32-bytes-metrics-guard")
	defer gw.Close()

	// 1. Unauthenticated request to /metrics in production -> 401 Unauthorized
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for /metrics in production, got %d", rec.Code)
	}

	// 2. Request with valid AEITRON_METRICS_TOKEN -> 200 OK
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer super-secret-metrics-token-999")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /metrics with metrics token, got %d", rec.Code)
	}

	// 3. Request with valid admin JWT token -> 200 OK
	adminToken, err := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "operator_alice",
		TenantID: "system",
		Role:     "operator",
		Scopes:   []string{"metrics:read"},
		Exp:      time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to generate admin token: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /metrics with operator token, got %d", rec.Code)
	}
}

// TestSecurityRegression_AuditSpoolerBackpressureAndDropMetrics verifies that queue backpressure
// tracks dropped counts and triggers onDrop callback.
func TestSecurityRegression_AuditSpoolerBackpressureAndDropMetrics(t *testing.T) {
	spooler := NewAuditSpooler(2)
	dropCount := 0
	spooler.SetOnDrop(func() {
		dropCount++
	})

	for i := 0; i < 20; i++ {
		spooler.Spool(AuditRecord{
			RequestID: "req_test",
			Method:    "POST",
			Path:      "/v1/orders",
		})
	}

	if spooler.DroppedCount() == 0 {
		t.Fatalf("expected droppedCount > 0 under extreme queue backpressure")
	}
	if dropCount == 0 {
		t.Fatalf("expected drop callback to be invoked under backpressure")
	}
}
