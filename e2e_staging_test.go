package apigateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestE2EStaging_FullLifeCycleAndContextPropagation verifies end-to-end proxying,
// context propagation (X-Tenant-ID, X-Actor-ID, X-Request-ID), and gateway telemetry
// over real TCP network sockets.
func TestE2EStaging_FullLifeCycleAndContextPropagation(t *testing.T) {
	var capturedTenantID, capturedActorID, capturedRole, capturedReqID string
	var upstreamHits int32

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		capturedTenantID = r.Header.Get("X-Tenant-ID")
		capturedActorID = r.Header.Get("X-Actor-ID")
		capturedRole = r.Header.Get("X-Actor-Role")
		capturedReqID = r.Header.Get("X-Request-ID")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","data":{"instance_id":"inst-stage-101","state":"running"}}`))
	}))
	defer mockUpstream.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	err := gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/compute",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: false,
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to register route: %v", err)
	}

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	// Generate authenticated token
	now := time.Now().UTC()
	token, err := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_staging_42",
		Sub:      "user_staging_99",
		Role:     "member",
		Scopes:   []string{"compute:read", "compute:write"},
		Exp:      now.Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/compute/instances", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-ID", "req_staging_trace_001")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed over TCP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
	}

	if atomic.LoadInt32(&upstreamHits) != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", atomic.LoadInt32(&upstreamHits))
	}
	if capturedTenantID != "tenant_staging_42" {
		t.Errorf("expected X-Tenant-ID 'tenant_staging_42', got '%s'", capturedTenantID)
	}
	if capturedActorID != "user_staging_99" {
		t.Errorf("expected X-Actor-ID 'user_staging_99', got '%s'", capturedActorID)
	}
	if capturedRole != "member" {
		t.Errorf("expected X-Actor-Role 'member', got '%s'", capturedRole)
	}
	if capturedReqID != "req_staging_trace_001" {
		t.Errorf("expected X-Request-ID propagation, got '%s'", capturedReqID)
	}

	// Verify gateway response headers
	if resp.Header.Get("X-Request-ID") == "" {
		t.Errorf("missing X-Request-ID in gateway response")
	}
	if resp.Header.Get("traceparent") == "" {
		t.Errorf("missing traceparent in gateway response")
	}
}

// TestE2EStaging_AuthenticationFailures verifies RFC 7807 problem details when
// authentication fails (missing, malformed, forged signature, expired, or bad API key).
func TestE2EStaging_AuthenticationFailures(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer mockUpstream.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: false,
	})

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	cases := []struct {
		name       string
		authHeader string
		apiKey     string
	}{
		{"MissingCredentials", "", ""},
		{"MalformedToken", "Bearer this-is-not-a-valid-jwt", ""},
		{"ForgedSignature", "", ""},
		{"ExpiredToken", "", ""},
		{"InvalidAPIKey", "", "ak_live_nonexistent_key_000"},
	}

	// Prepare forged token
	attackerAuth := NewAuthenticator("attacker-secret-key-differing-signature")
	forgedToken, _ := attackerAuth.GenerateSignedToken(JWTClaims{
		TenantID: "tenant_victim",
		Sub:      "user_victim",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})
	cases[2].authHeader = "Bearer " + forgedToken

	// Prepare expired token
	expiredToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_valid",
		Sub:      "user_valid",
		Exp:      time.Now().Add(-2 * time.Hour).Unix(),
	})
	cases[3].authHeader = "Bearer " + expiredToken

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/orders", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.apiKey != "" {
				req.Header.Set("X-API-Key", tc.apiKey)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			var prob ProblemDetails
			if err := json.Unmarshal(body, &prob); err != nil {
				t.Fatalf("response body is not valid RFC 7807 problem json: %v (%s)", err, string(body))
			}
			if prob.Status != http.StatusUnauthorized {
				t.Errorf("expected problem status 401, got %d", prob.Status)
			}
		})
	}
}

// TestE2EStaging_AuthorizationAndScopeEnforcement verifies RBAC and scope evaluation.
func TestE2EStaging_AuthorizationAndScopeEnforcement(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"audit_logs":[]}`))
	}))
	defer mockUpstream.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/audit",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: false,
		RequiredScopes: []string{"audit:read"},
	})

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Caller without required scope -> 403 Forbidden
	insufficientToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_scope_test",
		Sub:      "user_limited",
		Role:     "member",
		Scopes:   []string{"billing:read"}, // missing audit:read
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/audit/logs", nil)
	req.Header.Set("Authorization", "Bearer "+insufficientToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for insufficient scope, got %d", resp.StatusCode)
	}

	// 2. Caller with required scope -> 200 OK
	sufficientToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_scope_test",
		Sub:      "user_admin",
		Role:     "admin",
		Scopes:   []string{"audit:read", "audit:export"},
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	req2, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/audit/logs", nil)
	req2.Header.Set("Authorization", "Bearer "+sufficientToken)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for authorized scope, got %d", resp2.StatusCode)
	}
}

// TestE2EStaging_RateLimitingOverTCP verifies burst threshold enforcement over TCP sockets.
func TestE2EStaging_RateLimitingOverTCP(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"rate_limit_test"}`))
	}))
	defer mockUpstream.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/catalog",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: false,
	})

	// Configure a tight bucket on "free" tier for staging test (capacity: 3, refill rate: 0.1/sec)
	origFree := DefaultRateLimits["free"]
	defer func() { DefaultRateLimits["free"] = origFree }()
	DefaultRateLimits["free"] = RateLimitTierConfig{
		RequestsPerSecond: 0.1,
		BurstCapacity:     3,
	}

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	token, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_ratelimit_staging",
		Sub:      "user_rl",
		Role:     "member",
		Tier:     "free",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	client := &http.Client{Timeout: 5 * time.Second}
	var got429 bool
	var retryAfterHeader string

	// Fire 8 requests in rapid succession over TCP
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/catalog/items", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			retryAfterHeader = resp.Header.Get("Retry-After")
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}

	if !got429 {
		t.Fatalf("expected 429 Too Many Requests after burst exhaustion, but all requests succeeded")
	}
	if retryAfterHeader == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}
}

// TestE2EStaging_RFC9111CacheHitMissAndETagValidation exercises edge caching and 304 conditional validation.
func TestE2EStaging_RFC9111CacheHitMissAndETagValidation(t *testing.T) {
	var upstreamCalls int32
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", `"e2e-staging-v1-hash"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"payload":"cached_edge_data"}`))
	}))
	defer mockUpstream.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/status",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: true,
		CacheTTL:       60 * time.Second,
	})

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Initial request -> Cache MISS
	req1, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/status/probe", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp1.StatusCode)
	}
	if resp1.Header.Get("X-Cache") != "MISS" {
		t.Errorf("expected X-Cache MISS on first call, got %s", resp1.Header.Get("X-Cache"))
	}
	etag := resp1.Header.Get("ETag")
	if etag == "" {
		t.Fatalf("expected ETag header on cached response")
	}

	// 2. Second request -> Cache HIT (upstream not called)
	req2, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/status/probe", nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on cached call, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("X-Cache") != "HIT" {
		t.Errorf("expected X-Cache HIT on second call, got %s", resp2.Header.Get("X-Cache"))
	}
	if atomic.LoadInt32(&upstreamCalls) != 1 {
		t.Fatalf("expected upstream to be called only once, but called %d times", atomic.LoadInt32(&upstreamCalls))
	}

	// 3. Conditional validation with If-None-Match -> 304 Not Modified
	req3, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/status/probe", nil)
	req3.Header.Set("If-None-Match", etag)
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("request 3 failed: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified for matching ETag, got %d", resp3.StatusCode)
	}
}

// TestE2EStaging_IdempotentMutationReplayAndConflict tests RFC idempotency replay and payload conflict over TCP.
func TestE2EStaging_IdempotentMutationReplayAndConflict(t *testing.T) {
	var mutationHits int32
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&mutationHits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"order_id":"ord_stage_9988","status":"created"}`))
	}))
	defer mockUpstream.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/orders",
		UpstreamURL:    mockUpstream.URL,
		AllowAnonymous: false,
	})

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	token, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_order_test",
		Sub:      "user_order_actor",
		Role:     "member",
		Scopes:   []string{"orders:write"},
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	client := &http.Client{Timeout: 5 * time.Second}
	idemKey := "ik_staging_unique_001"
	bodyPayload := `{"sku":"metal-pop-iad1","quantity":2}`

	// 1. Initial Mutation Request
	req1, _ := http.NewRequest(http.MethodPost, gwServer.URL+"/v1/orders/provision", bytes.NewBufferString(bodyPayload))
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.Header.Set("Idempotency-Key", idemKey)
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("initial mutation failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("expected 201 Created, got %d: %s", resp1.StatusCode, string(body))
	}
	if atomic.LoadInt32(&mutationHits) != 1 {
		t.Fatalf("expected 1 mutation call upstream, got %d", atomic.LoadInt32(&mutationHits))
	}

	// 2. Replay with identical payload -> 201 Created with Idempotent-Replayed: true (upstream NOT called)
	req2, _ := http.NewRequest(http.MethodPost, gwServer.URL+"/v1/orders/provision", bytes.NewBufferString(bodyPayload))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Idempotency-Key", idemKey)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("replayed mutation failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created on replay, got %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Idempotent-Replayed") != "true" {
		t.Errorf("expected Idempotent-Replayed: true header, got '%s'", resp2.Header.Get("Idempotent-Replayed"))
	}
	if atomic.LoadInt32(&mutationHits) != 1 {
		t.Fatalf("upstream called on replayed idempotent request! expected 1, got %d", atomic.LoadInt32(&mutationHits))
	}

	// 3. Replay with DIFFERENT payload -> 409 Conflict
	differingPayload := `{"sku":"metal-pop-iad1","quantity":9999}`
	req3, _ := http.NewRequest(http.MethodPost, gwServer.URL+"/v1/orders/provision", bytes.NewBufferString(differingPayload))
	req3.Header.Set("Authorization", "Bearer "+token)
	req3.Header.Set("Idempotency-Key", idemKey)
	req3.Header.Set("Content-Type", "application/json")

	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("conflicting mutation failed: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on payload mismatch for same key, got %d", resp3.StatusCode)
	}
}

// TestE2EStaging_UpstreamFailureAndAutomaticRecovery proves that when an upstream backend
// abruptly crashes, the gateway fails cleanly with 502/503 UPSTREAM_UNAVAILABLE, and when
// the backend recovers on the same socket port, the gateway automatically recovers to 200 OK.
func TestE2EStaging_UpstreamFailureAndAutomaticRecovery(t *testing.T) {
	// Allocate a dynamic local loopback port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on loopback: %v", err)
	}
	addr := listener.Addr().String()

	// Handler serving 200 OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"service":"resilient_upstream","healthy":true}`))
	})

	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(listener)
	}()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	_ = gw.RegisterRoute(RouteRule{
		PathPrefix:     "/v1/resilient",
		UpstreamURL:    "http://" + addr,
		AllowAnonymous: true,
		Timeout:        2 * time.Second,
	})

	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Upstream is healthy -> 200 OK
	resp1, err := client.Get(gwServer.URL + "/v1/resilient/ping")
	if err != nil {
		t.Fatalf("healthy call failed: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from healthy upstream, got %d", resp1.StatusCode)
	}

	// 2. Abruptly kill upstream server (close listener)
	_ = srv.Shutdown(context.Background())
	_ = listener.Close()
	time.Sleep(50 * time.Millisecond)

	// 3. Gateway request should now fail cleanly with 502/503 UPSTREAM_UNAVAILABLE
	resp2, err := client.Get(gwServer.URL + "/v1/resilient/ping")
	if err != nil {
		t.Fatalf("expected HTTP error response, got transport error: %v", err)
	}
	resp2Body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusBadGateway && resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 502 or 503 while upstream is dead, got %d (%s)", resp2.StatusCode, string(resp2Body))
	}

	// 4. Restart upstream backend on the exact same TCP port
	restartedListener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("failed to re-bind upstream on %s: %v", addr, err)
	}
	defer restartedListener.Close()

	restartedSrv := &http.Server{Handler: handler}
	go func() {
		_ = restartedSrv.Serve(restartedListener)
	}()
	time.Sleep(50 * time.Millisecond)

	// 5. Gateway request automatically succeeds without restart!
	resp3, err := client.Get(gwServer.URL + "/v1/resilient/ping")
	if err != nil {
		t.Fatalf("recovered call failed: %v", err)
	}
	defer resp3.Body.Close()

	if resp3.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp3.Body)
		t.Fatalf("expected automatic recovery to 200 OK, got %d: %s", resp3.StatusCode, string(body))
	}
}

// TestE2EStaging_RealtimeServerSentEventsStream tests SSE streaming over real TCP sockets.
func TestE2EStaging_RealtimeServerSentEventsStream(t *testing.T) {
	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	token, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_sse_staging",
		Sub:      "user_sse_listener",
		Role:     "member",
		Scopes:   []string{"events:read"},
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})

	req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/events/stream?topics=compute.instances,dns.health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")

	// Use transport that does not block buffering
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to connect to SSE stream over TCP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK for SSE stream, got %d: %s", resp.StatusCode, string(body))
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("expected Content-Type text/event-stream, got %s", contentType)
	}

	// Publish an event in background
	go func() {
		time.Sleep(50 * time.Millisecond)
		gw.EventEngine().Publish(InfrastructureEvent{
			ID:        "evt_sse_stg_001",
			Topic:     "compute.instances",
			Type:      "instance.provisioned",
			TenantID:  "tenant_sse_staging",
			Timestamp: time.Now().UTC(),
			Data:      json.RawMessage(`{"instance_id":"srv-iad1-01","ip":"198.51.100.22"}`),
		})
	}()

	reader := bufio.NewReader(resp.Body)
	receivedEvent := false
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event:") && strings.Contains(line, "compute.instances") {
			receivedEvent = true
			break
		}
	}

	if !receivedEvent {
		t.Fatalf("did not receive expected SSE event 'compute.instances' within deadline")
	}
}

// TestE2EStaging_WebhookDeliveryVerification tests end-to-end webhook delivery,
// payload construction, and HMAC-SHA256 signature verification.
func TestE2EStaging_WebhookDeliveryVerification(t *testing.T) {
	origDev := os.Getenv("AEITRON_DEV_MODE")
	defer os.Setenv("AEITRON_DEV_MODE", origDev)
	os.Setenv("AEITRON_DEV_MODE", "true")

	var receivedSig, receivedTimestamp string
	var receivedPayload []byte
	var receivedEventID string
	var webhookDelivered sync.WaitGroup
	webhookDelivered.Add(1)

	destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get(HeaderWebhookSignature)
		receivedTimestamp = r.Header.Get(HeaderWebhookTimestamp)
		receivedEventID = r.Header.Get(HeaderWebhookDeliveryID)
		receivedPayload, _ = io.ReadAll(r.Body)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
		webhookDelivered.Done()
	}))
	defer destServer.Close()

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	webhookSecret := "whsec_staging_test_secret_32bytes"

	// Trigger a test webhook delivery to the destination server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := gw.WebhookEngine().TestWebhook(
		ctx,
		destServer.URL,
		webhookSecret,
		"instance.provisioned",
		json.RawMessage(`{"instance_id":"srv-fra1-09","region":"fra-1"}`),
	)
	if err != nil {
		t.Fatalf("TestWebhook failed: %v", err)
	}

	if !result.Success || result.StatusCode != http.StatusOK {
		t.Fatalf("expected successful webhook delivery, got status %d, err: %s", result.StatusCode, result.Error)
	}

	webhookDelivered.Wait()

	// Verify HMAC-SHA256 signature against the shared secret
	signer := NewWebhookSigner(5 * time.Minute)
	err = signer.Verify(webhookSecret, receivedPayload, receivedSig, receivedTimestamp)
	if err != nil {
		t.Fatalf("received webhook signature failed verification: %v (sig: %s, ts: %s)", err, receivedSig, receivedTimestamp)
	}

	if receivedEventID == "" {
		t.Errorf("expected delivery ID header to be sent with webhook")
	}
}

// TestE2EStaging_AdminEndpointFailClosedInProduction verifies that admin diagnostic endpoints
// (/v1/gateway/routes) strictly require admin authorization in production mode.
func TestE2EStaging_AdminEndpointFailClosedInProduction(t *testing.T) {
	origEnv := os.Getenv("AEITRON_ENV")
	defer os.Setenv("AEITRON_ENV", origEnv)
	os.Setenv("AEITRON_ENV", "production")

	secret := "test-staging-secret-key-32bytes-aeitron"
	gw := NewAPIGateway(secret)
	gwServer := httptest.NewServer(gw)
	defer gwServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Unauthenticated request -> 401 Unauthorized
	resp1, err := client.Get(gwServer.URL + "/v1/gateway/routes")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated admin route in prod, got %d", resp1.StatusCode)
	}

	// 2. Member request without admin role -> 403 Forbidden
	memberToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_admin_test",
		Sub:      "user_member",
		Role:     "member",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})
	req2, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/gateway/routes", nil)
	req2.Header.Set("Authorization", "Bearer "+memberToken)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for member role on admin route, got %d", resp2.StatusCode)
	}

	// 3. Admin request with admin role -> 200 OK
	adminToken, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		TenantID: "tenant_admin_test",
		Sub:      "user_admin",
		Role:     "admin",
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})
	req3, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/v1/gateway/routes", nil)
	req3.Header.Set("Authorization", "Bearer "+adminToken)
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for admin role on admin route, got %d", resp3.StatusCode)
	}
}
