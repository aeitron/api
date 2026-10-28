package apigateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func eventTestToken(gw *APIGateway, tenantID string) string {
	tok, _ := gw.Authenticator().GenerateSignedToken(JWTClaims{
		Sub:      "act_" + tenantID,
		TenantID: tenantID,
		Role:     "developer",
		Scopes:   []string{"events:read", "events:write", "webhooks:read", "webhooks:write"},
		Exp:      time.Now().Add(1 * time.Hour).Unix(),
	})
	return tok
}

func TestEvents_SSEConnectionAndHeaders(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	ts := httptest.NewServer(gw)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events/stream?topics=compute.instances", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-alpha"))

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("failed to connect to SSE stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("expected Content-Type text/event-stream, got %s", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache, no-transform" {
		t.Fatalf("expected Cache-Control no-cache, no-transform, got %s", cc)
	}
	if conn := resp.Header.Get("Connection"); conn != "keep-alive" {
		t.Fatalf("expected Connection keep-alive, got %s", conn)
	}
	if buf := resp.Header.Get("X-Accel-Buffering"); buf != "no" {
		t.Fatalf("expected X-Accel-Buffering no, got %s", buf)
	}
}

func TestEvents_RealTimeBroadcast(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	// Create test server to handle HTTP streaming properly
	ts := httptest.NewServer(gw)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events/stream?topics=compute.instances", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-test"))

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("failed to connect to SSE stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)

	// Publish event in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		pubPayload := map[string]interface{}{
			"topic":     "compute.instances",
			"type":      "instance.provisioned",
			"tenant_id": "tenant-test",
			"data": map[string]interface{}{
				"instance_id": "vm-99824",
				"status":      "running",
				"region":      "us-east-1",
			},
		}
		body, _ := json.Marshal(pubPayload)
		pReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/events/publish", bytes.NewReader(body))
		pReq.Header.Set("Content-Type", "application/json")
		pReq.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-test"))
		pResp, pErr := ts.Client().Do(pReq)
		if pErr == nil {
			pResp.Body.Close()
		}
	}()

	// Read lines until event received
	var receivedEvent, receivedData, receivedID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: ") {
			receivedID = strings.TrimPrefix(line, "id: ")
		} else if strings.HasPrefix(line, "event: ") {
			receivedEvent = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			receivedData = strings.TrimPrefix(line, "data: ")
			if receivedEvent == "compute.instances" {
				break
			}
		}
	}

	if receivedEvent != "compute.instances" {
		t.Fatalf("expected event compute.instances, got %q", receivedEvent)
	}
	if receivedID == "" {
		t.Fatalf("expected non-empty event ID")
	}
	if !strings.Contains(receivedData, "vm-99824") {
		t.Fatalf("expected data to contain vm-99824, got %q", receivedData)
	}
}

func TestEvents_TopicFilteringAndWildcards(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	engine := gw.EventEngine()
	if engine == nil {
		t.Fatalf("expected non-nil eventEngine")
	}

	// 1. Replay and topic matching check
	engine.Publish(InfrastructureEvent{
		ID:        "evt_compute_1",
		Topic:     "compute.instances",
		Type:      "vm.started",
		TenantID:  "tenant-1",
		Timestamp: time.Now().UTC(),
	})
	engine.Publish(InfrastructureEvent{
		ID:        "evt_dns_1",
		Topic:     "dns.health",
		Type:      "probe.failover",
		TenantID:  "tenant-1",
		Timestamp: time.Now().UTC(),
	})
	engine.Publish(InfrastructureEvent{
		ID:        "evt_storage_1",
		Topic:     "storage.buckets",
		Type:      "bucket.created",
		TenantID:  "tenant-1",
		Timestamp: time.Now().UTC(),
	})

	// Subscriber with compute.* should match compute.instances only
	computeHistory := engine.GetRecentHistory("tenant-1", "compute.*", 10)
	if len(computeHistory) != 1 {
		t.Fatalf("expected 1 compute event, got %d", len(computeHistory))
	}
	if computeHistory[0].ID != "evt_compute_1" {
		t.Fatalf("expected evt_compute_1, got %s", computeHistory[0].ID)
	}

	// Subscriber with dns.health should match dns.health only
	dnsHistory := engine.GetRecentHistory("tenant-1", "dns.health", 10)
	if len(dnsHistory) != 1 {
		t.Fatalf("expected 1 dns event, got %d", len(dnsHistory))
	}
	if dnsHistory[0].ID != "evt_dns_1" {
		t.Fatalf("expected evt_dns_1, got %s", dnsHistory[0].ID)
	}

	// Subscriber with * should get all 3 events
	allHistory := engine.GetRecentHistory("tenant-1", "*", 10)
	if len(allHistory) != 3 {
		t.Fatalf("expected 3 total events, got %d", len(allHistory))
	}
}

func TestEvents_LastEventIDCatchUpReplay(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	ts := httptest.NewServer(gw)
	defer ts.Close()

	// Pre-publish 3 events
	gw.EventEngine().Publish(InfrastructureEvent{
		ID:        "evt_historical_01",
		Topic:     "compute.instances",
		Type:      "vm.booting",
		TenantID:  "tenant-catchup",
		Data:      json.RawMessage(`{"seq":1}`),
		Timestamp: time.Now().UTC(),
	})
	gw.EventEngine().Publish(InfrastructureEvent{
		ID:        "evt_historical_02",
		Topic:     "compute.instances",
		Type:      "vm.running",
		TenantID:  "tenant-catchup",
		Data:      json.RawMessage(`{"seq":2}`),
		Timestamp: time.Now().UTC(),
	})
	gw.EventEngine().Publish(InfrastructureEvent{
		ID:        "evt_historical_03",
		Topic:     "compute.instances",
		Type:      "vm.ready",
		TenantID:  "tenant-catchup",
		Data:      json.RawMessage(`{"seq":3}`),
		Timestamp: time.Now().UTC(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Client requests stream starting after evt_historical_01
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events/stream?topics=compute.instances", nil)
	req.Header.Set("Last-Event-ID", "evt_historical_01")
	req.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-catchup"))

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	var replayedIDs []string

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		line, rErr := reader.ReadString('\n')
		if rErr != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: ") {
			id := strings.TrimPrefix(line, "id: ")
			replayedIDs = append(replayedIDs, id)
			if len(replayedIDs) == 2 {
				break
			}
		}
	}

	if len(replayedIDs) != 2 {
		t.Fatalf("expected 2 replayed events, got %d: %v", len(replayedIDs), replayedIDs)
	}
	if replayedIDs[0] != "evt_historical_02" || replayedIDs[1] != "evt_historical_03" {
		t.Fatalf("expected [evt_historical_02, evt_historical_03], got %v", replayedIDs)
	}
}

func TestEvents_KeepalivePingHeartbeat(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	// Override heartbeat interval to 30ms for rapid test verification
	gw.EventEngine().SetHeartbeatInterval(30 * time.Millisecond)

	ts := httptest.NewServer(gw)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-ping"))

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	var gotPing bool

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		line, rErr := reader.ReadString('\n')
		if rErr != nil {
			break
		}
		if strings.HasPrefix(line, ": ping") {
			gotPing = true
			break
		}
	}

	if !gotPing {
		t.Fatalf("expected keepalive ping heartbeat from SSE stream")
	}
}

func TestEvents_RecentHistoryEndpoint(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	gw.EventEngine().Publish(InfrastructureEvent{
		ID:        "evt_hist_1",
		Topic:     "dns.health",
		Type:      "check.fail",
		TenantID:  "tenant-history",
		Timestamp: time.Now().UTC(),
	})
	gw.EventEngine().Publish(InfrastructureEvent{
		ID:        "evt_hist_2",
		Topic:     "dns.health",
		Type:      "check.recover",
		TenantID:  "tenant-history",
		Timestamp: time.Now().UTC(),
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/events/history?topic=dns.health&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-history"))
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var data struct {
		Events []InfrastructureEvent `json:"events"`
		Count  int                   `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if data.Count != 2 {
		t.Fatalf("expected count 2, got %d", data.Count)
	}
	if data.Events[0].ID != "evt_hist_1" || data.Events[1].ID != "evt_hist_2" {
		t.Fatalf("unexpected event order: %+v", data.Events)
	}
}

func TestWebhook_TestSimulationEndpoint(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	// Mock receiver HTTP server
	var receivedSig string
	var receivedBody string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Aeitron-Signature")
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received": true}`))
	}))
	defer mockServer.Close()

	testReq := map[string]interface{}{
		"url":        mockServer.URL + "/test-endpoint",
		"secret":     "whsec_supersecretkey123",
		"event_type": "instance.created",
		"data": map[string]interface{}{
			"id":   "inst_443",
			"tier": "enterprise",
		},
	}
	body, _ := json.Marshal(testReq)

	req := httptest.NewRequest(http.MethodPost, "/v1/webhooks/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-test"))
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var simResult TestDeliveryResult
	if err := json.NewDecoder(resp.Body).Decode(&simResult); err != nil {
		t.Fatalf("failed to decode simulation result: %v", err)
	}

	if !simResult.Success {
		t.Fatalf("expected success true, got false, error: %s", simResult.Error)
	}
	if simResult.StatusCode != http.StatusOK {
		t.Fatalf("expected StatusCode 200, got %d", simResult.StatusCode)
	}
	if receivedSig == "" {
		t.Fatalf("expected mock server to receive X-Aeitron-Signature header")
	}
	if !strings.Contains(receivedBody, "inst_443") {
		t.Fatalf("expected mock server body to contain inst_443, got %s", receivedBody)
	}
	if simResult.HeadersSent["X-Aeitron-Signature"] != receivedSig {
		t.Fatalf("signature header mismatch between simulation output and receiver")
	}
}

func TestWebhook_PortalEndpoint(t *testing.T) {
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/webhooks/portal", nil)
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html Content-Type, got %s", ct)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	requiredStrings := []string{
		"Interactive Webhook Simulator",
		"Live Deliveries Stream",
		"Dead-Letter Queue (DLQ)",
		"Exponential Backoff Lifecycle",
		"X-Aeitron-Signature",
		"Node.js",
		"Python",
		"Rust",
	}

	for _, s := range requiredStrings {
		if !strings.Contains(bodyStr, s) {
			t.Fatalf("expected portal HTML to contain %q", s)
		}
	}
}

func TestEvents_WebhookDispatchToSSEConvergence(t *testing.T) {
	t.Setenv("AEITRON_DEV_MODE", "true")
	gw := NewAPIGateway("test-jwt-secret-key-for-auth-32b")
	defer gw.Close()

	ts := httptest.NewServer(gw)
	defer ts.Close()

	// 1. Create a dummy webhook subscription so Dispatch generates a delivery
	dummyTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer dummyTarget.Close()

	subReq := map[string]interface{}{
		"url":    dummyTarget.URL + "/webhook",
		"secret": "whsec_convergence_key",
		"events": []string{"compute.vm.boot"},
	}
	sBody, _ := json.Marshal(subReq)
	cReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/webhooks/subscriptions", bytes.NewReader(sBody))
	cReq.Header.Set("Content-Type", "application/json")
	cReq.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-convergence"))
	cResp, err := ts.Client().Do(cReq)
	if err != nil {
		t.Fatalf("failed to create subscription: %v", err)
	}
	cResp.Body.Close()

	// 2. Connect client to SSE stream subscribing to webhooks.*
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sseReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events/stream?topics=webhooks.*", nil)
	sseReq.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-convergence"))

	sseResp, err := ts.Client().Do(sseReq)
	if err != nil {
		t.Fatalf("failed to open SSE stream: %v", err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)

	// 3. Dispatch webhook event in background
	go func() {
		time.Sleep(100 * time.Millisecond)
		dispReq := map[string]interface{}{
			"id":         "evt_disp_991",
			"type":       "compute.vm.boot",
			"tenant_id":  "tenant-convergence",
			"created_at": time.Now().UTC(),
			"data": map[string]interface{}{
				"vm_name": "aeitron-edge-node-01",
			},
		}
		dBody, _ := json.Marshal(dispReq)
		pReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/webhooks/dispatch", bytes.NewReader(dBody))
		pReq.Header.Set("Content-Type", "application/json")
		pReq.Header.Set("Authorization", "Bearer "+eventTestToken(gw, "tenant-convergence"))
		pResp, pErr := ts.Client().Do(pReq)
		if pErr == nil {
			pResp.Body.Close()
		}
	}()

	// 4. Assert SSE stream receives webhooks.deliveries topic event
	var receivedTopic string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, rErr := reader.ReadString('\n')
		if rErr != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event: ") {
			receivedTopic = strings.TrimPrefix(line, "event: ")
			if receivedTopic == "webhooks.deliveries" {
				break
			}
		}
	}

	if receivedTopic != "webhooks.deliveries" {
		t.Fatalf("expected to receive event topic webhooks.deliveries, got %q", receivedTopic)
	}
}
