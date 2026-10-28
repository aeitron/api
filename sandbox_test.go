package apigateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSandbox_LiveTestModeHeaderAndAuth(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	// 1. Unregistered aeitron_test_ key should dynamically authenticate in sandbox mode
	req := httptest.NewRequest(http.MethodGet, "/v1/sandbox/config", nil)
	req.Header.Set("Authorization", "Bearer aeitron_test_sandbox_developer_key_99")
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if lm := resp.Header.Get("Aeitron-Livemode"); lm != "false" {
		t.Fatalf("expected Aeitron-Livemode false, got %s", lm)
	}
	if sb := resp.Header.Get("X-Aeitron-Sandbox"); sb != "active" {
		t.Fatalf("expected X-Aeitron-Sandbox active, got %s", sb)
	}
}

func TestSandbox_LiveProductionKeyHeader(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	// Register explicit live production key
	gw.Authenticator().RegisterAPIKey("aeitron_live_prod_corp_key", &TenantContext{
		TenantID: "tenant_corp_prod",
		ActorID:  "act_prod_corp",
		Role:     "admin",
		Scopes:   []string{"*"},
		Tier:     "enterprise",
		Livemode: true,
	})

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	req.Header.Set("Authorization", "Bearer aeitron_live_prod_corp_key")
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if lm := resp.Header.Get("Aeitron-Livemode"); lm != "true" {
		t.Fatalf("expected Aeitron-Livemode true for live key, got %s", lm)
	}
}

func TestSandbox_ZeroChargeOrderSimulation(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	orderPayload := map[string]interface{}{
		"amount_cents":   4900,
		"currency":       "USD",
		"customer_email": "developer@startup.example",
	}
	body, _ := json.Marshal(orderPayload)

	req := httptest.NewRequest(http.MethodPost, "/v1/orders/checkout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aeitron_test_acme_corp_key")
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}
	if lm := resp.Header.Get("Aeitron-Livemode"); lm != "false" {
		t.Fatalf("expected Aeitron-Livemode false, got %s", lm)
	}

	var res struct {
		Status   string       `json:"status"`
		Livemode bool         `json:"livemode"`
		Order    SandboxOrder `json:"order"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.Status != "succeeded" {
		t.Fatalf("expected status succeeded, got %s", res.Status)
	}
	if res.Livemode != false {
		t.Fatalf("expected livemode false")
	}
	if !strings.HasPrefix(res.Order.ID, "ord_test_") {
		t.Fatalf("expected order ID prefix ord_test_, got %s", res.Order.ID)
	}
	if !strings.HasPrefix(res.Order.TransactionID, "ch_test_") {
		t.Fatalf("expected transaction ID prefix ch_test_, got %s", res.Order.TransactionID)
	}
	if res.Order.AmountCents != 4900 {
		t.Fatalf("expected amount 4900, got %d", res.Order.AmountCents)
	}
	if res.Order.Simulation["real_charge_prevented"] != true {
		t.Fatalf("expected real_charge_prevented true in simulation metadata")
	}

	// Verify order is queryable in sandbox state
	getReq := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	getReq.Header.Set("Authorization", "Bearer aeitron_test_acme_corp_key")
	getW := httptest.NewRecorder()
	gw.ServeHTTP(getW, getReq)

	var listRes struct {
		Livemode bool            `json:"livemode"`
		Orders   []*SandboxOrder `json:"orders"`
		Count    int             `json:"count"`
	}
	_ = json.NewDecoder(getW.Result().Body).Decode(&listRes)
	if listRes.Count != 1 || listRes.Orders[0].ID != res.Order.ID {
		t.Fatalf("expected 1 sandboxed order matching %s, got count %d", res.Order.ID, listRes.Count)
	}
}

func TestSandbox_ZeroHypervisorVMProvisioning(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	vmPayload := map[string]interface{}{
		"name":      "sandbox-dev-vm",
		"region":    "dhaka-edge",
		"vcpu":      4,
		"memory_mb": 8192,
	}
	body, _ := json.Marshal(vmPayload)

	req := httptest.NewRequest(http.MethodPost, "/v1/compute/vms", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer aeitron_test_microvm_key")
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}

	var res struct {
		Status   string    `json:"status"`
		Livemode bool      `json:"livemode"`
		Instance SandboxVM `json:"instance"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res.Status != "running" {
		t.Fatalf("expected running status, got %s", res.Status)
	}
	if !strings.HasPrefix(res.Instance.ID, "vm_test_") {
		t.Fatalf("expected vm_test_ ID prefix, got %s", res.Instance.ID)
	}
	if !strings.HasPrefix(res.Instance.IPAddress, "198.51.100.") {
		t.Fatalf("expected RFC 5737 Test-Net IP address, got %s", res.Instance.IPAddress)
	}
	if res.Instance.Simulation["real_hypervisor_prevented"] != true {
		t.Fatalf("expected real_hypervisor_prevented true")
	}

	// Verify VM is in sandbox instances query
	getReq := httptest.NewRequest(http.MethodGet, "/v1/compute/vms", nil)
	getReq.Header.Set("Authorization", "Bearer aeitron_test_microvm_key")
	getW := httptest.NewRecorder()
	gw.ServeHTTP(getW, getReq)

	var listRes struct {
		Instances []*SandboxVM `json:"instances"`
		Count     int          `json:"count"`
	}
	_ = json.NewDecoder(getW.Result().Body).Decode(&listRes)
	if listRes.Count != 1 || listRes.Instances[0].ID != res.Instance.ID {
		t.Fatalf("expected 1 sandboxed VM matching %s, got count %d", res.Instance.ID, listRes.Count)
	}
}

func TestSandbox_DNSZoneAndStorageBucketSimulation(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	// 1. Create simulated DNS Zone
	dnsBody, _ := json.Marshal(map[string]string{"name": "myapp-sandbox.dev"})
	dnsReq := httptest.NewRequest(http.MethodPost, "/v1/dns/zones", bytes.NewReader(dnsBody))
	dnsReq.Header.Set("Content-Type", "application/json")
	dnsReq.Header.Set("Authorization", "Bearer aeitron_test_all_infra")
	dnsW := httptest.NewRecorder()
	gw.ServeHTTP(dnsW, dnsReq)

	if dnsW.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for DNS zone, got %d", dnsW.Code)
	}

	// 2. Create simulated Storage Bucket
	bktBody, _ := json.Marshal(map[string]string{"name": "sandbox-user-uploads", "region": "dhaka-edge"})
	bktReq := httptest.NewRequest(http.MethodPost, "/v1/storage/buckets", bytes.NewReader(bktBody))
	bktReq.Header.Set("Content-Type", "application/json")
	bktReq.Header.Set("Authorization", "Bearer aeitron_test_all_infra")
	bktW := httptest.NewRecorder()
	gw.ServeHTTP(bktW, bktReq)

	if bktW.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for storage bucket, got %d", bktW.Code)
	}

	// 3. Inspect tenant sandbox state
	stateReq := httptest.NewRequest(http.MethodGet, "/v1/sandbox/state", nil)
	stateReq.Header.Set("Authorization", "Bearer aeitron_test_all_infra")
	stateW := httptest.NewRecorder()
	gw.ServeHTTP(stateW, stateReq)

	if stateW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for sandbox state, got %d", stateW.Code)
	}

	var stateResp struct {
		Livemode bool `json:"livemode"`
		State    struct {
			ZonesCount   int `json:"zones_count"`
			BucketsCount int `json:"buckets_count"`
		} `json:"state"`
	}
	_ = json.NewDecoder(stateW.Result().Body).Decode(&stateResp)
	if stateResp.State.ZonesCount != 1 || stateResp.State.BucketsCount != 1 {
		t.Fatalf("expected 1 zone and 1 bucket in sandbox state, got %+v", stateResp.State)
	}
}

func TestSandbox_ResetState(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	// Provision a mock VM
	vmBody, _ := json.Marshal(map[string]string{"name": "temp-vm"})
	vReq := httptest.NewRequest(http.MethodPost, "/v1/compute/vms", bytes.NewReader(vmBody))
	vReq.Header.Set("Content-Type", "application/json")
	vReq.Header.Set("Authorization", "Bearer aeitron_test_reset_tenant")
	vW := httptest.NewRecorder()
	gw.ServeHTTP(vW, vReq)

	// Reset sandbox
	rstReq := httptest.NewRequest(http.MethodPost, "/v1/sandbox/reset", nil)
	rstReq.Header.Set("Authorization", "Bearer aeitron_test_reset_tenant")
	rstW := httptest.NewRecorder()
	gw.ServeHTTP(rstW, rstReq)

	if rstW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on sandbox reset, got %d", rstW.Code)
	}

	// Verify state is clean
	sReq := httptest.NewRequest(http.MethodGet, "/v1/sandbox/state", nil)
	sReq.Header.Set("Authorization", "Bearer aeitron_test_reset_tenant")
	sW := httptest.NewRecorder()
	gw.ServeHTTP(sW, sReq)

	var stateResp struct {
		State struct {
			VMsCount int `json:"vms_count"`
		} `json:"state"`
	}
	_ = json.NewDecoder(sW.Result().Body).Decode(&stateResp)
	if stateResp.State.VMsCount != 0 {
		t.Fatalf("expected 0 VMs after reset, got %d", stateResp.State.VMsCount)
	}
}

func TestSandbox_ReDocAndScalarPlayground(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	// 1. ReDoc endpoint
	reqReDoc := httptest.NewRequest(http.MethodGet, "/redoc", nil)
	wReDoc := httptest.NewRecorder()
	gw.ServeHTTP(wReDoc, reqReDoc)

	if wReDoc.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /redoc, got %d", wReDoc.Code)
	}
	if ct := wReDoc.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html for /redoc, got %s", ct)
	}
	reDocBody, _ := io.ReadAll(wReDoc.Result().Body)
	if !strings.Contains(string(reDocBody), "redoc.standalone.js") || !strings.Contains(string(reDocBody), "ReDoc Specification") {
		t.Fatalf("expected ReDoc HTML with standalone bundle")
	}

	// 2. /v1/docs/redoc alias
	reqAlias := httptest.NewRequest(http.MethodGet, "/v1/docs/redoc", nil)
	wAlias := httptest.NewRecorder()
	gw.ServeHTTP(wAlias, reqAlias)
	if wAlias.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /v1/docs/redoc, got %d", wAlias.Code)
	}

	// 3. Scalar playground with pre-configured demo test key
	reqScalar := httptest.NewRequest(http.MethodGet, "/docs", nil)
	wScalar := httptest.NewRecorder()
	gw.ServeHTTP(wScalar, reqScalar)

	if wScalar.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /docs, got %d", wScalar.Code)
	}
	scalarBody, _ := io.ReadAll(wScalar.Result().Body)
	sBody := string(scalarBody)
	if !strings.Contains(sBody, "@scalar/api-reference") {
		t.Fatalf("expected @scalar/api-reference in /docs")
	}
	if !strings.Contains(sBody, "aeitron_test_sandbox_developer_demo_key") {
		t.Fatalf("expected pre-configured sandbox demo key in Scalar configuration")
	}
	if !strings.Contains(sBody, "Live Sandbox Active") {
		t.Fatalf("expected Live Sandbox Active indicator badge")
	}
}

func TestSandbox_IdempotencyReplaySupport(t *testing.T) {
	gw := NewAPIGateway("test-secret-key-for-sandbox-suite-32b")
	defer gw.Close()

	orderPayload := map[string]interface{}{
		"amount_cents":   9900,
		"currency":       "USD",
		"customer_email": "idemp@example.com",
	}
	body, _ := json.Marshal(orderPayload)

	idempKey := "ik_test_sandbox_checkout_01"

	// 1. Initial request
	req1 := httptest.NewRequest(http.MethodPost, "/v1/orders/checkout", bytes.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer aeitron_test_idemp_key")
	req1.Header.Set("Idempotency-Key", idempKey)
	w1 := httptest.NewRecorder()
	gw.ServeHTTP(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on first request, got %d", w1.Code)
	}

	var res1 struct {
		Order SandboxOrder `json:"order"`
	}
	_ = json.NewDecoder(w1.Result().Body).Decode(&res1)

	// 2. Replay with identical idempotency key
	req2 := httptest.NewRequest(http.MethodPost, "/v1/orders/checkout", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer aeitron_test_idemp_key")
	req2.Header.Set("Idempotency-Key", idempKey)
	w2 := httptest.NewRecorder()
	gw.ServeHTTP(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on replay, got %d", w2.Code)
	}
	if replayed := w2.Header().Get("Idempotent-Replayed"); replayed != "true" {
		t.Fatalf("expected Idempotent-Replayed true, got %s", replayed)
	}

	var res2 struct {
		Order SandboxOrder `json:"order"`
	}
	_ = json.NewDecoder(w2.Result().Body).Decode(&res2)

	if res1.Order.ID != res2.Order.ID {
		t.Fatalf("expected identical order ID on replayed request (%s vs %s)", res1.Order.ID, res2.Order.ID)
	}
	if res1.Order.TransactionID != res2.Order.TransactionID {
		t.Fatalf("expected identical transaction ID on replayed request (%s vs %s)", res1.Order.TransactionID, res2.Order.TransactionID)
	}
}
