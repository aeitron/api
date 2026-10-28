package apigateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SandboxOrder represents a simulated, non-charging ecommerce/billing transaction.
type SandboxOrder struct {
	ID            string                 `json:"id"`
	TransactionID string                 `json:"transaction_id"`
	AmountCents   int64                  `json:"amount_cents"`
	Currency      string                 `json:"currency"`
	Status        string                 `json:"status"` // "succeeded", "pending"
	Livemode      bool                   `json:"livemode"`
	CustomerEmail string                 `json:"customer_email"`
	ReceiptURL    string                 `json:"receipt_url"`
	CardDetails   map[string]interface{} `json:"card_details"`
	Simulation    map[string]interface{} `json:"sandbox_simulation"`
	CreatedAt     time.Time              `json:"created_at"`
}

// SandboxVM represents a simulated microVM instance with zero hypervisor hardware allocation.
type SandboxVM struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Status     string                 `json:"status"` // "running", "provisioning", "stopped"
	Livemode   bool                   `json:"livemode"`
	IPAddress  string                 `json:"ip_address"` // RFC 5737 Test-Net-2
	VCPU       int                    `json:"vcpu"`
	MemoryMB   int                    `json:"memory_mb"`
	Region     string                 `json:"region"`
	Simulation map[string]interface{} `json:"sandbox_simulation"`
	CreatedAt  time.Time              `json:"created_at"`
}

// SandboxDNSZone represents a simulated DNS zone without registrar or BGP network modification.
type SandboxDNSZone struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Livemode    bool      `json:"livemode"`
	NameServers []string  `json:"name_servers"`
	CreatedAt   time.Time `json:"created_at"`
}

// SandboxBucket represents a simulated cloud storage bucket.
type SandboxBucket struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	Status    string    `json:"status"`
	Livemode  bool      `json:"livemode"`
	CreatedAt time.Time `json:"created_at"`
}

// SandboxTenantState stores isolated mock infrastructure fixtures per tenant.
type SandboxTenantState struct {
	mu      sync.RWMutex
	Orders  map[string]*SandboxOrder
	VMs     map[string]*SandboxVM
	Zones   map[string]*SandboxDNSZone
	Buckets map[string]*SandboxBucket
}

func newSandboxTenantState() *SandboxTenantState {
	return &SandboxTenantState{
		Orders:  make(map[string]*SandboxOrder),
		VMs:     make(map[string]*SandboxVM),
		Zones:   make(map[string]*SandboxDNSZone),
		Buckets: make(map[string]*SandboxBucket),
	}
}

// SandboxEngine manages Stripe-grade test mode, zero-charge simulations, and fixture state.
type SandboxEngine struct {
	mu      sync.RWMutex
	tenants map[string]*SandboxTenantState
}

// NewSandboxEngine initializes a self-hosted sandbox engine.
func NewSandboxEngine() *SandboxEngine {
	return &SandboxEngine{
		tenants: make(map[string]*SandboxTenantState),
	}
}

func (s *SandboxEngine) getTenantState(tenantID string) *SandboxTenantState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tenantID == "" {
		tenantID = "default_sandbox"
	}
	ts, exists := s.tenants[tenantID]
	if !exists {
		ts = newSandboxTenantState()
		s.tenants[tenantID] = ts
	}
	return ts
}

// IsSandbox detects whether a request runs in live test mode (Sandbox).
func (s *SandboxEngine) IsSandbox(r *http.Request, tenantCtx *TenantContext) bool {
	if tenantCtx != nil && !tenantCtx.Livemode {
		return true
	}

	// Check headers
	if strings.EqualFold(r.Header.Get("Aeitron-Livemode"), "false") ||
		strings.EqualFold(r.Header.Get("X-Aeitron-Simulate"), "true") {
		return true
	}

	// Check API Key header
	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if strings.HasPrefix(key, "aeitron_test_") || strings.HasPrefix(key, "ak_test_") {
		return true
	}

	// Check Authorization header
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.Contains(auth, "aeitron_test_") || strings.Contains(auth, "ak_test_") {
		return true
	}

	return false
}

// HandleSandboxSimulation intercepts mutative or queries destined for live infrastructure
// and returns simulated fixture data without real charging or hypervisor allocation.
func (s *SandboxEngine) HandleSandboxSimulation(w http.ResponseWriter, r *http.Request, tenantCtx *TenantContext, reqID string) bool {
	if !s.IsSandbox(r, tenantCtx) {
		return false
	}

	tenantID := "default_sandbox"
	if tenantCtx != nil && tenantCtx.TenantID != "" {
		tenantID = tenantCtx.TenantID
	}
	tState := s.getTenantState(tenantID)

	w.Header().Set("Aeitron-Livemode", "false")
	w.Header().Set("X-Aeitron-Sandbox", "active")

	// 1. Sandbox Inspection & Reset Management Endpoints
	if (r.URL.Path == "/v1/sandbox/state" || r.URL.Path == "/sandbox/state") && r.Method == http.MethodGet {
		tState.mu.RLock()
		defer tState.mu.RUnlock()

		ordersList := make([]*SandboxOrder, 0, len(tState.Orders))
		for _, o := range tState.Orders {
			ordersList = append(ordersList, o)
		}
		vmsList := make([]*SandboxVM, 0, len(tState.VMs))
		for _, v := range tState.VMs {
			vmsList = append(vmsList, v)
		}
		zonesList := make([]*SandboxDNSZone, 0, len(tState.Zones))
		for _, z := range tState.Zones {
			zonesList = append(zonesList, z)
		}
		bucketsList := make([]*SandboxBucket, 0, len(tState.Buckets))
		for _, b := range tState.Buckets {
			bucketsList = append(bucketsList, b)
		}

		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"livemode":  false,
			"tenant_id": tenantID,
			"state": map[string]interface{}{
				"orders":        ordersList,
				"orders_count":  len(ordersList),
				"vms":           vmsList,
				"vms_count":     len(vmsList),
				"zones":         zonesList,
				"zones_count":   len(zonesList),
				"buckets":       bucketsList,
				"buckets_count": len(bucketsList),
			},
		})
		return true
	}

	if (r.URL.Path == "/v1/sandbox/reset" || r.URL.Path == "/sandbox/reset") && r.Method == http.MethodPost {
		tState.mu.Lock()
		tState.Orders = make(map[string]*SandboxOrder)
		tState.VMs = make(map[string]*SandboxVM)
		tState.Zones = make(map[string]*SandboxDNSZone)
		tState.Buckets = make(map[string]*SandboxBucket)
		tState.mu.Unlock()

		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"status":    "sandbox_reset_success",
			"livemode":  false,
			"tenant_id": tenantID,
			"message":   "All sandboxed mock infrastructure fixtures cleared for tenant",
		})
		return true
	}

	if (r.URL.Path == "/v1/sandbox/config" || r.URL.Path == "/sandbox/config") && r.Method == http.MethodGet {
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"livemode":           false,
			"test_card_numbers":  []string{"4242424242424242", "4000056655665556"},
			"test_network_range": "198.51.100.0/24 (RFC 5737 Test-Net)",
			"emulated_boot_ms":   12,
			"supported_test_keys": []string{
				"aeitron_test_demo",
				"aeitron_test_sandbox_developer_demo_key",
				"ak_test_developer_key",
			},
		})
		return true
	}

	// 2. Orders & Checkout Simulation (Prevents Real Credit Card / Bank Charges)
	if (r.URL.Path == "/v1/orders/checkout" || r.URL.Path == "/v1/orders" || strings.HasPrefix(r.URL.Path, "/v1/billing/charge")) && r.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		var orderReq struct {
			AmountCents   int64  `json:"amount_cents"`
			Currency      string `json:"currency"`
			CustomerEmail string `json:"customer_email"`
		}
		_ = json.Unmarshal(bodyBytes, &orderReq)
		if orderReq.AmountCents <= 0 {
			orderReq.AmountCents = 2500 // $25.00 default fixture
		}
		if orderReq.Currency == "" {
			orderReq.Currency = "USD"
		}
		if orderReq.CustomerEmail == "" {
			orderReq.CustomerEmail = "developer-test@aeitron.example"
		}

		suffix := randomHex(6)
		order := &SandboxOrder{
			ID:            "ord_test_" + suffix,
			TransactionID: "ch_test_" + suffix,
			AmountCents:   orderReq.AmountCents,
			Currency:      strings.ToUpper(orderReq.Currency),
			Status:        "succeeded",
			Livemode:      false,
			CustomerEmail: orderReq.CustomerEmail,
			ReceiptURL:    "https://aeitron.com/receipts/test_rcpt_" + suffix,
			CardDetails: map[string]interface{}{
				"brand":       "Visa (Test Fixture)",
				"last4":       "4242",
				"funding":     "credit",
				"exp_month":   12,
				"exp_year":    2030,
				"country":     "US",
				"cvc_check":   "pass",
				"fingerprint": "fp_test_" + suffix,
			},
			Simulation: map[string]interface{}{
				"real_charge_prevented": true,
				"charge_mode":           "sandbox_mock",
				"payment_gateway":       "aeitron_test_processor",
			},
			CreatedAt: time.Now().UTC(),
		}

		tState.mu.Lock()
		tState.Orders[order.ID] = order
		tState.mu.Unlock()

		writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
			"status":   "succeeded",
			"livemode": false,
			"order":    order,
		})
		return true
	}

	// Query sandbox orders list
	if r.URL.Path == "/v1/orders" && r.Method == http.MethodGet {
		tState.mu.RLock()
		defer tState.mu.RUnlock()
		ordersList := make([]*SandboxOrder, 0, len(tState.Orders))
		for _, o := range tState.Orders {
			ordersList = append(ordersList, o)
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"livemode": false,
			"orders":   ordersList,
			"count":    len(ordersList),
		})
		return true
	}

	// 3. Compute / MicroVM Provisioning Simulation (Prevents Real Hypervisor Resource Spawning)
	if (r.URL.Path == "/v1/compute/vms" || r.URL.Path == "/v1/compute/instances") && r.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		var vmReq struct {
			Name     string `json:"name"`
			Region   string `json:"region"`
			VCPU     int    `json:"vcpu"`
			MemoryMB int    `json:"memory_mb"`
		}
		_ = json.Unmarshal(bodyBytes, &vmReq)
		if vmReq.Name == "" {
			vmReq.Name = "sandbox-microvm-" + randomHex(4)
		}
		if vmReq.Region == "" {
			vmReq.Region = "dhaka-edge"
		}
		if vmReq.VCPU <= 0 {
			vmReq.VCPU = 2
		}
		if vmReq.MemoryMB <= 0 {
			vmReq.MemoryMB = 4096
		}

		suffix := randomHex(6)
		vm := &SandboxVM{
			ID:        "vm_test_" + suffix,
			Name:      vmReq.Name,
			Status:    "running",
			Livemode:  false,
			IPAddress: fmt.Sprintf("198.51.100.%d", 10+(len(tState.VMs)%240)),
			VCPU:      vmReq.VCPU,
			MemoryMB:  vmReq.MemoryMB,
			Region:    vmReq.Region,
			Simulation: map[string]interface{}{
				"real_hypervisor_prevented": true,
				"hypervisor_driver":         "emulated_sandbox_microvm",
				"emulated_boot_latency_ms":  12,
			},
			CreatedAt: time.Now().UTC(),
		}

		tState.mu.Lock()
		tState.VMs[vm.ID] = vm
		tState.mu.Unlock()

		writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
			"status":   "running",
			"livemode": false,
			"instance": vm,
		})
		return true
	}

	// Query sandbox VMs list
	if (r.URL.Path == "/v1/compute/vms" || r.URL.Path == "/v1/compute/instances") && r.Method == http.MethodGet {
		tState.mu.RLock()
		defer tState.mu.RUnlock()
		vmsList := make([]*SandboxVM, 0, len(tState.VMs))
		for _, v := range tState.VMs {
			vmsList = append(vmsList, v)
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"livemode":  false,
			"instances": vmsList,
			"count":     len(vmsList),
		})
		return true
	}

	// 4. DNS Zone Creation Simulation (Prevents Real Registrar & BGP Anycast Churn)
	if (r.URL.Path == "/v1/dns/zones" || r.URL.Path == "/v1/dns/domains") && r.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		var dnsReq struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(bodyBytes, &dnsReq)
		if dnsReq.Name == "" {
			dnsReq.Name = "sandbox-domain-" + randomHex(4) + ".io"
		}

		suffix := randomHex(6)
		zone := &SandboxDNSZone{
			ID:          "zone_test_" + suffix,
			Name:        dnsReq.Name,
			Status:      "active",
			Livemode:    false,
			NameServers: []string{"ns1.sandbox.aeitron.net", "ns2.sandbox.aeitron.net"},
			CreatedAt:   time.Now().UTC(),
		}

		tState.mu.Lock()
		tState.Zones[zone.ID] = zone
		tState.mu.Unlock()

		writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
			"status":   "active",
			"livemode": false,
			"zone":     zone,
		})
		return true
	}

	// Query sandbox DNS zones
	if (r.URL.Path == "/v1/dns/zones" || r.URL.Path == "/v1/dns/domains") && r.Method == http.MethodGet {
		tState.mu.RLock()
		defer tState.mu.RUnlock()
		zonesList := make([]*SandboxDNSZone, 0, len(tState.Zones))
		for _, z := range tState.Zones {
			zonesList = append(zonesList, z)
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"livemode": false,
			"zones":    zonesList,
			"count":    len(zonesList),
		})
		return true
	}

	// 5. Cloud Storage Buckets Simulation
	if r.URL.Path == "/v1/storage/buckets" && r.Method == http.MethodPost {
		bodyBytes, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
		var bktReq struct {
			Name   string `json:"name"`
			Region string `json:"region"`
		}
		_ = json.Unmarshal(bodyBytes, &bktReq)
		if bktReq.Name == "" {
			bktReq.Name = "sandbox-bucket-" + randomHex(4)
		}
		if bktReq.Region == "" {
			bktReq.Region = "dhaka-edge"
		}

		suffix := randomHex(6)
		bkt := &SandboxBucket{
			ID:        "bkt_test_" + suffix,
			Name:      bktReq.Name,
			Region:    bktReq.Region,
			Status:    "ready",
			Livemode:  false,
			CreatedAt: time.Now().UTC(),
		}

		tState.mu.Lock()
		tState.Buckets[bkt.ID] = bkt
		tState.mu.Unlock()

		writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
			"status":   "ready",
			"livemode": false,
			"bucket":   bkt,
		})
		return true
	}

	// Query sandbox Storage Buckets
	if r.URL.Path == "/v1/storage/buckets" && r.Method == http.MethodGet {
		tState.mu.RLock()
		defer tState.mu.RUnlock()
		bktList := make([]*SandboxBucket, 0, len(tState.Buckets))
		for _, b := range tState.Buckets {
			bktList = append(bktList, b)
		}
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"livemode": false,
			"buckets":  bktList,
			"count":    len(bktList),
		})
		return true
	}

	// 6. Fast AI Inference Simulation
	if r.URL.Path == "/v1/inference/completions" && r.Method == http.MethodPost {
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"id":       "cmpl_test_" + randomHex(8),
			"livemode": false,
			"model":    "aeitron-omni-flash-test",
			"choices": []map[string]interface{}{
				{
					"index":         0,
					"text":          "Simulated AI response from Aeitron Edge Test Sandbox. Zero GPU cost incurred.",
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     12,
				"completion_tokens": 16,
				"total_tokens":      28,
			},
			"placement": map[string]interface{}{
				"region":              "dhaka-edge",
				"routed_latency_ms":   1,
				"carbon_efficiency":   "100% green (simulated)",
				"cache_hit_predicted": true,
			},
		})
		return true
	}

	return false
}
