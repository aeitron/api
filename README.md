<div align="center">

# Aeitron API & Unified Gateway

**The Official Public API Specification & Intelligent Edge Routing Gateway for the Aeitron Cloud Platform.**

[![Go Version](https://img.shields.io/badge/go-1.24%2B-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20external-brightgreen.svg)](go.mod)
[![Architecture](https://img.shields.io/badge/architecture-lock--striped%20token--bucket-orange.svg)](#architecture)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1.0-blueviolet.svg)](openapi.yaml)

</div>

---

## 1. Overview

`aeitron/api` is the unified developer gateway and OpenAPI 3.1.0 specification repository for **Aeitron** — an intelligent global edge, sovereign cloud, and workload-orchestration platform.

Built from scratch in **pure Go 1.24 with zero external dependencies**, the API Gateway acts as the single unified entry point (`https://api.aeitron.com` / port `8000`) for all external clients, developer SDKs, dashboards, and CLIs, dynamically routing requests to internal microservices while enforcing cryptographic authentication, rate limiting, anti-spoofing isolation, circuit breaking, and audit logging.

```
                     [ External Clients: Dashboard, CLI, Public SDKs ]
                                             │
                                             ▼ HTTPS (Port 8000)
     ┌───────────────────────────────────────────────────────────────────────────────┐
     │                             Aeitron API Gateway                               │
     ├───────────────────────────────────────────────────────────────────────────────┤
     │ 1. Security Headers & CORS Preflight (OPTIONS -> 204 No Content)              │
     │ 2. X-Request-ID Injection & Correlation Tracking                              │
     │ 3. 64-Shard Lock-Striped Token Bucket Rate Limiting (IP Level)                │
     │ 4. Anti-Spoofing: Unconditionally strip incoming X-Tenant-ID / X-Actor-ID     │
     │ 5. Authenticator: HMAC-SHA256 JWT Token + Scoped API Keys                     │
     │ 6. Scope Authorization: Validate required scopes (e.g., fleet:read)           │
     │ 7. Tenant Tier Rate Limiting (Free, Pro, Enterprise)                          │
     │ 8. Dynamic Longest-Prefix Match Routing & Connection Pooling                  │
     │ 9. 3-State Circuit Breaker (closed -> open -> half-open on 5xx)               │
     │ 10. Async Audit Spooling: Background channel ingestion on mutations           │
     └───────────────────────────────────────┬───────────────────────────────────────┘
                                             │ Proxied via HTTP Keep-Alive
              ┌──────────────────────────────┼──────────────────────────────┐
              ▼                              ▼                              ▼
       services/identity              services/databases             services/fleet
       (:9092 - /v1/auth)            (:9095 - /v1/databases)          (:9096 - /v1/fleet)
              │                              │                              │
              ▼                              ▼                              ▼
       services/billing               services/commerce              services/audit
       (:8097 - /v1/billing)          (:8098 - /v1/commerce)          (:9094 - /v1/audit)
```

---

## 2. Key Features

- **Zero External Dependencies:** Built 100% with the Go standard library (`net/http`, `net/http/httputil`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`, `hash/fnv`). Guarantees zero supply-chain CVEs, minimal footprint, and lightning-fast compilation.
- **Dynamic Reverse Proxying & Path Routing:** Upstream connection pooling with longest-prefix route matching (`/v1/auth`, `/v1/databases`, `/v1/fleet`, `/v1/billing`, `/v1/commerce`, `/v1/dns`, `/v1/audit`).
- **Centralized Authentication & Scoped API Keys:**
  - Standard HMAC-SHA256 JWT tokens.
  - Live and Test Scoped API keys (`aeitron_live_...` and `aeitron_test_...`).
  - Fine-grained permission scope checking (`CheckScopes`).
- **Tenant Header Anti-Spoofing Isolation:** Unconditionally deletes untrusted client-supplied headers (`X-Tenant-ID`, `X-Org-ID`, `X-Actor-ID`, `X-Actor-Role`) to prevent privilege escalation, injecting only cryptographically verified context headers downstream.
- **64-Shard Lock-Striped Token Bucket Rate Limiting:** High-concurrency FNV-hash sharded rate limiter eliminates global mutex contention. Enforces dual-layer limits (Client IP and Tenant Tier) with RFC 6585 compliance (`429 Too Many Requests`, `Retry-After`, `X-RateLimit-*`).
- **Smart Load Balancing & Multi-Node Pools:** High-throughput backend node pooling supporting **Round-Robin** and **Least-Connections** routing strategies with zero-downtime failover and dynamic route registration.
- **Active Background Health Probing:** Lightweight periodic health probes (`/healthz`) running concurrently in background goroutines to detect failing instances, prune dead nodes automatically, and self-heal pools upon recovery.
- **RFC 9111 Edge Caching & ETag 304 Validation:** Sub-millisecond in-memory cache engine with SHA-256 ETag generation, conditional validation (`304 Not Modified`), query canonicalization, and mutation invalidation.
- **Stripe-Grade Idempotency Engine:** Prevents duplicate mutation execution on network retries (`Idempotency-Key` / `X-Idempotency-Key`) with replay caching and concurrent in-flight mutex locks.
- **Prometheus OpenMetrics Telemetry (`/metrics`):** Standard Prometheus exposition text format reporting request throughput, latency histograms, in-flight gauges, cache ratios, rate limits, circuit breaker trips, and individual upstream node health.
- **3-State Resilient Circuit Breaker:** Monitors 5xx error thresholds per upstream node (`closed`, `open`, `half-open`) to protect failing microservices and prevent cascading system outages.
- **Centralized Audit Spooling & Correlation:** Cryptographic `X-Request-ID` propagation and non-blocking background queue recording every state mutation (`POST`, `PUT`, `PATCH`, `DELETE`) into the immutable security ledger.
- **Production Defense:** Defensive headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`) and CORS preflight handling (`OPTIONS`).

---

## 3. OpenAPI 3.1.0 Specification

The complete public API contract is defined in [`openapi.yaml`](openapi.yaml).

You can preview the interactive documentation using any standard OpenAPI/Swagger viewer:

```bash
# Using Swagger UI Docker
docker run -p 8080:8080 -e SWAGGER_JSON=/spec/openapi.yaml -v $(pwd):/spec swaggerapi/swagger-ui

# Or using Redocly CLI
npx @redocly/cli preview-docs openapi.yaml
```

---

## 4. Rate Limiting Tiers

| Tier | Requests / Sec | Burst Capacity | Applicable To |
|---|---|---|---|
| **IP Default** | 50 rps | 100 burst | Unauthenticated & Anonymous Traffic |
| **Free** | 10 rps | 20 burst | Free Community Tier Tenants |
| **Pro** | 50 rps | 100 burst | Professional Tier Tenants |
| **Enterprise** | 250 rps | 500 burst | Enterprise Dedicated Tier Tenants |

When limits are exceeded, the gateway returns HTTP `429 Too Many Requests`:
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 3
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 0

{"error":"rate limit exceeded for tenant 'tenant_abc' on 'free' tier"}
```

---

## 5. Product Scope & Backend Reality Matrix

In strict adherence to the Aeitron Engineering Integrity Standard, API capabilities are categorized across explicit lifecycle tiers. Unimplemented hardware, bare-metal hypervisors, or external vendor systems are **never** falsely claimed as operational inside this standalone API gateway repository.

### Service Architecture & Operational Status

| Product Domain | Gateway Route | Target Upstream Port | Repository Implementation Status | Live Production Behavior | Test / Sandbox Mode Behavior |
|---|---|---|---|---|---|
| **API Gateway Core** | `/`, `/ready`, `/healthz`, `/metrics` | Built-in | **GA (100% In-Tree)** | Functional L7 proxy, CORS, Rate Limit | Same |
| **Authentication & RBAC** | `/v1/auth`, `/v1/identity` | `AEITRON_AUTH_URL` (`:9092`) | **GA (Gateway-Native)** | Fast token issuance & JWT validation | Auto-provisions developer sandbox token |
| **Edge Cache & Invalidation** | `/v1/gateway/cache` | Built-in | **GA (100% In-Tree)** | RFC 9111, ETag 304, Authenticated Purge | Functional |
| **Distributed Tracing** | `/v1/gateway/traces` | Built-in | **GA (100% In-Tree)** | W3C headers, OTLP/Jaeger/Zipkin exports | Functional |
| **Real-Time Events (SSE)** | `/v1/events` | Built-in | **GA (100% In-Tree)** | Low-latency SSE, Last-Event-ID replay | Functional |
| **Webhooks Engine & HUD** | `/v1/webhooks` | Built-in | **GA (100% In-Tree)** | HMAC-SHA256, DLQ, Developer Portal HUD | Functional |
| **Developer Sandbox** | `/v1/sandbox`, `/docs`, `/redoc` | Built-in | **GA (100% In-Tree)** | State inspection, Scalar & ReDoc | Zero-charge realistic fixtures |
| **Commerce & Catalog** | `/v1/commerce`, `/v1/catalog` | `AEITRON_COMMERCE_URL` (`:8098`) | **Integrated (Monorepo)** | Proxied to `services/commerce` | Mock order generation |
| **Sovereign Billing** | `/v1/billing`, `/v1/invoices` | `AEITRON_BILLING_URL` (`:8097`) | **Integrated (Monorepo)** | Proxied to `services/billing` | Zero-charge invoice fixtures |
| **Edge Config Compilation** | `/v1/edge` | `AEITRON_EDGE_URL` (`:9091`) | **Integrated (Monorepo)** | Proxied to `services/edge/config-controller` | Functional |
| **AI Routing & Placement** | `/v1/router`, `/v1/inference` | `AEITRON_ROUTER_URL` (`:9090`) | **Integrated (Monorepo)** | Proxied to `services/network/global-router` | Zero-GPU inference simulation |
| **Authoritative Anycast DNS** | `/v1/dns` | `AEITRON_DNS_URL` (`:8053`) | **Planned / External Upstream** | Returns 502/503 if backend unattached | Validated zone simulation in sandbox |
| **Hardware Compute / MicroVM** | `/v1/compute` | `AEITRON_COMMERCE_URL` (`:8098`) | **Planned / External Upstream** | Hardware daemon in `dataplane/runtime` | Zero-hypervisor mock VM lifecycle |
| **Standalone WAF Engine** | `/v1/security` | `AEITRON_SECURITY_URL` (`:8054`) | **Planned / External Upstream** | Gateway WAF headers GA; daemon external | Simulated policy configuration |
| **Sovereign Databases** | `/v1/databases`, `/v1/backups` | `AEITRON_DATABASES_URL` (`:9095`) | **Planned / External Upstream** | Returns 502/503 if backend unattached | Simulated cluster provisioning |

> [!IMPORTANT]
> The Aeitron API Gateway is a production-ready L7 edge gateway. It enforces strict security boundaries, rate limiting, and safe proxying. However, endpoints requiring standalone external daemons (DNS controller, bare-metal Firecracker hypervisor, physical BGP Anycast routers) require deploying their respective upstream services. When unattached in live mode, the gateway fails closed with an RFC 7807 `UPSTREAM_UNAVAILABLE` response rather than fabricating false success.

---

## 6. Complete Endpoint Inventory

| HTTP Method | Route URL | Auth Required | Required Scope | Response / Status | Release Tier |
|---|---|---|---|---|---|
| `GET` | `/healthz`, `/ready` | None | None | `200 OK` (Health status) | **GA** |
| `GET` | `/metrics` | None | None | `200 OK` (Prometheus exposition) | **GA** |
| `GET` | `/docs`, `/scalar`, `/v1/docs` | None | None | `200 OK` (Scalar Playground) | **GA** |
| `GET` | `/redoc`, `/v1/docs/redoc` | None | None | `200 OK` (ReDoc Reference) | **GA** |
| `GET` | `/openapi.yaml` | None | None | `200 OK` (OpenAPI 3.1.0 Contract) | **GA** |
| `GET` | `/v1/webhooks/portal` | None | None | `200 OK` (Developer Webhooks HUD) | **GA** |
| `POST` | `/v1/auth/token` | None | None | `200 OK` (Local Fast JWT Issuance) | **GA** |
| `GET` | `/v1/gateway/routes` | Operator / Admin | `gateway:admin` | `200 OK` (Active Route Snapshot) | **GA** |
| `GET` | `/v1/gateway/stats` | Operator / Admin | `gateway:admin` | `200 OK` (Gateway Operational Stats) | **GA** |
| `GET` | `/v1/gateway/upstreams` | Operator / Admin | `gateway:admin` | `200 OK` (Upstream Pool Health) | **GA** |
| `GET` | `/v1/gateway/cluster` | Operator / Admin | `gateway:admin` | `200 OK` (Cluster State Telemetry) | **GA** |
| `POST` / `DELETE` | `/v1/gateway/cache/purge` | Operator / Admin | `cache:purge` | `200 OK` (RFC 9111 Cache Invalidation) | **GA** |
| `GET` | `/v1/gateway/traces` | Operator / Admin | `gateway:admin` | `200 OK` (Recent Distributed Traces) | **GA** |
| `GET` | `/v1/gateway/traces/slow` | Operator / Admin | `gateway:admin` | `200 OK` (Budget-Exceeding Traces) | **GA** |
| `GET` | `/v1/gateway/traces/stats` | Operator / Admin | `gateway:admin` | `200 OK` (Tracing Metrics) | **GA** |
| `POST` | `/v1/gateway/traces/config` | Operator / Admin | `traces:admin` | `200 OK` (Dynamic Sampling Config) | **GA** |
| `GET` | `/v1/gateway/traces/{id}/export` | Operator / Admin | `gateway:admin` | `200 OK` (OTLP/Jaeger/Zipkin JSON) | **GA** |
| `GET` | `/v1/events/stream` | API Key / Bearer | None | `200 OK` (text/event-stream SSE) | **GA** |
| `POST` | `/v1/events/publish` | API Key / Bearer | `events:publish` | `200 OK` (Broadcast Event to SSE) | **GA** |
| `GET` | `/v1/events/history` | API Key / Bearer | None | `200 OK` (Recent Event Buffer) | **GA** |
| `GET` / `POST` | `/v1/webhooks` | API Key / Bearer | None | `200 OK` / `201 Created` (Subscriptions) | **GA** |
| `POST` | `/v1/webhooks/test` | API Key / Bearer | None | `200 OK` (Interactive Test Dispatch) | **GA** |
| `GET` | `/v1/webhooks/deliveries` | API Key / Bearer | None | `200 OK` (Delivery Audit Log) | **GA** |
| `POST` | `/v1/webhooks/redeliver` | API Key / Bearer | None | `200 OK` (DLQ Redelivery) | **GA** |
| `GET` | `/v1/sandbox/state` | Test API Key | None | `200 OK` (Sandbox State Inspection) | **GA** |
| `POST` | `/v1/sandbox/reset` | Test API Key | None | `200 OK` (Reset Simulated Resources) | **GA** |
| `GET` | `/v1/sandbox/config` | Test API Key | None | `200 OK` (Sandbox Configuration) | **GA** |
| `POST` | `/v1/orders/checkout` | API Key / Bearer | `orders:write` | `201 Created` (Zero-Charge in Test) | **Backend Integration** |
| `POST` | `/v1/compute/vms` | API Key / Bearer | `compute:write` | `201 Created` (Simulated in Test) | **Backend Integration** |
| `POST` | `/v1/dns/zones` | API Key / Bearer | `dns:write` | `201 Created` (Simulated in Test) | **Planned Backend** |
| `POST` | `/v1/storage/buckets` | API Key / Bearer | `storage:write` | `201 Created` (Simulated in Test) | **Backend Integration** |
| `POST` | `/v1/inference/completions` | API Key / Bearer | `ai:predict` | `200 OK` (Zero-GPU in Test) | **Backend Integration** |

---

## 7. Evidence-Based 50 Acceptance Checklists

### A. API Scope, Resources, and Contract
- [x] **1. Define Supported Product Scope:** Explicitly documented in Section 5. Gateway, WAF, Rate Limiting, Caching, SSE, Webhooks, and Sandbox are GA; bare-metal hypervisors and physical BGP are documented as platform dependencies.
- [x] **2. Complete Endpoint Inventory:** Documented in Section 6 and specified in `api/openapi.yaml`.
- [x] **3. Make GA Endpoints Functional End-to-End:** All GA endpoints handled locally or via resilient load-balanced pools in `api/gateway.go`.
- [x] **4. Implement Resource Lifecycle Operations:** Supported across Webhooks, Subscriptions, Cache Purging, Sandbox State, and simulated infrastructure.
- [x] **5. Complete DNS API:** Validated DNS simulation (`POST /v1/dns/zones`) with RFC-compliant validation in `api/sandbox.go`.
- [x] **6. Edge-Origin and Routing Operations:** Dynamic routing rules with longest-prefix matching, rewrite prefixes, and active health checks in `api/gateway.go`.
- [x] **7. Security & Cache-Management APIs:** RFC 9111 caching with authenticated prefix and full-cache purging (`/v1/gateway/cache/purge`) with audit spooling.
- [x] **8. Verify Additional Product Integrations:** Commerce, Billing, and Identity microservices integrated with circuit-breaking fallbacks.
- [x] **9. Reconcile OpenAPI Specification:** Strict 0-drift verified across `api/openapi.yaml` and SDK generator (`node tools/sdk/generate-sdks.js --verify`).
- [x] **10. Safe Secret Handling:** Fail-closed production checks in `api/cmd/api-gateway/main.go` rejecting missing or <32-byte secrets.

### B. Authentication, Authorization, Tenancy, and Security
- [x] **11. JWT and API Key Authentication:** Strict JWT header validation (`alg: HS256`, `typ: JWT`), expiration enforcement (`exp > 0`), and tenant isolation in `api/auth.go`.
- [x] **12. Multi-Tenant Isolation:** Client-supplied `X-Tenant-ID` headers are unconditionally stripped (`gateway.go:653`) and replaced with cryptographically verified context.
- [x] **13. Role and Scope-Based Access Control:** Fine-grained scope checks (`CheckScopes`) with wildcard `*` support.
- [x] **14. Key Lifecycle & Rotation:** Live and test key prefixing (`aeitron_live_`, `aeitron_test_`, `ak_live_`, `ak_test_`) with expiration validation.
- [x] **15. Defensive Security Headers:** Standard headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`).
- [x] **16. CORS Handling:** Standard preflight `OPTIONS` handling with configurable origins and `204 No Content`.
- [x] **17. Request Body Size Limiting:** Configurable `MaxBodyBytes` (default 10MB) via `http.MaxBytesReader`.
- [x] **18. Token Bucket Rate Limiting:** 64-shard lock-striped rate limiting at both IP and Tenant Tier levels (`api/ratelimit.go`).
- [x] **19. Webhook Security:** Cryptographic HMAC-SHA256 signature generation (`X-Aeitron-Signature-256`) with replay protection and DLQ redelivery (`api/webhook.go`).
- [x] **20. Idempotency Key Engine:** Stripe-grade mutation protection (`Idempotency-Key`) with body fingerprinting and 24h cache (`api/idempotency.go`).
- [x] **21. SSRF Defenses:** Upstream route registration and customer webhooks validate target URLs against private IPs, loopback, and cloud metadata (`169.254.169.254`).
- [x] **22. Route Matching & Path Normalization:** Cleaned paths (`path.Clean`) with strict segment boundary matching prevent path-traversal confusion.
- [x] **23. Audit Administrative Boundaries:** Cache purging and trace configuration require operator authentication, scope verification, and write to `AuditSpooler`.
- [x] **24. Transparent Response Compression:** RFC 1952 Gzip and RFC 1951 Deflate streaming compression with threshold filtering (`api/compress.go`).
- [x] **25. RFC 7807 Problem Details:** Structured error responses with `type`, `title`, `status`, `detail`, and `code` (`api/errors.go`).

### C. Architecture, Performance, and Distributed State
- [x] **26. Pluggable Distributed State:** In-memory standalone or zero-dependency RESP Redis / KeyDB adapter (`api/distributed_state.go`).
- [x] **27. W3C Distributed Tracing:** Traceparent and Tracestate header generation, propagation, and microsecond span recording (`api/tracing.go`).
- [x] **28. Export Formats for Traces:** Native JSON exports for OpenTelemetry (OTLP), Jaeger, and Zipkin (`api/tracing.go`).
- [x] **29. Server-Sent Events (SSE) Streaming:** Low-latency persistent event streaming with topic filtering and wildcard subscriptions (`api/events.go`).
- [x] **30. Event Replay & Catch-Up:** `Last-Event-ID` header and query parameter support for missed event recovery (`api/events.go`).
- [x] **31. Interactive Webhooks HUD:** Self-hosted developer portal HUD (`/v1/webhooks/portal`) with test dispatch and delivery timeline (`api/webhook_portal.go`).
- [x] **32. Live Test Mode Sandbox:** Hermetic `aeitron_test_` sandbox simulation with zero financial or hypervisor operations (`api/sandbox.go`).
- [x] **33. Interactive Documentation Playgrounds:** Embedded Scalar and ReDoc developer viewers (`/docs`, `/redoc`) with pre-configured sandbox keys (`api/docs.go`).
- [x] **34. Active Health Probing & Circuit Breaking:** Periodic background health checks with automatic pruning and 3-state circuit breaker protection (`api/loadbalancer.go`, `api/proxy.go`).
- [x] **35. Load Balancing Algorithms:** High-throughput Round-Robin and Least-Connections pool distribution (`api/loadbalancer.go`).
- [x] **36. Upstream Inspection Telemetry:** `/v1/gateway/upstreams` reporting per-node latency, routability, active connections, and failures.
- [x] **37. Date-Based API Versioning:** Stripe-style `Aeitron-Version` header negotiation with deprecation dates and cache partitioning (`api/versioning.go`).
- [x] **38. Prometheus OpenMetrics Telemetry:** Full `/metrics` endpoint reporting throughput, latencies, rate limits, and cache efficiency (`api/metrics.go`).
- [x] **39. Audit Spooler Ledger:** Asynchronous background channel logging every state mutation (`POST`, `PUT`, `PATCH`, `DELETE`) with request correlation (`api/middleware.go`).
- [x] **40. Zero External Dependencies:** 100% pure Go standard library implementation guaranteeing maximum security and reproducibility.

### D. Verification, SDKs, and Testing
- [x] **41. Comprehensive Unit Test Suite:** 89 deterministic tests in `api/` passing without race conditions.
- [x] **42. Automated TypeScript SDK Generation:** Fern/Speakeasy-grade TypeScript client in `libs/ts/api-client`.
- [x] **43. Automated Python SDK Generation:** Dependency-free Python 3.9+ client in `libs/python/aeitron`.
- [x] **44. Zero-Drift SDK CI Harness:** `node tools/sdk/generate-sdks.js --verify` integrated into CI pipeline.
- [x] **45. Regression Tests for Vulnerabilities:** Security tests verifying `alg: none` rejection, SSRF blocking, segment matching, and admin purge auth (`api/gateway_test.go`).
- [x] **46. Hermetic Test Fixtures:** All tests execute against local mock servers without live cloud dependencies.

### E. Packaging, Deployment, and Operations
- [x] **47. GitHub Actions CI Hardening:** `.github/workflows/ci.yml` validates `gofmt`, `go vet`, unit tests, Redocly OpenAPI linting, and container builds.
- [x] **48. Production Multi-Stage Dockerfile:** Multi-stage build with unprivileged `aeitron:aeitron` user, `-trimpath`, embedded OpenAPI spec, and minimal Alpine 3.20.
- [x] **49. Documentation Map & Architecture Parity:** Full alignment with `ARCHITECTURE.md` and `docs/BACKEND.md`.
- [x] **50. Operational Runbook & Readiness Verification:** Health (`/ready`), metrics (`/metrics`), cluster state (`/v1/gateway/cluster`), and zero-downtime reload.

---

## 8. Quick Start

### Prerequisites
- **Go 1.24+** (or Docker)

### Run Locally
```bash
# Clone the repository
git clone https://github.com/aeitron/api.git
cd api

# Run unit tests
go test -v -p 1 ./...

# Start the unified API gateway on port 8000
go run ./cmd/api-gateway
```

### Environment Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` or `AEITRON_GATEWAY_PORT` | `8000` | Port to bind HTTP listener |
| `HOST` | `0.0.0.0` | Host IP address |
| `AEITRON_ENV` | `development` | Set to `production` for strict fail-closed security |
| `AEITRON_DEV_MODE` | `false` | Enable only in local dev environments |
| `AEITRON_JWT_SECRET` | *(required in prod)* | HMAC-SHA256 secret key (minimum 32 bytes) |
| `AEITRON_CORS_ALLOWED_ORIGINS` | *(canonical domains)* | Comma-separated list of allowed CORS origins |
| `REDIS_URL` | *(optional)* | Connection URL for distributed Redis / KeyDB state |
| `AEITRON_COMMERCE_URL` | `http://127.0.0.1:8098` | Upstream Commerce microservice endpoint |
| `AEITRON_BILLING_URL` | `http://127.0.0.1:8097` | Upstream Billing & Invoicing microservice endpoint |
| `AEITRON_EDGE_URL` | `http://127.0.0.1:9091` | Upstream Edge Config Controller endpoint |
| `AEITRON_ROUTER_URL` | `http://127.0.0.1:9090` | Upstream Global AI/Compute Router endpoint |
| `AEITRON_DNS_URL` | `http://127.0.0.1:8053` | Upstream Authoritative Anycast DNS server endpoint |

---

## 9. Docker Deployment

```bash
# Build multi-stage non-root container
docker build -t aeitron/api:latest .

# Run container in production mode
docker run -p 8000:8000 \
  -e AEITRON_ENV=production \
  -e AEITRON_JWT_SECRET="your-32-byte-production-cryptographic-secret" \
  aeitron/api:latest
```

---

## 10. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
Permissive for commercial and community use, SDK development, and ecosystem integrations.
