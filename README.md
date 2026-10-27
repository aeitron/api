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
- **3-State Resilient Circuit Breaker:** Monitors 5xx error thresholds per upstream (`closed`, `open`, `half-open`) to protect failing microservices and prevent cascading system outages.
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

## 5. Quick Start

### Prerequisites
- **Go 1.24+** (or Docker)

### Run Locally
```bash
# Clone the repository
git clone https://github.com/aeitron/api.git
cd api

# Run unit tests
go test -v ./...

# Start the unified API gateway on port 8000
go run ./cmd/api-gateway
```

### Environment Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` or `AEITRON_GATEWAY_PORT` | `8000` | Port to bind HTTP listener |
| `HOST` | `0.0.0.0` | Host IP address |
| `AEITRON_JWT_SECRET` | `aeitron-dev-...` | HMAC-SHA256 secret key for signing & validating tokens |

### Example Request

```bash
# Authenticate using Scoped API Key
curl -i https://api.aeitron.com/v1/databases/instances \
  -H "X-API-Key: aeitron_live_sk_948f92b7c6..."

# Check Gateway Health & Routes
curl http://localhost:8000/ready
curl http://localhost:8000/v1/gateway/stats
```

---

## 6. Docker Deployment

```bash
# Build multi-stage non-root container
docker build -t aeitron/api:latest .

# Run container
docker run -p 8000:8000 -e AEITRON_JWT_SECRET="your-32-byte-secret" aeitron/api:latest
```

---

## 7. License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
Permissive for commercial and community use, SDK development, and ecosystem integrations.
