# Aeitron API Gateway — System Architecture & Design Specification

## 1. System Mission & Operational Boundaries

`aeitron/api` is the high-performance unified L7 developer gateway, reverse proxy, and OpenAPI 3.1.0 contract owner for the Aeitron Cloud Platform.

Implemented in pure **Go 1.24 with zero external dependencies**, it provides:
- Centralized cryptographic HMAC-SHA256 JWT & Scoped API key authentication
- Anti-spoofing tenant identity isolation
- Sub-millisecond RFC 9111 edge caching with ETag conditional validation
- 64-shard lock-striped token-bucket rate limiting
- Stripe-grade idempotency mutation deduplication
- Low-latency Server-Sent Events (SSE) streaming
- Cryptographic HMAC-signed webhook delivery with DLQ retry automation
- Pluggable distributed cluster state (Redis / KeyDB) with seamless fail-open in-memory resilience

```
                                [ Public Clients / Dashboard / SDKs ]
                                                 │
                                                 ▼ (Port 8000)
    ┌────────────────────────────────────────────────────────────────────────────────────────┐
    │                                  Aeitron API Gateway                                   │
    ├────────────────────────────────────────────────────────────────────────────────────────┤
    │ 1. CORS Preflight & Defensive Headers (Strict-Transport-Security, X-Frame-Options)     │
    │ 2. W3C Traceparent & Request-ID Correlation Generation                                 │
    │ 3. 64-Shard Lock-Striped Token Bucket Rate Limiting (Client IP Level)                  │
    │ 4. Anti-Spoofing: Strip incoming X-Tenant-ID / X-Actor-ID client headers                │
    │ 5. Authenticator: Cryptographic HMAC-SHA256 JWT Token & Scoped API Keys (ak_live_)     │
    │ 6. RBAC Scope Validation (CheckScopes)                                                 │
    │ 7. Tenant Tier Rate Limiting (free: 10 burst, pro: 100 burst, enterprise: 2000 burst)   │
    │ 8. Stripe-Grade Idempotency Engine: SHA-256 Body Fingerprinting & Replay Cache        │
    │ 9. Sub-millisecond RFC 9111 Edge Caching & ETag Conditional Validation (304)           │
    │ 10. Longest-Prefix Dynamic Upstream Matching & Circuit Breaker (5xx Error Tracking)    │
    │ 11. Async Audit Spooling: Non-blocking mutation channel ingestion                     │
    └────────────────────────────────────────────┬───────────────────────────────────────────┘
                                                 │
                   ┌─────────────────────────────┼─────────────────────────────┐
                   ▼                             ▼                             ▼
            services/identity             services/commerce             services/network
            (:9092 - /v1/auth)            (:8098 - /v1/commerce)        (:9090 - /v1/router)
```

---

## 2. Request Processing Pipeline

1. **Defensive Security & CORS Preflight:**
   - Evaluates incoming `Origin` against canonical allowlist (`aeitron.com`, `aeitron.io`).
   - Disallowed preflights fail closed with `403 Forbidden`. Permitted preflights return `204 No Content`.
2. **Correlation & Distributed Tracing:**
   - Injects `X-Request-ID` if absent. Generates W3C `traceparent` (`00-<trace_id>-<span_id>-<flags>`) and records microsecond span metrics.
3. **Lock-Striped IP Rate Limiting:**
   - Hashes client IP with FNV-32a across 64 shards to eliminate global mutex bottlenecks.
4. **Anti-Spoofing Tenant Isolation:**
   - Unconditionally deletes client-submitted `X-Tenant-ID`, `X-Org-ID`, `X-Actor-ID`, `X-Actor-Role`.
5. **Authentication & Authorization:**
   - Validates HMAC-SHA256 JWT tokens (rejecting `alg: none` and algorithm confusion) or Scoped API keys (`ak_live_`, `ak_test_`).
   - Injects server-verified tenant context headers downstream.
   - Enforces required permission scopes (e.g. `audit:read`, `fleet:read`).
6. **Tenant Tier Rate Limiting:**
   - Evaluates tenant token bucket limits based on account tier.
7. **Idempotency Key Protection:**
   - On mutations (`POST`, `PUT`, `PATCH`, `DELETE`) carrying `Idempotency-Key`, checks cache.
   - Exact replays return cached response with `Idempotent-Replayed: true`. Mismatched payloads return `409 Conflict`.
8. **RFC 9111 Edge Caching:**
   - Cacheable GET queries served from memory with `X-Cache: HIT`. Matching `If-None-Match` returns `304 Not Modified`.
9. **Reverse Proxying & Circuit Breaking:**
   - Routes to upstream node pools using atomic Round-Robin or Least-Connections algorithms.
   - 3-state circuit breaker trips on consecutive 5xx errors to protect failing backends.
10. **Audit Spooling & OpenMetrics:**
    - State mutations spooled to background audit channel; request counters and latency histograms exported at `/metrics`.

---

## 3. Pluggable Distributed State Architecture

When running across multi-PoP deployments:
- Configure `REDIS_URL=redis://127.0.0.1:6379/0`.
- The gateway uses a zero-dependency RESP client to synchronize token buckets, idempotency locks, and cache entries cluster-wide.
- If Redis becomes unreachable, the gateway automatically logs a cluster error and falls open to thread-safe local in-memory state without dropping requests.

