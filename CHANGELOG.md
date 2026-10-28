# Changelog

All notable changes to the Aeitron API and Unified Gateway will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-10-28

### Security & Hardening
- **Critical Privilege Escalation Defense:** Bound test developer keys (`ak_test_`, `aeitron_test_`) strictly to non-admin sandbox scopes (`SandboxDeveloperScopes`), eliminating wildcard `*` auto-provisioning. Enforced fail-closed 403 Forbidden on all administrative and diagnostic routes (`/v1/gateway/*`, cache purge) when accessed with test credentials (`Livemode == false`).
- **Tenant Identity Spoofing Mitigation:** Eliminated unverified `X-Tenant-ID` header fallback on events and webhooks endpoints; all operational routes now require verified server-side authentication (`AuthenticateRequest`). Enforced server-derived tenant context for event streaming and webhook deliveries, rejecting cross-tenant publishing and dispatch mutations with 403 Forbidden.
- **TLS Handshake for Redis Clusters:** Enhanced `distributed_state.go` to perform full TLS 1.2+ handshake using `crypto/tls` when dialing `rediss://` or `tls://` endpoints with strict ServerName SNI verification.
- **Fail-Closed Distributed Consistency:** Added configurable `FailClosed` mode (`AEITRON_CLUSTER_FAIL_CLOSED=true`) preventing silent local memory drift during Redis cluster partitions in multi-replica deployments.
- **Security Regression Suite:** Added `security_regression_test.go` covering test key privilege containment, tenant spoofing resistance, and Redis TLS fail-closed semantics.

## [1.0.0] - 2026-10-28

### Added
- Pure Go 1.24 Unified L7 Edge & API Gateway with zero external dependencies.
- Cryptographic HMAC-SHA256 JWT validation and Scoped API key authentication (`ak_live_`, `ak_test_`).
- Anti-spoofing tenant identity isolation stripping untrusted client headers.
- 64-shard lock-striped token-bucket rate limiter with dual IP and tenant tier limits.
- RFC 9111 edge caching with deterministic SHA-256 ETag generation and `304 Not Modified` validation.
- Stripe-grade `Idempotency-Key` mutation engine with body fingerprinting and 24h cache.
- Low-latency Server-Sent Events (SSE) streaming (`GET /v1/events/stream`) with topic filtering.
- Asynchronous webhook engine with HMAC-SHA256 signatures, replay protection, and Dead-Letter Queue (DLQ).
- Self-hosted Developer Webhooks Portal HUD (`/v1/webhooks/portal`).
- Live test mode sandbox (`ak_test_`) returning hermetic fixtures without billing or hypervisor mutation.
- Embedded interactive Scalar (`/docs`) and ReDoc (`/redoc`) playgrounds.
- Date-based API versioning (`Aeitron-Version`) and deprecation warnings (`X-Aeitron-Deprecation-Date`).
- Prometheus OpenMetrics telemetry endpoint (`/metrics`) and W3C distributed tracing (`traceparent`).
- Multi-node load balancing pools (Round-Robin and Least-Connections) with active health probing.
- End-to-end socket staging test suite (`e2e_staging_test.go`).
- Multi-stage non-root Alpine Docker container and Docker Compose orchestration stack.

