package apigateway

import (
	"errors"
	"time"
)

// Common standard errors.
var (
	ErrUnauthorized        = errors.New("unauthorized: missing or invalid credentials")
	ErrForbidden           = errors.New("forbidden: insufficient permission scopes")
	ErrRateLimitExceeded   = errors.New("too many requests: rate limit exceeded")
	ErrUpstreamUnavailable = errors.New("upstream service unavailable: circuit breaker tripped")
	ErrRouteNotFound       = errors.New("route not found")
)

// RouteRule specifies dynamic reverse proxy routing and security policy for a path prefix.
type RouteRule struct {
	PathPrefix     string        `json:"path_prefix"`
	UpstreamURL    string        `json:"upstream_url"`
	StripPrefix    bool          `json:"strip_prefix"`
	AllowAnonymous bool          `json:"allow_anonymous"`
	RequiredScopes []string      `json:"required_scopes,omitempty"`
	Timeout        time.Duration `json:"timeout"`
	RateLimitTier  string        `json:"rate_limit_tier,omitempty"` // "free", "pro", "enterprise"
}

// TenantContext contains verified tenant and actor identity extracted from credentials.
type TenantContext struct {
	TenantID  string    `json:"tenant_id"`
	OrgID     string    `json:"org_id"`
	ProjectID string    `json:"project_id"`
	ActorID   string    `json:"actor_id"`
	Role      string    `json:"role"`
	Scopes    []string  `json:"scopes"`
	Tier      string    `json:"tier"` // "free", "pro", "enterprise"
	ExpiresAt time.Time `json:"expires_at"`
}

// RateLimitTierConfig specifies token bucket rate and capacity for a tenant tier.
type RateLimitTierConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstCapacity     int     `json:"burst_capacity"`
}

// DefaultRateLimits defines production token-bucket tiers.
var DefaultRateLimits = map[string]RateLimitTierConfig{
	"ip_default": {
		RequestsPerSecond: 100.0, // 100 req/s per IP
		BurstCapacity:     200,
	},
	"free": {
		RequestsPerSecond: 1.0, // 60 req/min
		BurstCapacity:     10,
	},
	"pro": {
		RequestsPerSecond: 10.0, // 600 req/min
		BurstCapacity:     50,
	},
	"enterprise": {
		RequestsPerSecond: 1000.0, // 60,000 req/min
		BurstCapacity:     2000,
	},
}

// GatewayStats reports live operational metrics.
type GatewayStats struct {
	TotalRequests     int64             `json:"total_requests"`
	ActiveConnections int64             `json:"active_connections"`
	StatusCodes       map[int]int64     `json:"status_codes"`
	UpstreamStatus    map[string]string `json:"upstream_status"`
	RateLimitedCount  int64             `json:"rate_limited_count"`
	AuthFailedCount   int64             `json:"auth_failed_count"`
	UptimeSeconds     int64             `json:"uptime_seconds"`
}

// AuditRecord represents a captured state-mutating request for the compliance ledger.
type AuditRecord struct {
	RequestID    string    `json:"request_id"`
	TenantID     string    `json:"tenant_id"`
	ActorID      string    `json:"actor_id"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	ClientIP     string    `json:"client_ip"`
	StatusCode   int       `json:"status_code"`
	DurationMs   int64     `json:"duration_ms"`
	Timestamp    time.Time `json:"timestamp"`
	ResponseBody string    `json:"response_body,omitempty"`
}
