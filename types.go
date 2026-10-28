package apigateway

import (
	"errors"
	"strings"
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

// HealthCheckConfig defines active health probing parameters for upstream backend instances.
type HealthCheckConfig struct {
	Enabled            bool          `json:"enabled"`
	Path               string        `json:"path"`                // e.g. "/healthz"
	Interval           time.Duration `json:"interval"`            // e.g. 10s
	Timeout            time.Duration `json:"timeout"`             // e.g. 2s
	UnhealthyThreshold int           `json:"unhealthy_threshold"` // consecutive failures to mark unhealthy (e.g. 2)
	HealthyThreshold   int           `json:"healthy_threshold"`   // consecutive successes to mark healthy (e.g. 2)
}

// RouteRule specifies dynamic reverse proxy routing and security policy for a path prefix.
type RouteRule struct {
	PathPrefix     string            `json:"path_prefix"`
	UpstreamURL    string            `json:"upstream_url,omitempty"`
	UpstreamURLs   []string          `json:"upstream_urls,omitempty"`  // Multiple backend instances for smart load balancing
	LoadBalancer   string            `json:"load_balancer,omitempty"`  // "round_robin" (default) or "least_conn"
	HealthCheck    HealthCheckConfig `json:"health_check,omitempty"`   // Active background health checking
	RewritePrefix  string            `json:"rewrite_prefix,omitempty"` // Rewrites path prefix (e.g. /v1/domains -> /v1/commerce/domains)
	StripPrefix    bool              `json:"strip_prefix"`
	AllowAnonymous bool              `json:"allow_anonymous"`
	RequiredScopes []string          `json:"required_scopes,omitempty"`
	Timeout        time.Duration     `json:"timeout"`
	RateLimitTier  string            `json:"rate_limit_tier,omitempty"` // "free", "pro", "enterprise"
	MaxBodyBytes   int64             `json:"max_body_bytes,omitempty"`  // Max request payload in bytes (default: 1MB)
	CacheTTL       time.Duration     `json:"cache_ttl,omitempty"`       // RFC 9111 edge cache TTL (0 = bypass cache)
}

// TenantContext contains verified tenant and actor identity extracted from credentials.
type TenantContext struct {
	TenantID  string    `json:"tenant_id"`
	OrgID     string    `json:"org_id"`
	ProjectID string    `json:"project_id"`
	ActorID   string    `json:"actor_id"`
	Role      string    `json:"role"`
	Scopes    []string  `json:"scopes"`
	Tier      string    `json:"tier"`     // "free", "pro", "enterprise"
	Livemode  bool      `json:"livemode"` // true for live production keys, false for sandbox/test keys
	ExpiresAt time.Time `json:"expires_at"`
}

// RateLimitTierConfig specifies token bucket rate and capacity for a tenant tier.
type RateLimitTierConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstCapacity     int     `json:"burst_capacity"`
}

// DefaultRateLimits defines production token-bucket tiers with explicit aliases.
var DefaultRateLimits = map[string]RateLimitTierConfig{
	"ip_default": {
		RequestsPerSecond: 100.0, // 100 req/s per IP
		BurstCapacity:     200,
	},
	"free": {
		RequestsPerSecond: 1.0, // 60 req/min
		BurstCapacity:     10,
	},
	"tier_free": {
		RequestsPerSecond: 1.0,
		BurstCapacity:     10,
	},
	"developer": {
		RequestsPerSecond: 5.0, // 300 req/min
		BurstCapacity:     25,
	},
	"tier_developer": {
		RequestsPerSecond: 5.0,
		BurstCapacity:     25,
	},
	"pro": {
		RequestsPerSecond: 10.0, // 600 req/min
		BurstCapacity:     50,
	},
	"tier_pro": {
		RequestsPerSecond: 10.0,
		BurstCapacity:     50,
	},
	"enterprise": {
		RequestsPerSecond: 1000.0, // 60,000 req/min
		BurstCapacity:     2000,
	},
	"tier_enterprise": {
		RequestsPerSecond: 1000.0,
		BurstCapacity:     2000,
	},
}

// ResolveRateLimitTier safely normalizes and resolves any tier string to an approved tier config.
// Unknown, empty, or unmapped tiers fail closed to the restricted "free" tier (never unlimited).
func ResolveRateLimitTier(tier string) (string, RateLimitTierConfig) {
	clean := strings.ToLower(strings.TrimSpace(tier))
	if clean == "" {
		return "free", DefaultRateLimits["free"]
	}
	if cfg, exists := DefaultRateLimits[clean]; exists {
		return clean, cfg
	}
	// Support un-prefixed or prefixed variants
	if strings.HasPrefix(clean, "tier_") {
		unprefixed := strings.TrimPrefix(clean, "tier_")
		if cfg, exists := DefaultRateLimits[unprefixed]; exists {
			return unprefixed, cfg
		}
	} else {
		prefixed := "tier_" + clean
		if cfg, exists := DefaultRateLimits[prefixed]; exists {
			return clean, cfg
		}
	}
	// Fail-safe default for unknown tiers: always bound to free tier
	return "free", DefaultRateLimits["free"]
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
