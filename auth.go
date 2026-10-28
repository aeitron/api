package apigateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SandboxDeveloperScopes defines the strictly bounded permissions assigned to developer sandbox keys.
// Wildcard scopes ("*"), administrative scopes, and operator privileges are strictly prohibited.
var SandboxDeveloperScopes = []string{
	"sandbox:read",
	"sandbox:write",
	"compute:read",
	"compute:write",
	"dns:read",
	"dns:write",
	"billing:read",
	"orders:write",
	"storage:read",
	"storage:write",
	"events:read",
	"events:write",
	"webhooks:read",
	"webhooks:write",
}

// Authenticator validates JWT tokens and Scoped API Keys.
type Authenticator struct {
	mu        sync.RWMutex
	jwtSecret []byte
	apiKeys   map[string]*TenantContext // raw key -> context
}

// NewAuthenticator creates an Authenticator with a configured signing secret.
func NewAuthenticator(jwtSecret string) *Authenticator {
	if jwtSecret == "" {
		// Generate an ephemeral random 32-byte secret instead of using a predictable fixed string
		randomSecretBytes := make([]byte, 32)
		if _, err := rand.Read(randomSecretBytes); err == nil {
			jwtSecret = hex.EncodeToString(randomSecretBytes)
		} else {
			jwtSecret = "aeitron-fallback-secret-key-min-32bytes"
		}
	}
	return &Authenticator{
		jwtSecret: []byte(jwtSecret),
		apiKeys:   make(map[string]*TenantContext),
	}
}

// RegisterAPIKey registers a valid API key with its permissions (for in-memory fast caching).
func (a *Authenticator) RegisterAPIKey(rawKey string, ctx *TenantContext) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := *ctx
	a.apiKeys[rawKey] = &cp
}

// AuthenticateRequest validates incoming credentials and returns the verified TenantContext.
func (a *Authenticator) AuthenticateRequest(r *http.Request) (*TenantContext, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	apiKeyHeader := strings.TrimSpace(r.Header.Get("X-API-Key"))

	var rawToken string
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			rawToken = parts[1]
		} else {
			rawToken = authHeader
		}
	} else if apiKeyHeader != "" {
		rawToken = apiKeyHeader
	}

	if rawToken == "" {
		return nil, ErrUnauthorized
	}

	// 1. Check if token is a Scoped API Key (prefixed with aeitron_live_, aeitron_test_, ak_live_, ak_test_)
	if strings.HasPrefix(rawToken, "aeitron_live_") || strings.HasPrefix(rawToken, "aeitron_test_") ||
		strings.HasPrefix(rawToken, "ak_live_") || strings.HasPrefix(rawToken, "ak_test_") {
		return a.validateAPIKey(rawToken)
	}

	// 2. Otherwise validate as JWT Token (header.payload.signature)
	ctx, err := a.validateJWT(rawToken)
	if err == nil && ctx != nil {
		if strings.EqualFold(r.Header.Get("Aeitron-Livemode"), "false") || strings.EqualFold(r.Header.Get("X-Aeitron-Simulate"), "true") {
			ctx.Livemode = false
		}
	}
	return ctx, err
}

func (a *Authenticator) validateAPIKey(key string) (*TenantContext, error) {
	a.mu.RLock()
	ctx, exists := a.apiKeys[key]
	a.mu.RUnlock()

	isTestPrefix := strings.HasPrefix(key, "aeitron_test_") || strings.HasPrefix(key, "ak_test_")

	if exists {
		if !ctx.ExpiresAt.IsZero() && time.Now().UTC().After(ctx.ExpiresAt) {
			return nil, fmt.Errorf("%w: API key has expired", ErrUnauthorized)
		}
		cp := *ctx
		if isTestPrefix {
			cp.Livemode = false
		} else if strings.HasPrefix(key, "aeitron_live_") || strings.HasPrefix(key, "ak_live_") {
			cp.Livemode = true
		}
		return &cp, nil
	}

	// Auto-provision hermetic sandbox tenant for developer test keys (aeitron_test_... / ak_test_...)
	// Strictly assign bounded non-admin scopes. Wildcards ("*") and administrative roles are forbidden.
	if isTestPrefix {
		tenantID := "test_sandbox"
		parts := strings.Split(key, "_")
		if len(parts) >= 3 && parts[2] != "" {
			tenantID = "test_" + parts[2]
		}
		limit := len(key)
		if limit > 24 {
			limit = 24
		}
		boundedScopes := make([]string, len(SandboxDeveloperScopes))
		copy(boundedScopes, SandboxDeveloperScopes)
		return &TenantContext{
			TenantID:  tenantID,
			OrgID:     "org_sandbox",
			ProjectID: "proj_sandbox",
			ActorID:   "act_" + key[:limit],
			Role:      "developer",
			Scopes:    boundedScopes,
			Tier:      "developer",
			Livemode:  false,
			ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
		}, nil
	}

	return nil, ErrUnauthorized
}

// JWTClaims represents standard and custom Aeitron claims.
type JWTClaims struct {
	Sub       string   `json:"sub"` // Actor ID
	TenantID  string   `json:"tenant_id"`
	OrgID     string   `json:"org_id"`
	ProjectID string   `json:"project_id"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	Tier      string   `json:"tier"`
	Livemode  *bool    `json:"livemode,omitempty"`
	Exp       int64    `json:"exp"`
}

func (a *Authenticator) validateJWT(token string) (*TenantContext, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid JWT format", ErrUnauthorized)
	}

	// 1. Decode and strictly validate JWT Header (mitigate 'none' alg or algorithm confusion)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed token header", ErrUnauthorized)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid token header json", ErrUnauthorized)
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		return nil, fmt.Errorf("%w: unsupported token algorithm '%s', only HS256 is accepted", ErrUnauthorized, header.Alg)
	}
	if header.Typ != "" && !strings.EqualFold(header.Typ, "JWT") {
		return nil, fmt.Errorf("%w: invalid token type '%s', expected JWT", ErrUnauthorized, header.Typ)
	}

	// 2. Verify HMAC-SHA256 signature
	dataToSign := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, a.jwtSecret)
	mac.Write([]byte(dataToSign))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("%w: invalid token signature", ErrUnauthorized)
	}

	// 3. Decode and validate claims payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed token payload", ErrUnauthorized)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: malformed token claims", ErrUnauthorized)
	}

	// Enforce non-zero expiration timestamp
	if claims.Exp <= 0 {
		return nil, fmt.Errorf("%w: token must include a non-zero exp timestamp", ErrUnauthorized)
	}
	if time.Now().UTC().Unix() > claims.Exp {
		return nil, fmt.Errorf("%w: token expired", ErrUnauthorized)
	}

	// Enforce required tenant identification
	if strings.TrimSpace(claims.TenantID) == "" {
		return nil, fmt.Errorf("%w: token missing required tenant_id claim", ErrUnauthorized)
	}

	tier := claims.Tier
	if tier == "" {
		tier = "free"
	}

	livemode := true
	if claims.Livemode != nil {
		livemode = *claims.Livemode
	}

	return &TenantContext{
		TenantID:  claims.TenantID,
		OrgID:     claims.OrgID,
		ProjectID: claims.ProjectID,
		ActorID:   claims.Sub,
		Role:      claims.Role,
		Scopes:    claims.Scopes,
		Tier:      tier,
		Livemode:  livemode,
		ExpiresAt: time.Unix(claims.Exp, 0).UTC(),
	}, nil
}

// GenerateSignedToken creates a signed JWT for testing or token issuance.
func (a *Authenticator) GenerateSignedToken(claims JWTClaims) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	dataToSign := header + "." + payload
	mac := hmac.New(sha256.New, a.jwtSecret)
	mac.Write([]byte(dataToSign))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return header + "." + payload + "." + sig, nil
}

// CheckScopes verifies if the tenant context contains all required scopes.
func CheckScopes(userScopes []string, required []string) bool {
	if len(required) == 0 {
		return true
	}

	scopeMap := make(map[string]bool)
	for _, s := range userScopes {
		if s == "*" {
			return true // Superuser wildcard
		}
		scopeMap[s] = true
	}

	for _, req := range required {
		if !scopeMap[req] {
			return false
		}
	}
	return true
}
