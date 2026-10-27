package apigateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Authenticator validates JWT tokens and Scoped API Keys.
type Authenticator struct {
	mu        sync.RWMutex
	jwtSecret []byte
	apiKeys   map[string]*TenantContext // raw key -> context
}

// NewAuthenticator creates an Authenticator with a configured signing secret.
func NewAuthenticator(jwtSecret string) *Authenticator {
	if jwtSecret == "" {
		jwtSecret = "aeitron-default-secret-key-change-in-production-32bytes"
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

	// 1. Check if token is a Scoped API Key (prefixed with aeitron_live_ or aeitron_test_)
	if strings.HasPrefix(rawToken, "aeitron_live_") || strings.HasPrefix(rawToken, "aeitron_test_") {
		return a.validateAPIKey(rawToken)
	}

	// 2. Otherwise validate as JWT Token (header.payload.signature)
	return a.validateJWT(rawToken)
}

func (a *Authenticator) validateAPIKey(key string) (*TenantContext, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ctx, exists := a.apiKeys[key]
	if !exists {
		return nil, ErrUnauthorized
	}

	if !ctx.ExpiresAt.IsZero() && time.Now().UTC().After(ctx.ExpiresAt) {
		return nil, fmt.Errorf("%w: API key has expired", ErrUnauthorized)
	}

	cp := *ctx
	return &cp, nil
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
	Exp       int64    `json:"exp"`
}

func (a *Authenticator) validateJWT(token string) (*TenantContext, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid JWT format", ErrUnauthorized)
	}

	// Verify HMAC-SHA256 signature
	dataToSign := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, a.jwtSecret)
	mac.Write([]byte(dataToSign))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("%w: invalid token signature", ErrUnauthorized)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed token payload", ErrUnauthorized)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: malformed token claims", ErrUnauthorized)
	}

	// Verify expiration
	if claims.Exp > 0 && time.Now().UTC().Unix() > claims.Exp {
		return nil, fmt.Errorf("%w: token expired", ErrUnauthorized)
	}

	tier := claims.Tier
	if tier == "" {
		tier = "free"
	}

	return &TenantContext{
		TenantID:  claims.TenantID,
		OrgID:     claims.OrgID,
		ProjectID: claims.ProjectID,
		ActorID:   claims.Sub,
		Role:      claims.Role,
		Scopes:    claims.Scopes,
		Tier:      tier,
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
