package apigateway

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

var validRequestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)

// GenerateRequestID generates a unique, cryptographically random Request ID.
func GenerateRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

// ExtractOrGenerateRequestID extracts a valid X-Request-ID header or creates a new one.
func ExtractOrGenerateRequestID(r *http.Request) string {
	reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if reqID != "" && validRequestIDPattern.MatchString(reqID) {
		return reqID
	}
	return GenerateRequestID()
}

// ResponseWriterWrapper intercepts and records the HTTP response status, written byte count, and optional body buffer.
type ResponseWriterWrapper struct {
	http.ResponseWriter
	StatusCode   int
	BytesWritten int64
	BodyBuffer   *bytes.Buffer
}

// NewResponseWriterWrapper creates a wrapper defaulting to status 200 OK.
func NewResponseWriterWrapper(w http.ResponseWriter) *ResponseWriterWrapper {
	return &ResponseWriterWrapper{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
	}
}

func (rw *ResponseWriterWrapper) WriteHeader(statusCode int) {
	rw.StatusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *ResponseWriterWrapper) Write(b []byte) (int, error) {
	if rw.BodyBuffer != nil {
		rw.BodyBuffer.Write(b)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.BytesWritten += int64(n)
	return n, err
}

func (rw *ResponseWriterWrapper) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ApplySecurityHeaders adds standard defensive headers to the response.
func ApplySecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

var defaultAllowedOrigins = []string{
	"https://aeitron.com",
	"https://app.aeitron.com",
	"https://dashboard.aeitron.com",
	"https://developer.aeitron.com",
	"https://api.aeitron.com",
}

// IsOriginAllowed checks whether an incoming Origin header matches the configured allowlist.
func IsOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	// 1. Check custom configured origins from environment
	if custom := os.Getenv("AEITRON_CORS_ALLOWED_ORIGINS"); custom != "" {
		for _, o := range strings.Split(custom, ",") {
			trimmed := strings.TrimSpace(o)
			if trimmed == "*" || strings.EqualFold(trimmed, origin) {
				return true
			}
		}
	}

	// 2. Check canonical Aeitron production domains and wildcard subdomains
	originLower := strings.ToLower(origin)
	for _, allowed := range defaultAllowedOrigins {
		if strings.EqualFold(allowed, originLower) {
			return true
		}
	}
	if strings.HasSuffix(originLower, ".aeitron.com") || strings.HasSuffix(originLower, ".aeitron.io") {
		return true
	}

	// 3. In development mode, allow localhost and 127.0.0.1 on any port
	isDev := !strings.EqualFold(os.Getenv("AEITRON_ENV"), "production") || strings.EqualFold(os.Getenv("AEITRON_DEV_MODE"), "true")
	if isDev {
		if strings.HasPrefix(originLower, "http://localhost") || strings.HasPrefix(originLower, "http://127.0.0.1") ||
			strings.HasPrefix(originLower, "https://localhost") || strings.HasPrefix(originLower, "https://127.0.0.1") {
			return true
		}
	}

	return false
}

// HandleCORS processes preflight OPTIONS or attaches CORS response headers according to strict origin allowlist.
func HandleCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))

	// Non-CORS request (e.g. backend curl, CLI, SDK)
	if origin == "" {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}

	allowed := IsOriginAllowed(origin)
	if !allowed {
		if r.Method == http.MethodOptions {
			http.Error(w, "CORS origin not permitted", http.StatusForbidden)
			return true
		}
		// For regular requests, do NOT reflect untrusted origin
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, X-Request-ID, Accept, Idempotency-Key, X-Idempotency-Key, If-None-Match, If-Modified-Since, Aeitron-Version, X-Aeitron-Version, API-Version")
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Idempotent-Replayed, ETag, X-Cache, Age, Aeitron-Version, X-Aeitron-Deprecation-Date, Sunset, Link, X-Aeitron-Warning")
	w.Header().Set("Access-Control-Max-Age", "86400")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// AuditSpooler buffers and dispatches audit events for state mutations.
type AuditSpooler struct {
	mu      sync.RWMutex
	records []AuditRecord
	ch      chan AuditRecord
}

// NewAuditSpooler creates a background audit spooler.
func NewAuditSpooler(bufferSize int) *AuditSpooler {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	spooler := &AuditSpooler{
		ch: make(chan AuditRecord, bufferSize),
	}
	go spooler.worker()
	return spooler
}

func (s *AuditSpooler) worker() {
	for rec := range s.ch {
		s.mu.Lock()
		if len(s.records) > 5000 {
			s.records = s.records[1000:] // Bound memory
		}
		s.records = append(s.records, rec)
		s.mu.Unlock()
	}
}

// Spool queues an audit event asynchronously.
func (s *AuditSpooler) Spool(rec AuditRecord) {
	select {
	case s.ch <- rec:
	default:
		// Drop without blocking request path under extreme backpressure
	}
}

// GetRecords returns recent audit records.
func (s *AuditSpooler) GetRecords() []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]AuditRecord, len(s.records))
	copy(list, s.records)
	return list
}
