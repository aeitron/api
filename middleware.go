package apigateway

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
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

// ResponseWriterWrapper intercepts and records the HTTP response status and written byte count.
type ResponseWriterWrapper struct {
	http.ResponseWriter
	StatusCode   int
	BytesWritten int64
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
	n, err := rw.ResponseWriter.Write(b)
	rw.BytesWritten += int64(n)
	return n, err
}

// ApplySecurityHeaders adds standard defensive headers to the response.
func ApplySecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}

// HandleCORS processes preflight OPTIONS or attaches CORS response headers.
func HandleCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-API-Key, Content-Type, X-Request-ID, Accept")
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")
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
