package apigateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ProblemDetails represents an RFC 7807 compliant error object.
// It also provides a legacy "error" string field for backwards compatibility with simple error readers.
type ProblemDetails struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code,omitempty"`
	Error     string `json:"error"` // Backwards-compatible mirror of Detail
}

// WriteProblem writes an RFC 7807 Problem Details response.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail, code string) {
	reqID := ""
	instance := ""
	if r != nil {
		reqID = r.Header.Get("X-Request-ID")
		instance = r.URL.Path
	}
	if reqID == "" {
		reqID = w.Header().Get("X-Request-ID")
	}

	typeSlug := strings.ToLower(strings.ReplaceAll(title, " ", "-"))
	problem := ProblemDetails{
		Type:      fmt.Sprintf("https://api.aeitron.com/errors/%s", typeSlug),
		Title:     title,
		Status:    status,
		Detail:    detail,
		Instance:  instance,
		RequestID: reqID,
		Code:      code,
		Error:     detail,
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

// WriteUnauthorized returns a 401 Unauthorized problem.
func WriteUnauthorized(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", detail, "UNAUTHORIZED")
}

// WriteForbidden returns a 403 Forbidden problem.
func WriteForbidden(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusForbidden, "Forbidden", detail, "FORBIDDEN")
}

// WriteNotFound returns a 404 Not Found problem.
func WriteNotFound(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusNotFound, "Not Found", detail, "NOT_FOUND")
}

// WriteMethodNotAllowed returns a 405 Method Not Allowed problem.
func WriteMethodNotAllowed(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusMethodNotAllowed, "Method Not Allowed", detail, "METHOD_NOT_ALLOWED")
}

// WritePayloadTooLarge returns a 413 Payload Too Large problem.
func WritePayloadTooLarge(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusRequestEntityTooLarge, "Payload Too Large", detail, "PAYLOAD_TOO_LARGE")
}

// WriteRateLimited returns a 429 Too Many Requests problem.
func WriteRateLimited(w http.ResponseWriter, r *http.Request, detail string, retryAfterSeconds int) {
	if retryAfterSeconds > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds))
	}
	WriteProblem(w, r, http.StatusTooManyRequests, "Too Many Requests", detail, "RATE_LIMIT_EXCEEDED")
}

// WriteBadGateway returns a 502 Bad Gateway problem.
func WriteBadGateway(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusBadGateway, "Bad Gateway", detail, "UPSTREAM_GATEWAY_ERROR")
}

// WriteServiceUnavailable returns a 503 Service Unavailable problem.
func WriteServiceUnavailable(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusServiceUnavailable, "Service Unavailable", detail, "SERVICE_UNAVAILABLE")
}

// WriteValidationError returns a 422 Unprocessable Entity problem.
func WriteValidationError(w http.ResponseWriter, r *http.Request, detail string) {
	WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", detail, "VALIDATION_FAILED")
}

// WriteConflict returns a 409 Conflict problem.
func WriteConflict(w http.ResponseWriter, r *http.Request, detail, code string) {
	if code == "" {
		code = "RESOURCE_CONFLICT"
	}
	WriteProblem(w, r, http.StatusConflict, "Conflict", detail, code)
}

// WriteBadRequest returns a 400 Bad Request problem.
func WriteBadRequest(w http.ResponseWriter, r *http.Request, detail, code string) {
	if code == "" {
		code = "BAD_REQUEST"
	}
	WriteProblem(w, r, http.StatusBadRequest, "Bad Request", detail, code)
}
