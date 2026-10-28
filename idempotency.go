package apigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var (
	// ErrInvalidIdempotencyKey is returned when the key is too short, too long, or has illegal characters.
	ErrInvalidIdempotencyKey = errors.New("idempotency key must be between 8 and 128 characters matching [a-zA-Z0-9_\\-\\.:]")

	// ErrIdempotencyMismatch is returned when an existing key is reused with a different payload or path.
	ErrIdempotencyMismatch = errors.New("keys with identical idempotency values must send identical request parameters")

	// ErrIdempotencyInFlight is returned when a concurrent request with the same key is currently being processed.
	ErrIdempotencyInFlight = errors.New("a request with this idempotency key is currently in progress")

	idempotencyKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.:]{8,128}$`)
)

// IdempotencyRecord stores the execution state and cached response for a mutation request.
type IdempotencyRecord struct {
	Key          string            `json:"key"`
	TenantID     string            `json:"tenant_id"`
	RequestHash  string            `json:"request_hash"`
	State        string            `json:"state"` // "IN_FLIGHT" or "COMPLETED"
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	ResponseBody []byte            `json:"response_body"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`

	Done chan struct{} `json:"-"`
}

// IdempotencyEngine manages concurrent locking, payload validation, and replay caching for mutating requests.
type IdempotencyEngine struct {
	mu           sync.RWMutex
	records      map[string]*IdempotencyRecord
	ttl          time.Duration
	stateAdapter ClusterStateAdapter
}

// NewIdempotencyEngine creates an IdempotencyEngine with a default 24-hour TTL (Stripe standard).
func NewIdempotencyEngine(ttl time.Duration) *IdempotencyEngine {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	engine := &IdempotencyEngine{
		records: make(map[string]*IdempotencyRecord),
		ttl:     ttl,
	}
	go engine.reaperWorker()
	return engine
}

// SetStateAdapter configures the cluster state adapter for distributed idempotency synchronization.
func (ie *IdempotencyEngine) SetStateAdapter(adapter ClusterStateAdapter) {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	ie.stateAdapter = adapter
}

// StateAdapter returns the configured cluster state adapter.
func (ie *IdempotencyEngine) StateAdapter() ClusterStateAdapter {
	ie.mu.RLock()
	defer ie.mu.RUnlock()
	return ie.stateAdapter
}

// ComputePayloadHash returns the SHA-256 fingerprint of the HTTP method, path, and request body.
func ComputePayloadHash(method, path string, bodyBytes []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte(":"))
	h.Write([]byte(path))
	h.Write([]byte(":"))
	h.Write(bodyBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateIdempotencyKey verifies that a key satisfies formatting constraints.
func ValidateIdempotencyKey(key string) error {
	if !idempotencyKeyRegex.MatchString(key) {
		return ErrInvalidIdempotencyKey
	}
	return nil
}

// AcquireOrReplay checks if an idempotency key already exists.
// Returns:
//   - (record, true, nil) if the request was previously completed and is ready for replay.
//   - (record, false, nil) if the lock was acquired and the request should be forwarded upstream.
//   - (nil, false, ErrIdempotencyMismatch) if the payload differs from the previous request.
//   - (nil, false, ErrIdempotencyInFlight) if a concurrent request is currently running and timed out.
func (ie *IdempotencyEngine) AcquireOrReplay(tenantID, key, method, path string, bodyBytes []byte, waitTimeout time.Duration) (*IdempotencyRecord, bool, error) {
	if err := ValidateIdempotencyKey(key); err != nil {
		return nil, false, err
	}

	payloadHash := ComputePayloadHash(method, path, bodyBytes)
	scopedKey := tenantID + ":" + key

	// If distributed cluster state adapter configured and not local memory, synchronize cluster-wide
	ie.mu.RLock()
	adapter := ie.stateAdapter
	ie.mu.RUnlock()

	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		acquired, existing, err := adapter.IdempotencyAcquire(ctx, scopedKey, payloadHash, ie.ttl)
		cancel()
		if err == nil {
			if !acquired && existing != nil {
				if existing.RequestHash != payloadHash {
					return nil, false, ErrIdempotencyMismatch
				}
				if existing.State == "COMPLETED" {
					return existing, true, nil
				}
				return nil, false, ErrIdempotencyInFlight
			}
		}
	}

	ie.mu.Lock()
	now := time.Now().UTC()

	rec, exists := ie.records[scopedKey]
	if exists {
		// If expired, clean up and treat as new
		if now.After(rec.ExpiresAt) {
			delete(ie.records, scopedKey)
			rec = nil
			exists = false
		}
	}

	if exists {
		// Mismatch detection: same key must have same payload
		if rec.RequestHash != payloadHash {
			ie.mu.Unlock()
			return nil, false, ErrIdempotencyMismatch
		}

		// Replay cached response immediately if already completed
		if rec.State == "COMPLETED" {
			ie.mu.Unlock()
			return rec, true, nil
		}

		// If in-flight, release lock and wait for completion channel
		doneChan := rec.Done
		ie.mu.Unlock()

		if waitTimeout <= 0 {
			waitTimeout = 1500 * time.Millisecond
		}

		select {
		case <-doneChan:
			ie.mu.RLock()
			recAfter := ie.records[scopedKey]
			ie.mu.RUnlock()
			if recAfter != nil && recAfter.State == "COMPLETED" {
				return recAfter, true, nil
			}
			return nil, false, ErrIdempotencyInFlight

		case <-time.After(waitTimeout):
			return nil, false, ErrIdempotencyInFlight
		}
	}

	// Register fresh in-flight record
	newRecord := &IdempotencyRecord{
		Key:         key,
		TenantID:    tenantID,
		RequestHash: payloadHash,
		State:       "IN_FLIGHT",
		CreatedAt:   now,
		ExpiresAt:   now.Add(ie.ttl),
		Done:        make(chan struct{}),
	}
	ie.records[scopedKey] = newRecord
	ie.mu.Unlock()

	return newRecord, false, nil
}

// Complete saves the upstream status, headers, and body bytes, and notifies any concurrent waiters.
func (ie *IdempotencyEngine) Complete(tenantID, key string, statusCode int, header http.Header, bodyBytes []byte) {
	scopedKey := tenantID + ":" + key

	ie.mu.Lock()
	rec, exists := ie.records[scopedKey]
	if !exists || rec.State == "COMPLETED" {
		ie.mu.Unlock()
		return
	}

	rec.StatusCode = statusCode
	rec.ResponseBody = make([]byte, len(bodyBytes))
	copy(rec.ResponseBody, bodyBytes)

	rec.Headers = make(map[string]string)
	if ctype := header.Get("Content-Type"); ctype != "" {
		rec.Headers["Content-Type"] = ctype
	}

	rec.State = "COMPLETED"
	close(rec.Done)
	adapter := ie.stateAdapter
	ie.mu.Unlock()

	// Synchronize completion to distributed cluster state adapter
	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_ = adapter.IdempotencyComplete(ctx, scopedKey, rec, ie.ttl)
		cancel()
	}
}

// Abort cancels an in-flight record if an upstream proxy failure occurs.
func (ie *IdempotencyEngine) Abort(tenantID, key string) {
	scopedKey := tenantID + ":" + key

	ie.mu.Lock()
	rec, exists := ie.records[scopedKey]
	if exists && rec.State == "IN_FLIGHT" {
		delete(ie.records, scopedKey)
		close(rec.Done)
	}
	adapter := ie.stateAdapter
	ie.mu.Unlock()

	// Synchronize abort to distributed cluster state adapter
	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_ = adapter.IdempotencyAbort(ctx, scopedKey)
		cancel()
	}
}

// reaperWorker cleans up expired idempotency records every 10 minutes.
func (ie *IdempotencyEngine) reaperWorker() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ie.evictExpired()
	}
}

func (ie *IdempotencyEngine) evictExpired() {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	now := time.Now().UTC()
	for k, rec := range ie.records {
		if now.After(rec.ExpiresAt) {
			delete(ie.records, k)
		}
	}
}
