package apigateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Canonical Aeitron webhook headers matching Stripe-style conventions
	HeaderWebhookSignature  = "X-Aeitron-Signature"
	HeaderWebhookTimestamp  = "X-Aeitron-Timestamp"
	HeaderWebhookDeliveryID = "X-Aeitron-Delivery-ID"
	HeaderWebhookEventType  = "X-Aeitron-Event-Type"
	HeaderWebhookUserAgent  = "Aeitron-Webhook-Delivery/1.0"
)

var (
	ErrInvalidWebhookSignature   = errors.New("invalid webhook signature or timestamp skew")
	ErrWebhookSubNotFound        = errors.New("webhook subscription not found")
	ErrWebhookDeadLetterNotFound = errors.New("dead-letter webhook item not found")
	ErrInvalidWebhookURL         = errors.New("invalid or unsafe destination webhook URL")
)

// WebhookEvent represents an infrastructure cloud event notification.
type WebhookEvent struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"` // e.g. "deployment.succeeded", "invoice.paid", "domain.verified", "ddos.detected"
	TenantID  string          `json:"tenant_id"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// WebhookSubscription defines a tenant's registered webhook receiver endpoint.
type WebhookSubscription struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"` // e.g. ["deployment.*", "invoice.paid"] or ["*"]
	Secret    string    `json:"secret"` // "whsec_..."
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateSubscriptionRequest contains parameters to register a new webhook destination.
type CreateSubscriptionRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret,omitempty"`
	Active *bool    `json:"active,omitempty"`
}

// WebhookDelivery records an individual webhook delivery execution attempt and status.
type WebhookDelivery struct {
	ID             string     `json:"id"`
	SubscriptionID string     `json:"subscription_id"`
	TenantID       string     `json:"tenant_id"`
	EventID        string     `json:"event_id"`
	EventType      string     `json:"event_type"`
	URL            string     `json:"url"`
	Attempt        int        `json:"attempt"`
	MaxAttempts    int        `json:"max_attempts"`
	StatusCode     int        `json:"status_code"`
	Error          string     `json:"error,omitempty"`
	DurationMs     int64      `json:"duration_ms"`
	Status         string     `json:"status"` // "pending", "success", "retrying", "dead_letter"
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
	NextRetryAt    *time.Time `json:"next_retry_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// DeadLetterItem preserves permanently failed deliveries for forensic inspection and manual redelivery.
type DeadLetterItem struct {
	Delivery     WebhookDelivery     `json:"delivery"`
	Event        WebhookEvent        `json:"event"`
	Subscription WebhookSubscription `json:"subscription"`
	FailedAt     time.Time           `json:"failed_at"`
	Reason       string              `json:"reason"`
}

// WebhookConfig tunes the asynchronous worker pool, retries, and HTTP timeouts.
type WebhookConfig struct {
	MaxRetries        int
	InitialBackoff    time.Duration
	BackoffMultiplier float64
	HTTPTimeout       time.Duration
	QueueSize         int
	Workers           int
	ClockSkewWindow   time.Duration
	HTTPClient        *http.Client
}

// DefaultWebhookConfig returns production-tuned defaults.
func DefaultWebhookConfig() WebhookConfig {
	return WebhookConfig{
		MaxRetries:        3,
		InitialBackoff:    500 * time.Millisecond,
		BackoffMultiplier: 2.0,
		HTTPTimeout:       5 * time.Second,
		QueueSize:         2000,
		Workers:           4,
		ClockSkewWindow:   5 * time.Minute,
	}
}

// WebhookSigner signs outgoing payloads and verifies incoming HMAC-SHA256 signatures.
type WebhookSigner struct {
	tolerance time.Duration
}

// NewWebhookSigner initializes a WebhookSigner with a clock skew tolerance.
func NewWebhookSigner(tolerance time.Duration) *WebhookSigner {
	if tolerance <= 0 {
		tolerance = 5 * time.Minute
	}
	return &WebhookSigner{tolerance: tolerance}
}

// Sign computes the HMAC-SHA256 signature over "timestamp.payload".
// Returns the header value (format "sha256=<hex>") and the Unix timestamp string.
func (s *WebhookSigner) Sign(secret string, payload []byte, ts time.Time) (string, string) {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	toSign := tsStr + "." + string(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(toSign))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	return "sha256=" + sigHex, tsStr
}

// Verify checks if sigHeader matches the HMAC-SHA256 signature and validates timestamp skew to defeat replay attacks.
func (s *WebhookSigner) Verify(secret string, payload []byte, sigHeader string, tsHeader string) error {
	if secret == "" || sigHeader == "" || tsHeader == "" {
		return ErrInvalidWebhookSignature
	}

	tsUnix, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp format", ErrInvalidWebhookSignature)
	}

	eventTime := time.Unix(tsUnix, 0).UTC()
	now := time.Now().UTC()

	diff := now.Sub(eventTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > s.tolerance {
		return fmt.Errorf("%w: timestamp out of acceptable window (clock skew %v exceeds max %v)", ErrInvalidWebhookSignature, diff, s.tolerance)
	}

	toSign := tsHeader + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(toSign))
	expectedHex := hex.EncodeToString(mac.Sum(nil))

	providedHex := sigHeader
	if strings.HasPrefix(providedHex, "sha256=") {
		providedHex = strings.TrimPrefix(providedHex, "sha256=")
	} else if strings.HasPrefix(providedHex, "v1=") {
		providedHex = strings.TrimPrefix(providedHex, "v1=")
	}

	if !hmac.Equal([]byte(expectedHex), []byte(providedHex)) {
		return fmt.Errorf("%w: signature mismatch", ErrInvalidWebhookSignature)
	}

	return nil
}

type deliveryJob struct {
	sub        WebhookSubscription
	event      WebhookEvent
	payload    []byte
	attempt    int
	deliveryID string
	createdAt  time.Time
}

// WebhookEngine coordinates asynchronous event notification, subscription routing,
// exponential backoff retries, and dead-letter queue management.
type WebhookEngine struct {
	cfg     WebhookConfig
	signer  *WebhookSigner
	client  *http.Client
	metrics *MetricsCollector

	mu            sync.RWMutex
	subscriptions map[string]*WebhookSubscription // sub_id -> sub
	deliveries    []*WebhookDelivery              // circular history (capped at 1000)
	deadLetters   []*DeadLetterItem               // circular DLQ (capped at 500)

	queue      chan deliveryJob
	inFlight   sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	activeSubs atomic.Int64
}

// NewWebhookEngine initializes the asynchronous webhook delivery engine.
func NewWebhookEngine(cfg WebhookConfig, metrics *MetricsCollector) *WebhookEngine {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 500 * time.Millisecond
	}
	if cfg.BackoffMultiplier < 1.0 {
		cfg.BackoffMultiplier = 2.0
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 5 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 2000
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.ClockSkewWindow <= 0 {
		cfg.ClockSkewWindow = 5 * time.Minute
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.HTTPTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &WebhookEngine{
		cfg:           cfg,
		signer:        NewWebhookSigner(cfg.ClockSkewWindow),
		client:        httpClient,
		metrics:       metrics,
		subscriptions: make(map[string]*WebhookSubscription),
		deliveries:    make([]*WebhookDelivery, 0, 100),
		deadLetters:   make([]*DeadLetterItem, 0, 50),
		queue:         make(chan deliveryJob, cfg.QueueSize),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Spawn bounded background worker pool
	for i := 0; i < cfg.Workers; i++ {
		go engine.workerLoop()
	}

	return engine
}

// Signer returns the cryptographic HMAC signer.
func (e *WebhookEngine) Signer() *WebhookSigner {
	return e.signer
}

// CreateSubscription registers a new tenant webhook destination after SSRF validation.
func (e *WebhookEngine) CreateSubscription(tenantID string, req CreateSubscriptionRequest) (*WebhookSubscription, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	trimmedURL := strings.TrimSpace(req.URL)
	if trimmedURL == "" {
		return nil, errors.New("webhook destination url is required")
	}

	// SSRF Defense: validate safe destination URL
	if err := ValidateSafeTargetURL(trimmedURL); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidWebhookURL, err.Error())
	}

	events := req.Events
	if len(events) == 0 {
		events = []string{"*"}
	}

	secret := strings.TrimSpace(req.Secret)
	if secret == "" {
		secret = "whsec_" + randomHex(24)
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	now := time.Now().UTC()
	sub := &WebhookSubscription{
		ID:        "sub_" + randomHex(12),
		TenantID:  tenantID,
		URL:       trimmedURL,
		Events:    events,
		Secret:    secret,
		Active:    active,
		CreatedAt: now,
		UpdatedAt: now,
	}

	e.mu.Lock()
	e.subscriptions[sub.ID] = sub
	if active {
		e.activeSubs.Add(1)
	}
	count := e.activeSubs.Load()
	e.mu.Unlock()

	if e.metrics != nil {
		e.metrics.SetWebhookActiveSubscriptions(count)
	}

	return sub, nil
}

// GetSubscription retrieves a webhook subscription by ID for the tenant.
func (e *WebhookEngine) GetSubscription(tenantID, id string) (*WebhookSubscription, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	sub, exists := e.subscriptions[id]
	if !exists || (tenantID != "" && tenantID != "*" && sub.TenantID != tenantID) {
		return nil, ErrWebhookSubNotFound
	}
	cp := *sub
	return &cp, nil
}

// ListSubscriptions returns all registered subscriptions for the tenant.
func (e *WebhookEngine) ListSubscriptions(tenantID string) []*WebhookSubscription {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*WebhookSubscription
	for _, sub := range e.subscriptions {
		if tenantID == "" || tenantID == "*" || sub.TenantID == tenantID {
			cp := *sub
			result = append(result, &cp)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result
}

// DeleteSubscription removes a webhook subscription.
func (e *WebhookEngine) DeleteSubscription(tenantID, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	sub, exists := e.subscriptions[id]
	if !exists || (tenantID != "" && tenantID != "*" && sub.TenantID != tenantID) {
		return ErrWebhookSubNotFound
	}

	if sub.Active {
		e.activeSubs.Add(-1)
	}
	delete(e.subscriptions, id)
	count := e.activeSubs.Load()

	if e.metrics != nil {
		e.metrics.SetWebhookActiveSubscriptions(count)
	}
	return nil
}

// ActiveSubscriptionsCount returns the total number of active subscriptions.
func (e *WebhookEngine) ActiveSubscriptionsCount() int64 {
	return e.activeSubs.Load()
}

// Dispatch matches an event to active tenant subscriptions and enqueues asynchronous deliveries.
func (e *WebhookEngine) Dispatch(event WebhookEvent) ([]*WebhookDelivery, error) {
	if event.Type == "" {
		return nil, errors.New("event type is required")
	}
	if event.ID == "" {
		event.ID = "evt_" + randomHex(12)
	}
	if event.TenantID == "" {
		event.TenantID = "default"
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal webhook event: %w", err)
	}

	e.mu.RLock()
	var matchedSubs []WebhookSubscription
	for _, sub := range e.subscriptions {
		if !sub.Active {
			continue
		}
		if sub.TenantID == event.TenantID || sub.TenantID == "*" {
			for _, pattern := range sub.Events {
				if matchesEventPattern(pattern, event.Type) {
					matchedSubs = append(matchedSubs, *sub)
					break
				}
			}
		}
	}
	e.mu.RUnlock()

	if e.metrics != nil {
		e.metrics.RecordWebhookDispatched(event.Type)
	}

	if len(matchedSubs) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	var deliveries []*WebhookDelivery

	e.mu.Lock()
	for _, sub := range matchedSubs {
		deliveryID := "del_" + randomHex(12)
		del := &WebhookDelivery{
			ID:             deliveryID,
			SubscriptionID: sub.ID,
			TenantID:       sub.TenantID,
			EventID:        event.ID,
			EventType:      event.Type,
			URL:            sub.URL,
			Attempt:        1,
			MaxAttempts:    e.cfg.MaxRetries,
			Status:         "pending",
			CreatedAt:      now,
		}
		e.deliveries = append(e.deliveries, del)
		if len(e.deliveries) > 1000 {
			e.deliveries = e.deliveries[len(e.deliveries)-1000:]
		}

		deliveries = append(deliveries, del)

		job := deliveryJob{
			sub:        sub,
			event:      event,
			payload:    payload,
			attempt:    1,
			deliveryID: deliveryID,
			createdAt:  now,
		}

		e.inFlight.Add(1)
		select {
		case e.queue <- job:
		default:
			// Queue is saturated; mark delivery as failed
			del.Status = "dead_letter"
			del.Error = "webhook delivery queue saturated"
			e.inFlight.Done()
		}
	}
	e.mu.Unlock()

	return deliveries, nil
}

// workerLoop processes queued webhook jobs concurrently.
func (e *WebhookEngine) workerLoop() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case job, ok := <-e.queue:
			if !ok {
				return
			}
			e.executeDelivery(job)
			e.inFlight.Done()
		}
	}
}

// executeDelivery sends the signed HTTP POST notification to the destination URL.
func (e *WebhookEngine) executeDelivery(job deliveryJob) {
	sigHeader, tsStr := e.signer.Sign(job.sub.Secret, job.payload, time.Now().UTC())

	req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, job.sub.URL, bytes.NewReader(job.payload))
	if err != nil {
		e.handleFailure(job, 0, err.Error(), 0)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderWebhookSignature, sigHeader)
	req.Header.Set(HeaderWebhookTimestamp, tsStr)
	req.Header.Set(HeaderWebhookDeliveryID, job.deliveryID)
	req.Header.Set(HeaderWebhookEventType, job.event.Type)
	req.Header.Set("User-Agent", HeaderWebhookUserAgent)

	start := time.Now()
	resp, err := e.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		e.handleFailure(job, 0, err.Error(), duration)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		e.handleSuccess(job, resp.StatusCode, duration)
	} else {
		e.handleFailure(job, resp.StatusCode, fmt.Sprintf("HTTP %d", resp.StatusCode), duration)
	}
}

func (e *WebhookEngine) handleSuccess(job deliveryJob, statusCode int, duration time.Duration) {
	now := time.Now().UTC()
	durMs := duration.Milliseconds()

	e.mu.Lock()
	for _, del := range e.deliveries {
		if del.ID == job.deliveryID {
			del.Status = "success"
			del.StatusCode = statusCode
			del.DurationMs = durMs
			del.DeliveredAt = &now
			del.Error = ""
			break
		}
	}
	e.mu.Unlock()

	if e.metrics != nil {
		e.metrics.RecordWebhookDelivery("success")
	}
}

func (e *WebhookEngine) handleFailure(job deliveryJob, statusCode int, reason string, duration time.Duration) {
	durMs := duration.Milliseconds()

	if job.attempt < e.cfg.MaxRetries {
		// Calculate exponential backoff: InitialBackoff * (Multiplier ^ (attempt - 1))
		multiplier := math.Pow(e.cfg.BackoffMultiplier, float64(job.attempt-1))
		backoff := time.Duration(float64(e.cfg.InitialBackoff) * multiplier)
		nextRetry := time.Now().UTC().Add(backoff)

		e.mu.Lock()
		for _, del := range e.deliveries {
			if del.ID == job.deliveryID {
				del.Status = "retrying"
				del.StatusCode = statusCode
				del.DurationMs = durMs
				del.Error = reason
				del.NextRetryAt = &nextRetry
				del.Attempt = job.attempt
				break
			}
		}
		e.mu.Unlock()

		if e.metrics != nil {
			e.metrics.RecordWebhookDelivery("retrying")
		}

		// Schedule exponential backoff retry
		e.inFlight.Add(1)
		time.AfterFunc(backoff, func() {
			defer e.inFlight.Done()
			select {
			case <-e.ctx.Done():
				return
			default:
				nextJob := job
				nextJob.attempt++
				e.inFlight.Add(1)
				select {
				case e.queue <- nextJob:
				default:
					e.inFlight.Done()
					// If queue is full, mark dead-letter
					e.moveToDeadLetter(job, statusCode, "retry queue saturated", durMs)
				}
			}
		})
	} else {
		// Max retry attempts exhausted -> route to Dead-Letter Queue (DLQ)
		e.moveToDeadLetter(job, statusCode, reason, durMs)
	}
}

func (e *WebhookEngine) moveToDeadLetter(job deliveryJob, statusCode int, reason string, durMs int64) {
	now := time.Now().UTC()

	var finalDel WebhookDelivery
	e.mu.Lock()
	for _, del := range e.deliveries {
		if del.ID == job.deliveryID {
			del.Status = "dead_letter"
			del.StatusCode = statusCode
			del.DurationMs = durMs
			del.Error = reason
			del.NextRetryAt = nil
			del.Attempt = job.attempt
			finalDel = *del
			break
		}
	}

	dlItem := &DeadLetterItem{
		Delivery:     finalDel,
		Event:        job.event,
		Subscription: job.sub,
		FailedAt:     now,
		Reason:       reason,
	}
	e.deadLetters = append(e.deadLetters, dlItem)
	if len(e.deadLetters) > 500 {
		e.deadLetters = e.deadLetters[len(e.deadLetters)-500:]
	}
	e.mu.Unlock()

	if e.metrics != nil {
		e.metrics.RecordWebhookDelivery("dead_letter")
		e.metrics.RecordWebhookDLQ()
	}
}

// ListDeliveries returns recent deliveries for a tenant.
func (e *WebhookEngine) ListDeliveries(tenantID string) []*WebhookDelivery {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*WebhookDelivery
	for _, del := range e.deliveries {
		if tenantID == "" || tenantID == "*" || del.TenantID == tenantID {
			cp := *del
			result = append(result, &cp)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result
}

// ListDeadLetters returns failed events currently in the Dead-Letter Queue.
func (e *WebhookEngine) ListDeadLetters(tenantID string) []*DeadLetterItem {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*DeadLetterItem
	for _, item := range e.deadLetters {
		if tenantID == "" || tenantID == "*" || item.Subscription.TenantID == tenantID {
			cp := *item
			result = append(result, &cp)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].FailedAt.After(result[j].FailedAt)
	})
	return result
}

// Redeliver re-queues a failed event from the Dead-Letter Queue for immediate delivery.
func (e *WebhookEngine) Redeliver(tenantID, deliveryID string) (*WebhookDelivery, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var targetItem *DeadLetterItem
	var targetIdx = -1

	for idx, item := range e.deadLetters {
		if item.Delivery.ID == deliveryID && (tenantID == "" || tenantID == "*" || item.Subscription.TenantID == tenantID) {
			targetItem = item
			targetIdx = idx
			break
		}
	}

	if targetItem == nil {
		return nil, ErrWebhookDeadLetterNotFound
	}

	now := time.Now().UTC()
	newDelID := "del_" + randomHex(12)
	payload, err := json.Marshal(targetItem.Event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event for redelivery: %w", err)
	}

	newDel := &WebhookDelivery{
		ID:             newDelID,
		SubscriptionID: targetItem.Subscription.ID,
		TenantID:       targetItem.Subscription.TenantID,
		EventID:        targetItem.Event.ID,
		EventType:      targetItem.Event.Type,
		URL:            targetItem.Subscription.URL,
		Attempt:        1,
		MaxAttempts:    e.cfg.MaxRetries,
		Status:         "pending",
		CreatedAt:      now,
	}
	e.deliveries = append(e.deliveries, newDel)

	// Remove from DLQ
	e.deadLetters = append(e.deadLetters[:targetIdx], e.deadLetters[targetIdx+1:]...)

	job := deliveryJob{
		sub:        targetItem.Subscription,
		event:      targetItem.Event,
		payload:    payload,
		attempt:    1,
		deliveryID: newDelID,
		createdAt:  now,
	}

	e.inFlight.Add(1)
	select {
	case e.queue <- job:
	default:
		newDel.Status = "dead_letter"
		newDel.Error = "redelivery queue saturated"
		e.inFlight.Done()
	}

	cp := *newDel
	return &cp, nil
}

// TestDeliveryResult encapsulates the synchronous test execution results for a webhook destination.
type TestDeliveryResult struct {
	URL          string            `json:"url"`
	EventType    string            `json:"event_type"`
	StatusCode   int               `json:"status_code"`
	Success      bool              `json:"success"`
	DurationMs   int64             `json:"duration_ms"`
	RequestBody  string            `json:"request_body"`
	ResponseBody string            `json:"response_body,omitempty"`
	Signature    string            `json:"signature"`
	Timestamp    string            `json:"timestamp"`
	HeadersSent  map[string]string `json:"headers_sent"`
	Error        string            `json:"error,omitempty"`
}

// TestWebhook tests delivery of a simulated event to an arbitrary endpoint URL with live HMAC verification.
func (e *WebhookEngine) TestWebhook(ctx context.Context, destURL, secret, eventType string, payload json.RawMessage) (*TestDeliveryResult, error) {
	trimmedURL := strings.TrimSpace(destURL)
	if trimmedURL == "" {
		return nil, errors.New("webhook destination url is required")
	}
	if err := ValidateSafeTargetURL(trimmedURL); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidWebhookURL, err.Error())
	}
	if eventType == "" {
		eventType = "test.webhook"
	}
	if secret == "" {
		secret = "whsec_test_" + randomHex(16)
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{"simulated": true, "message": "Aeitron Developer Portal Webhook Test Ping"}`)
	}

	testEvent := WebhookEvent{
		ID:        "evt_test_" + randomHex(12),
		Type:      eventType,
		TenantID:  "test_tenant",
		Timestamp: time.Now().UTC(),
		Data:      payload,
	}

	eventBytes, err := json.Marshal(testEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal test event: %w", err)
	}

	now := time.Now().UTC()
	sigHeader, tsHeader := e.signer.Sign(secret, eventBytes, now)
	deliveryID := "del_test_" + randomHex(12)

	headersSent := map[string]string{
		"Content-Type":          "application/json",
		"User-Agent":            HeaderWebhookUserAgent,
		HeaderWebhookSignature:  sigHeader,
		HeaderWebhookTimestamp:  tsHeader,
		HeaderWebhookDeliveryID: deliveryID,
		HeaderWebhookEventType:  eventType,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimmedURL, bytes.NewReader(eventBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	for k, v := range headersSent {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	durMs := time.Since(start).Milliseconds()

	result := &TestDeliveryResult{
		URL:         trimmedURL,
		EventType:   eventType,
		DurationMs:  durMs,
		RequestBody: string(eventBytes),
		Signature:   sigHeader,
		Timestamp:   tsHeader,
		HeadersSent: headersSent,
	}

	if err != nil {
		result.StatusCode = 0
		result.Success = false
		result.Error = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 300

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	result.ResponseBody = string(bodyBytes)

	return result, nil
}

// WaitIdle blocks until in-flight deliveries and scheduled retries have completed or timeout elapses.
func (e *WebhookEngine) WaitIdle(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		e.inFlight.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Close gracefully shuts down workers and cancels pending timers.
func (e *WebhookEngine) Close() {
	e.cancel()
}

func matchesEventPattern(pattern, eventType string) bool {
	pattern = strings.TrimSpace(pattern)
	eventType = strings.TrimSpace(eventType)
	if pattern == "*" || pattern == eventType {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		if strings.HasPrefix(eventType, prefix+".") {
			return true
		}
	}
	return false
}

func randomHex(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based hex if entropy fails
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
