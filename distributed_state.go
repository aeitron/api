package apigateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNilReply           = errors.New("redis: nil reply")
	ErrClosedPool         = errors.New("redis: connection pool closed")
	ErrClusterUnavailable = errors.New("cluster state adapter unavailable")
)

// ClusterStateAdapter defines the pluggable distributed synchronization interface for multi-PoP clusters.
type ClusterStateAdapter interface {
	Name() string
	Ping(ctx context.Context) error

	// Distributed Key-Value / Cache Operations
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	DeletePrefix(ctx context.Context, prefix string) (int, error)

	// Distributed Token-Bucket Rate Limiting
	RateLimitAllow(ctx context.Context, key string, rate float64, capacity int) (allowed bool, remaining int, retryAfter time.Duration, err error)

	// Distributed Idempotency Token Locking
	IdempotencyAcquire(ctx context.Context, key string, payloadHash string, ttl time.Duration) (acquired bool, existing *IdempotencyRecord, err error)
	IdempotencyComplete(ctx context.Context, key string, record *IdempotencyRecord, ttl time.Duration) error
	IdempotencyAbort(ctx context.Context, key string) error

	Close() error
}

// ---------------------------------------------------------------------------
// 1. In-Memory Adapter (Zero-Dependency Default)
// ---------------------------------------------------------------------------

// MemoryStateAdapter implements ClusterStateAdapter using high-performance lock-striped in-memory data structures.
type MemoryStateAdapter struct {
	mu          sync.RWMutex
	kvStore     map[string]memoryKVItem
	rateLimiter *TokenBucketLimiter
	idempStore  map[string]*IdempotencyRecord
}

type memoryKVItem struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryStateAdapter creates a local in-memory cluster state adapter.
func NewMemoryStateAdapter() *MemoryStateAdapter {
	adapter := &MemoryStateAdapter{
		kvStore:     make(map[string]memoryKVItem),
		rateLimiter: NewTokenBucketLimiter(),
		idempStore:  make(map[string]*IdempotencyRecord),
	}
	return adapter
}

func (m *MemoryStateAdapter) Name() string {
	return "memory"
}

func (m *MemoryStateAdapter) Ping(ctx context.Context) error {
	return nil
}

func (m *MemoryStateAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.kvStore[key]
	if !exists {
		return nil, ErrNilReply
	}
	if !item.expiresAt.IsZero() && time.Now().UTC().After(item.expiresAt) {
		return nil, ErrNilReply
	}
	cp := make([]byte, len(item.data))
	copy(cp, item.data)
	return cp, nil
}

func (m *MemoryStateAdapter) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().UTC().Add(ttl)
	}
	cp := make([]byte, len(val))
	copy(cp, val)
	m.kvStore[key] = memoryKVItem{
		data:      cp,
		expiresAt: exp,
	}
	return nil
}

func (m *MemoryStateAdapter) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.kvStore, key)
	return nil
}

func (m *MemoryStateAdapter) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	deleted := 0
	for k := range m.kvStore {
		if strings.HasPrefix(k, prefix) {
			delete(m.kvStore, k)
			deleted++
		}
	}
	return deleted, nil
}

func (m *MemoryStateAdapter) RateLimitAllow(ctx context.Context, key string, rate float64, capacity int) (bool, int, time.Duration, error) {
	allowed, remaining, retryAfter := m.rateLimiter.allowLocal(key, rate, capacity)
	return allowed, remaining, retryAfter, nil
}

func (m *MemoryStateAdapter) IdempotencyAcquire(ctx context.Context, key string, payloadHash string, ttl time.Duration) (bool, *IdempotencyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	if rec, exists := m.idempStore[key]; exists {
		if now.Before(rec.ExpiresAt) {
			return false, rec, nil
		}
		delete(m.idempStore, key)
	}

	newRec := &IdempotencyRecord{
		Key:         key,
		RequestHash: payloadHash,
		State:       "IN_FLIGHT",
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	m.idempStore[key] = newRec
	return true, newRec, nil
}

func (m *MemoryStateAdapter) IdempotencyComplete(ctx context.Context, key string, record *IdempotencyRecord, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	record.State = "COMPLETED"
	record.ExpiresAt = time.Now().UTC().Add(ttl)
	m.idempStore[key] = record
	return nil
}

func (m *MemoryStateAdapter) IdempotencyAbort(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.idempStore, key)
	return nil
}

func (m *MemoryStateAdapter) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// 2. Redis & KeyDB Cluster State Adapter (Standard Library RESP Client)
// ---------------------------------------------------------------------------

// RedisConfig tunes connection pooling, TLS security, and network timeouts.
type RedisConfig struct {
	Addr        string
	Password    string
	DB          int
	PoolSize    int
	DialTimeout time.Duration
	ReadTimeout time.Duration
	UseTLS      bool
	TLSConfig   *tls.Config
	FailClosed  bool
}

// DefaultRedisConfig returns resilient production defaults.
func DefaultRedisConfig(rawAddr string) RedisConfig {
	return RedisConfig{
		Addr:        rawAddr,
		PoolSize:    20,
		DialTimeout: 2 * time.Second,
		ReadTimeout: 1 * time.Second,
	}
}

// RedisStateAdapter communicates via standard REdis Serialization Protocol (RESP)
// with zero external dependencies, providing automated connection pooling and fail-open resilience.
type RedisStateAdapter struct {
	cfg       RedisConfig
	fallback  *MemoryStateAdapter
	pool      chan *redisConn
	closed    atomic.Bool
	connCount atomic.Int32
	metrics   *MetricsCollector
}

type redisConn struct {
	netConn net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
}

// NewRedisStateAdapter parses REDIS_URL and connects to Redis or KeyDB cluster nodes.
func NewRedisStateAdapter(redisURL string, cfg RedisConfig, metrics *MetricsCollector) (*RedisStateAdapter, error) {
	parsedAddr, password, db, useTLS, err := parseRedisURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url: %w", err)
	}

	cfg.Addr = parsedAddr
	if useTLS {
		cfg.UseTLS = true
	}
	if password != "" {
		cfg.Password = password
	}
	if db != 0 {
		cfg.DB = db
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 20
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 2 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 1 * time.Second
	}
	if strings.EqualFold(os.Getenv("AEITRON_CLUSTER_FAIL_CLOSED"), "true") || strings.EqualFold(os.Getenv("AEITRON_CLUSTER_FAIL_CLOSED"), "1") {
		cfg.FailClosed = true
	}

	adapter := &RedisStateAdapter{
		cfg:      cfg,
		fallback: NewMemoryStateAdapter(),
		pool:     make(chan *redisConn, cfg.PoolSize),
		metrics:  metrics,
	}

	// Pre-flight ping connectivity probe
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := adapter.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping redis server at %s: %w", cfg.Addr, err)
	}

	return adapter, nil
}

func parseRedisURL(raw string) (addr string, password string, db int, useTLS bool, err error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "redis://") && !strings.HasPrefix(raw, "rediss://") {
		// Bare host:port format
		return raw, "", 0, false, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, false, err
	}

	if strings.EqualFold(u.Scheme, "rediss") {
		useTLS = true
	}

	addr = u.Host
	if !strings.Contains(addr, ":") {
		if useTLS {
			addr += ":6380"
		} else {
			addr += ":6379"
		}
	}

	if u.User != nil {
		p, exists := u.User.Password()
		if exists {
			password = p
		} else {
			password = u.User.Username()
		}
	}

	path := strings.TrimPrefix(u.Path, "/")
	if path != "" {
		if dbVal, parseErr := strconv.Atoi(path); parseErr == nil {
			db = dbVal
		}
	}

	return addr, password, db, useTLS, nil
}

func (r *RedisStateAdapter) Name() string {
	return "redis"
}

func (r *RedisStateAdapter) getConn(ctx context.Context) (*redisConn, error) {
	if r.closed.Load() {
		return nil, ErrClosedPool
	}

	select {
	case conn := <-r.pool:
		return conn, nil
	default:
	}

	if r.connCount.Load() < int32(r.cfg.PoolSize) {
		r.connCount.Add(1)
		d := net.Dialer{Timeout: r.cfg.DialTimeout}
		var raw net.Conn
		var err error

		if r.cfg.UseTLS {
			tlsConf := r.cfg.TLSConfig
			if tlsConf == nil {
				host, _, splitErr := net.SplitHostPort(r.cfg.Addr)
				if splitErr != nil {
					host = r.cfg.Addr
				}
				tlsConf = &tls.Config{
					ServerName: host,
					MinVersion: tls.VersionTLS12,
				}
			}
			tlsDialer := &tls.Dialer{
				NetDialer: &d,
				Config:    tlsConf,
			}
			raw, err = tlsDialer.DialContext(ctx, "tcp", r.cfg.Addr)
		} else {
			raw, err = d.DialContext(ctx, "tcp", r.cfg.Addr)
		}

		if err != nil {
			r.connCount.Add(-1)
			return nil, err
		}

		conn := &redisConn{
			netConn: raw,
			reader:  bufio.NewReader(raw),
			writer:  bufio.NewWriter(raw),
		}

		// Optional Authentication
		if r.cfg.Password != "" {
			if err := r.auth(conn, r.cfg.Password); err != nil {
				_ = raw.Close()
				r.connCount.Add(-1)
				return nil, err
			}
		}
		// Optional DB Select
		if r.cfg.DB != 0 {
			if err := r.selectDB(conn, r.cfg.DB); err != nil {
				_ = raw.Close()
				r.connCount.Add(-1)
				return nil, err
			}
		}

		return conn, nil
	}

	// Wait for available connection in pool
	select {
	case conn := <-r.pool:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *RedisStateAdapter) putConn(conn *redisConn, err error) {
	if conn == nil {
		return
	}
	if err != nil || r.closed.Load() {
		_ = conn.netConn.Close()
		r.connCount.Add(-1)
		return
	}

	select {
	case r.pool <- conn:
	default:
		_ = conn.netConn.Close()
		r.connCount.Add(-1)
	}
}

func (r *RedisStateAdapter) auth(c *redisConn, password string) error {
	if err := writeRESPCommand(c.writer, "AUTH", password); err != nil {
		return err
	}
	reply, err := readRESPReply(c.reader)
	if err != nil {
		return err
	}
	if str, ok := reply.(string); !ok || !strings.EqualFold(str, "OK") {
		return fmt.Errorf("auth rejected: %v", reply)
	}
	return nil
}

func (r *RedisStateAdapter) selectDB(c *redisConn, db int) error {
	if err := writeRESPCommand(c.writer, "SELECT", strconv.Itoa(db)); err != nil {
		return err
	}
	reply, err := readRESPReply(c.reader)
	if err != nil {
		return err
	}
	if str, ok := reply.(string); !ok || !strings.EqualFold(str, "OK") {
		return fmt.Errorf("select db rejected: %v", reply)
	}
	return nil
}

func (r *RedisStateAdapter) Ping(ctx context.Context) error {
	conn, err := r.getConn(ctx)
	if err != nil {
		return err
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	err = writeRESPCommand(conn.writer, "PING")
	if err != nil {
		r.putConn(conn, err)
		return err
	}

	reply, err := readRESPReply(conn.reader)
	r.putConn(conn, err)
	if err != nil {
		return err
	}

	if str, ok := reply.(string); ok && strings.EqualFold(str, "PONG") {
		return nil
	}
	return fmt.Errorf("unexpected ping reply: %v", reply)
}

func (r *RedisStateAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	conn, err := r.getConn(ctx)
	if err != nil {
		if r.metrics != nil {
			r.metrics.RecordClusterOp("get_fallback")
		}
		if r.cfg.FailClosed {
			return nil, fmt.Errorf("%w: failed to connect to redis", ErrClusterUnavailable)
		}
		return r.fallback.Get(ctx, key)
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	err = writeRESPCommand(conn.writer, "GET", key)
	if err != nil {
		r.putConn(conn, err)
		if r.cfg.FailClosed {
			return nil, fmt.Errorf("%w: write command failed", ErrClusterUnavailable)
		}
		return r.fallback.Get(ctx, key)
	}

	reply, err := readRESPReply(conn.reader)
	r.putConn(conn, err)
	if err != nil {
		if r.cfg.FailClosed {
			return nil, fmt.Errorf("%w: read reply failed", ErrClusterUnavailable)
		}
		return r.fallback.Get(ctx, key)
	}

	if reply == nil {
		return nil, ErrNilReply
	}

	if r.metrics != nil {
		r.metrics.RecordClusterOp("get_hit")
	}

	switch v := reply.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return []byte(fmt.Sprintf("%v", v)), nil
	}
}

func (r *RedisStateAdapter) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	if !r.cfg.FailClosed {
		_ = r.fallback.Set(ctx, key, val, ttl)
	}

	conn, err := r.getConn(ctx)
	if err != nil {
		if r.metrics != nil {
			r.metrics.RecordClusterOp("set_fallback")
		}
		if r.cfg.FailClosed {
			return fmt.Errorf("%w: failed to connect to redis", ErrClusterUnavailable)
		}
		return nil // Fail-open: successfully updated local memory
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	var cmdErr error
	if ttl > 0 {
		sec := int(math.Ceil(ttl.Seconds()))
		if sec < 1 {
			sec = 1
		}
		cmdErr = writeRESPCommand(conn.writer, "SET", key, string(val), "EX", strconv.Itoa(sec))
	} else {
		cmdErr = writeRESPCommand(conn.writer, "SET", key, string(val))
	}

	if cmdErr != nil {
		r.putConn(conn, cmdErr)
		if r.cfg.FailClosed {
			return fmt.Errorf("%w: failed to set redis key", ErrClusterUnavailable)
		}
		return nil // Fail-open
	}

	_, readErr := readRESPReply(conn.reader)
	r.putConn(conn, readErr)
	if readErr != nil && r.cfg.FailClosed {
		return fmt.Errorf("%w: failed to read set reply", ErrClusterUnavailable)
	}

	if r.metrics != nil {
		r.metrics.RecordClusterOp("set_success")
	}
	return nil
}

func (r *RedisStateAdapter) Delete(ctx context.Context, key string) error {
	if !r.cfg.FailClosed {
		_ = r.fallback.Delete(ctx, key)
	}

	conn, err := r.getConn(ctx)
	if err != nil {
		if r.cfg.FailClosed {
			return fmt.Errorf("%w: failed to connect to redis", ErrClusterUnavailable)
		}
		return nil
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	err = writeRESPCommand(conn.writer, "DEL", key)
	if err != nil {
		r.putConn(conn, err)
		if r.cfg.FailClosed {
			return fmt.Errorf("%w: failed to delete redis key", ErrClusterUnavailable)
		}
		return nil
	}
	_, readErr := readRESPReply(conn.reader)
	r.putConn(conn, readErr)
	if readErr != nil && r.cfg.FailClosed {
		return fmt.Errorf("%w: failed to read delete reply", ErrClusterUnavailable)
	}
	return nil
}

func (r *RedisStateAdapter) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	if !r.cfg.FailClosed {
		_, _ = r.fallback.DeletePrefix(ctx, prefix)
	}

	conn, err := r.getConn(ctx)
	if err != nil {
		if r.cfg.FailClosed {
			return 0, fmt.Errorf("%w: failed to connect to redis", ErrClusterUnavailable)
		}
		return r.fallback.DeletePrefix(ctx, prefix)
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	err = writeRESPCommand(conn.writer, "KEYS", prefix+"*")
	if err != nil {
		r.putConn(conn, err)
		if r.cfg.FailClosed {
			return 0, fmt.Errorf("%w: failed to query keys in redis", ErrClusterUnavailable)
		}
		return r.fallback.DeletePrefix(ctx, prefix)
	}

	reply, readErr := readRESPReply(conn.reader)
	if readErr != nil || reply == nil {
		r.putConn(conn, readErr)
		if r.cfg.FailClosed {
			return 0, fmt.Errorf("%w: failed to read keys reply", ErrClusterUnavailable)
		}
		return r.fallback.DeletePrefix(ctx, prefix)
	}

	keysList, ok := reply.([]interface{})
	if !ok || len(keysList) == 0 {
		r.putConn(conn, nil)
		return 0, nil
	}

	delArgs := make([]string, 0, len(keysList)+1)
	delArgs = append(delArgs, "DEL")
	for _, k := range keysList {
		if s, isStr := k.(string); isStr {
			delArgs = append(delArgs, s)
		}
	}

	deletedCount := 0
	if len(delArgs) > 1 {
		delCmdErr := writeRESPCommand(conn.writer, delArgs...)
		if delCmdErr != nil {
			r.putConn(conn, delCmdErr)
			if r.cfg.FailClosed {
				return 0, fmt.Errorf("%w: failed to execute del command in redis", ErrClusterUnavailable)
			}
			return r.fallback.DeletePrefix(ctx, prefix)
		}
		delReply, delReadErr := readRESPReply(conn.reader)
		r.putConn(conn, delReadErr)
		if delReadErr != nil && r.cfg.FailClosed {
			return 0, fmt.Errorf("%w: failed to read del reply", ErrClusterUnavailable)
		}
		if n, isInt := delReply.(int64); isInt {
			deletedCount = int(n)
		} else {
			deletedCount = len(delArgs) - 1
		}
	} else {
		r.putConn(conn, nil)
	}

	return deletedCount, nil
}

// RateLimitAllow atomically calculates token bucket replenishment via Redis or transparently falls back.
func (r *RedisStateAdapter) RateLimitAllow(ctx context.Context, key string, rate float64, capacity int) (bool, int, time.Duration, error) {
	conn, err := r.getConn(ctx)
	if err != nil {
		// Fail-open: fall back to ultra-fast local in-memory token bucket unless fail-closed is configured
		if r.metrics != nil {
			r.metrics.RecordClusterOp("ratelimit_fallback")
		}
		if r.cfg.FailClosed {
			return false, 0, 1 * time.Second, fmt.Errorf("%w: failed to connect to redis in fail-closed mode", ErrClusterUnavailable)
		}
		return r.fallback.RateLimitAllow(ctx, key, rate, capacity)
	}

	now := time.Now().UTC().UnixNano()
	redisKey := "aeitron:ratelimit:" + key

	// Lua script for atomic token-bucket refill across distributed instances
	luaScript := `local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])
if not tokens then
    tokens = capacity - 1.0
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(capacity / rate) * 2 + 10)
    return {1, math.floor(tokens), 0}
end
local elapsed = (now - last_refill) / 1000000000.0
tokens = math.min(capacity, tokens + (elapsed * rate))
if tokens >= 1.0 then
    tokens = tokens - 1.0
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(capacity / rate) * 2 + 10)
    return {1, math.floor(tokens), 0}
else
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    local missing = 1.0 - tokens
    local retry_ms = math.ceil((missing / rate) * 1000.0)
    return {0, 0, retry_ms}
end`

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	cmdErr := writeRESPCommand(conn.writer, "EVAL", luaScript, "1", redisKey,
		fmt.Sprintf("%.4f", rate), strconv.Itoa(capacity), strconv.FormatInt(now, 10))
	if cmdErr != nil {
		r.putConn(conn, cmdErr)
		if r.cfg.FailClosed {
			return false, 0, 1 * time.Second, fmt.Errorf("%w: eval sha failed", ErrClusterUnavailable)
		}
		return r.fallback.RateLimitAllow(ctx, key, rate, capacity)
	}

	reply, readErr := readRESPReply(conn.reader)
	r.putConn(conn, readErr)
	if readErr != nil {
		if r.cfg.FailClosed {
			return false, 0, 1 * time.Second, fmt.Errorf("%w: read redis reply failed", ErrClusterUnavailable)
		}
		return r.fallback.RateLimitAllow(ctx, key, rate, capacity)
	}

	arr, ok := reply.([]interface{})
	if !ok || len(arr) < 3 {
		if r.cfg.FailClosed {
			return false, 0, 1 * time.Second, fmt.Errorf("%w: invalid redis reply shape", ErrClusterUnavailable)
		}
		return r.fallback.RateLimitAllow(ctx, key, rate, capacity)
	}

	allowedInt, _ := toInt64(arr[0])
	remainingInt, _ := toInt64(arr[1])
	retryMsInt, _ := toInt64(arr[2])

	allowed := allowedInt == 1
	retryAfter := time.Duration(retryMsInt) * time.Millisecond

	if r.metrics != nil {
		r.metrics.RecordClusterOp("ratelimit_cluster")
	}

	return allowed, int(remainingInt), retryAfter, nil
}

// IdempotencyAcquire atomically acquires a distributed idempotency token via SET NX PX.
func (r *RedisStateAdapter) IdempotencyAcquire(ctx context.Context, key string, payloadHash string, ttl time.Duration) (bool, *IdempotencyRecord, error) {
	conn, err := r.getConn(ctx)
	if err != nil {
		if r.cfg.FailClosed {
			return false, nil, fmt.Errorf("%w: failed to connect to redis in fail-closed mode", ErrClusterUnavailable)
		}
		return r.fallback.IdempotencyAcquire(ctx, key, payloadHash, ttl)
	}

	redisKey := "aeitron:idemp:" + key
	now := time.Now().UTC()
	initRecord := IdempotencyRecord{
		Key:         key,
		RequestHash: payloadHash,
		State:       "IN_FLIGHT",
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	bytesVal, _ := json.Marshal(initRecord)

	ttlMs := int(ttl.Milliseconds())
	if ttlMs <= 0 {
		ttlMs = 86400000 // 24 hours
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	cmdErr := writeRESPCommand(conn.writer, "SET", redisKey, string(bytesVal), "NX", "PX", strconv.Itoa(ttlMs))
	if cmdErr != nil {
		r.putConn(conn, cmdErr)
		if r.cfg.FailClosed {
			return false, nil, fmt.Errorf("%w: idempotency acquire failed", ErrClusterUnavailable)
		}
		return r.fallback.IdempotencyAcquire(ctx, key, payloadHash, ttl)
	}

	reply, readErr := readRESPReply(conn.reader)
	if readErr != nil {
		r.putConn(conn, readErr)
		if r.cfg.FailClosed {
			return false, nil, fmt.Errorf("%w: read idempotency reply failed", ErrClusterUnavailable)
		}
		return r.fallback.IdempotencyAcquire(ctx, key, payloadHash, ttl)
	}

	if replyStr, ok := reply.(string); ok && strings.EqualFold(replyStr, "OK") {
		r.putConn(conn, nil)
		if r.metrics != nil {
			r.metrics.RecordClusterOp("idemp_acquire_new")
		}
		return true, &initRecord, nil
	}

	// Key already exists in Redis: fetch existing record for replay check
	cmdErr = writeRESPCommand(conn.writer, "GET", redisKey)
	if cmdErr != nil {
		r.putConn(conn, cmdErr)
		if r.cfg.FailClosed {
			return false, nil, fmt.Errorf("%w: failed to read existing idempotency record", ErrClusterUnavailable)
		}
		return r.fallback.IdempotencyAcquire(ctx, key, payloadHash, ttl)
	}

	getReply, getErr := readRESPReply(conn.reader)
	r.putConn(conn, getErr)
	if getErr != nil || getReply == nil {
		if r.cfg.FailClosed {
			return false, nil, fmt.Errorf("%w: failed to retrieve existing idempotency record reply", ErrClusterUnavailable)
		}
		return r.fallback.IdempotencyAcquire(ctx, key, payloadHash, ttl)
	}

	var existingRec IdempotencyRecord
	if rawStr, isStr := getReply.(string); isStr {
		_ = json.Unmarshal([]byte(rawStr), &existingRec)
	}

	if r.metrics != nil {
		r.metrics.RecordClusterOp("idemp_replay_cluster")
	}

	return false, &existingRec, nil
}

// IdempotencyComplete stores the final completed mutation state in Redis.
func (r *RedisStateAdapter) IdempotencyComplete(ctx context.Context, key string, record *IdempotencyRecord, ttl time.Duration) error {
	if !r.cfg.FailClosed {
		_ = r.fallback.IdempotencyComplete(ctx, key, record, ttl)
	}

	conn, err := r.getConn(ctx)
	if err != nil {
		if r.cfg.FailClosed {
			return fmt.Errorf("%w: failed to connect to redis in fail-closed mode", ErrClusterUnavailable)
		}
		return nil
	}

	redisKey := "aeitron:idemp:" + key
	record.State = "COMPLETED"
	bytesVal, _ := json.Marshal(record)
	sec := int(math.Ceil(ttl.Seconds()))
	if sec <= 0 {
		sec = 86400
	}

	_ = conn.netConn.SetDeadline(time.Now().Add(r.cfg.ReadTimeout))
	cmdErr := writeRESPCommand(conn.writer, "SET", redisKey, string(bytesVal), "EX", strconv.Itoa(sec))
	if cmdErr != nil {
		r.putConn(conn, cmdErr)
		if r.cfg.FailClosed {
			return fmt.Errorf("%w: failed to store completed idempotency state", ErrClusterUnavailable)
		}
		return nil
	}

	_, readErr := readRESPReply(conn.reader)
	r.putConn(conn, readErr)
	if readErr != nil && r.cfg.FailClosed {
		return fmt.Errorf("%w: failed to read completed idempotency reply", ErrClusterUnavailable)
	}
	return nil
}

// IdempotencyAbort releases the lock upon server errors.
func (r *RedisStateAdapter) IdempotencyAbort(ctx context.Context, key string) error {
	if !r.cfg.FailClosed {
		_ = r.fallback.IdempotencyAbort(ctx, key)
	}
	return r.Delete(ctx, "aeitron:idemp:"+key)
}

func (r *RedisStateAdapter) Close() error {
	if r.closed.Swap(true) {
		return nil
	}
	close(r.pool)
	for conn := range r.pool {
		_ = conn.netConn.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// 3. Low-Level REdis Serialization Protocol (RESP) Engine
// ---------------------------------------------------------------------------

func writeRESPCommand(w *bufio.Writer, args ...string) error {
	if err := w.WriteByte('*'); err != nil {
		return err
	}
	if _, err := w.WriteString(strconv.Itoa(len(args))); err != nil {
		return err
	}
	if _, err := w.WriteString("\r\n"); err != nil {
		return err
	}

	for _, arg := range args {
		if err := w.WriteByte('$'); err != nil {
			return err
		}
		if _, err := w.WriteString(strconv.Itoa(len(arg))); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
		if _, err := w.WriteString(arg); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func readRESPReply(r *bufio.Reader) (interface{}, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("empty RESP line")
	}

	prefix := line[0]
	payload := line[1:]

	switch prefix {
	case '+': // Simple string
		return payload, nil
	case '-': // Error
		return nil, fmt.Errorf("redis error: %s", payload)
	case ':': // Integer
		return strconv.ParseInt(payload, 10, 64)
	case '$': // Bulk string
		length, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if length == -1 {
			return nil, nil // Null bulk string
		}
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:length]), nil
	case '*': // Array
		count, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if count == -1 {
			return nil, nil // Null array
		}
		items := make([]interface{}, count)
		for i := 0; i < count; i++ {
			item, err := readRESPReply(r)
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unsupported RESP reply type '%c'", prefix)
	}
}

func toInt64(val interface{}) (int64, bool) {
	switch v := val.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		i, err := strconv.ParseInt(v, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}
