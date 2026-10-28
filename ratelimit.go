package apigateway

import (
	"context"
	"hash/fnv"
	"math"
	"sync"
	"time"
)

const numShards = 64

type bucket struct {
	tokens     float64
	capacity   float64
	rate       float64
	lastRefill time.Time
	lastAccess time.Time
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// TokenBucketLimiter provides lock-striped, concurrent token-bucket rate limiting
// with optional distributed synchronization across cluster nodes.
type TokenBucketLimiter struct {
	shards       [numShards]*shard
	stateAdapter ClusterStateAdapter
	mu           sync.RWMutex
}

// NewTokenBucketLimiter initializes a sharded token bucket rate limiter.
func NewTokenBucketLimiter() *TokenBucketLimiter {
	limiter := &TokenBucketLimiter{}
	for i := 0; i < numShards; i++ {
		limiter.shards[i] = &shard{
			buckets: make(map[string]*bucket),
		}
	}
	return limiter
}

// SetStateAdapter configures the cluster state adapter for distributed multi-PoP rate limiting.
func (l *TokenBucketLimiter) SetStateAdapter(adapter ClusterStateAdapter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stateAdapter = adapter
}

// StateAdapter returns the configured cluster state adapter.
func (l *TokenBucketLimiter) StateAdapter() ClusterStateAdapter {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.stateAdapter
}

func (l *TokenBucketLimiter) getShard(key string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	idx := h.Sum32() % numShards
	return l.shards[idx]
}

// Allow evaluates if a request with the given key is permitted under rate and capacity.
// When a distributed cluster state adapter is configured, it synchronizes atomically
// with cluster nodes; otherwise (or on failure), it seamlessly evaluates local state.
func (l *TokenBucketLimiter) Allow(key string, rate float64, capacity int) (bool, int, time.Duration) {
	if rate <= 0 || capacity <= 0 {
		return true, capacity, 0
	}

	l.mu.RLock()
	adapter := l.stateAdapter
	l.mu.RUnlock()

	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		allowed, remaining, retryAfter, err := adapter.RateLimitAllow(ctx, key, rate, capacity)
		if err == nil {
			return allowed, remaining, retryAfter
		}
	}

	return l.allowLocal(key, rate, capacity)
}

func (l *TokenBucketLimiter) allowLocal(key string, rate float64, capacity int) (bool, int, time.Duration) {
	if rate <= 0 || capacity <= 0 {
		return true, capacity, 0
	}

	s := l.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	b, exists := s.buckets[key]
	if !exists {
		b = &bucket{
			tokens:     float64(capacity) - 1.0,
			capacity:   float64(capacity),
			rate:       rate,
			lastRefill: now,
			lastAccess: now,
		}
		s.buckets[key] = b
		return true, int(b.tokens), 0
	}

	b.lastAccess = now

	// Refill tokens based on elapsed duration
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now
	b.tokens = math.Min(b.capacity, b.tokens+(elapsed*rate))

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		remaining := int(math.Floor(b.tokens))
		return true, remaining, 0
	}

	// Rate limit exceeded: calculate retry-after duration
	missingTokens := 1.0 - b.tokens
	retryAfterSec := missingTokens / rate
	retryAfter := time.Duration(retryAfterSec * float64(time.Second))
	if retryAfter < 100*time.Millisecond {
		retryAfter = 100 * time.Millisecond
	}

	return false, 0, retryAfter
}

// CleanupStale removes buckets that have not been accessed for longer than ttl.
func (l *TokenBucketLimiter) CleanupStale(ttl time.Duration) int {
	now := time.Now().UTC()
	cleaned := 0
	for i := 0; i < numShards; i++ {
		s := l.shards[i]
		s.mu.Lock()
		for k, b := range s.buckets {
			if now.Sub(b.lastAccess) > ttl {
				delete(s.buckets, k)
				cleaned++
			}
		}
		s.mu.Unlock()
	}
	return cleaned
}
