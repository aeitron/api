package apigateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CacheEntry represents an RFC 9111 compliant cached HTTP response.
type CacheEntry struct {
	Key          string            `json:"key"`
	Path         string            `json:"path"`
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Body         []byte            `json:"body"`
	GzipBody     []byte            `json:"gzip_body,omitempty"`
	CachedAt     time.Time         `json:"cached_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	TTL          time.Duration     `json:"ttl"`
	ETag         string            `json:"etag"`
	LastModified string            `json:"last_modified"`
}

// AgeSeconds returns the current age of the cached entry in seconds (RFC 9111 Section 4.2.3).
func (e *CacheEntry) AgeSeconds() int {
	age := int(time.Since(e.CachedAt).Seconds())
	if age < 0 {
		return 0
	}
	return age
}

// RFC9111CacheEngine manages high-performance in-memory caching with ETag generation,
// 304 Not Modified validation, and mutation-based cache invalidation.
type RFC9111CacheEngine struct {
	mu           sync.RWMutex
	entries      map[string]*CacheEntry
	maxEntries   int
	maxBytes     int64
	currentBytes int64
	stateAdapter ClusterStateAdapter
}

// NewRFC9111CacheEngine creates a new RFC 9111 edge caching engine with bounded capacity.
func NewRFC9111CacheEngine(maxEntries int, maxBytes int64) *RFC9111CacheEngine {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if maxBytes <= 0 {
		maxBytes = 64 * 1024 * 1024 // 64 MB default ceiling
	}
	engine := &RFC9111CacheEngine{
		entries:    make(map[string]*CacheEntry),
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
	}
	go engine.reaperWorker()
	return engine
}

// SetStateAdapter configures the cluster state adapter for multi-tier L1 (memory) + L2 (Redis) caching.
func (c *RFC9111CacheEngine) SetStateAdapter(adapter ClusterStateAdapter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateAdapter = adapter
}

// StateAdapter returns the configured cluster state adapter.
func (c *RFC9111CacheEngine) StateAdapter() ClusterStateAdapter {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stateAdapter
}

// NormalizeKey generates a deterministic, RFC 9111 canonical cache key.
// Query parameters are sorted alphabetically so `?b=2&a=1` and `?a=1&b=2` share the exact same key.
func (c *RFC9111CacheEngine) NormalizeKey(tenantScope, method, rawPath, rawQuery string) string {
	method = strings.ToUpper(method)
	rawPath = "/" + strings.TrimPrefix(rawPath, "/")
	if tenantScope == "" {
		tenantScope = "public"
	}

	if rawQuery == "" {
		return fmt.Sprintf("%s:%s:%s", tenantScope, method, rawPath)
	}

	parsed, err := url.ParseQuery(rawQuery)
	if err != nil || len(parsed) == 0 {
		return fmt.Sprintf("%s:%s:%s?%s", tenantScope, method, rawPath, rawQuery)
	}

	keys := make([]string, 0, len(parsed))
	for k := range parsed {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		values := parsed[k]
		sort.Strings(values)
		for j, v := range values {
			if i > 0 || j > 0 {
				sb.WriteString("&")
			}
			sb.WriteString(url.QueryEscape(k))
			sb.WriteString("=")
			sb.WriteString(url.QueryEscape(v))
		}
	}

	return fmt.Sprintf("%s:%s:%s?%s", tenantScope, method, rawPath, sb.String())
}

// GenerateETag computes an RFC 9111 compliant weak ETag from response body bytes.
func GenerateETag(body []byte) string {
	h := sha256.Sum256(body)
	return fmt.Sprintf(`W/"aei_%s"`, hex.EncodeToString(h[:10]))
}

// IsRequestCacheable verifies RFC 9111 request cacheability rules.
// Only GET and HEAD methods can be cached. Requests with `no-store` or `no-cache` are bypassed.
func (c *RFC9111CacheEngine) IsRequestCacheable(r *http.Request) (cacheable bool, bypassLookup bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false, false
	}

	cc := strings.ToLower(r.Header.Get("Cache-Control"))
	pragma := strings.ToLower(r.Header.Get("Pragma"))

	if strings.Contains(cc, "no-store") {
		return false, false
	}
	if strings.Contains(cc, "no-cache") || strings.Contains(pragma, "no-cache") || strings.Contains(cc, "max-age=0") {
		return true, true // Cacheable to store after upstream returns, but bypass existing lookup
	}

	return true, false
}

// IsResponseCacheable verifies RFC 9111 Section 3 response cacheability rules.
func (c *RFC9111CacheEngine) IsResponseCacheable(statusCode int, header http.Header) bool {
	// Only successful read responses or explicit redirects are cacheable at gateway
	if statusCode != http.StatusOK && statusCode != http.StatusNonAuthoritativeInfo &&
		statusCode != http.StatusNoContent && statusCode != http.StatusMovedPermanently {
		return false
	}

	cc := strings.ToLower(header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}

	return true
}

// ParseUpstreamTTL extracts the TTL duration from upstream Cache-Control headers,
// prioritizing `s-maxage` (shared cache RFC 9111 standard) over `max-age`.
func (c *RFC9111CacheEngine) ParseUpstreamTTL(header http.Header, defaultTTL time.Duration) time.Duration {
	cc := header.Get("Cache-Control")
	if cc != "" {
		parts := strings.Split(cc, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "s-maxage=") {
				secsStr := strings.TrimPrefix(part, "s-maxage=")
				secsStr = strings.TrimPrefix(secsStr, "S-MAXAGE=")
				if s, err := strconv.Atoi(strings.Trim(secsStr, `"`)); err == nil && s >= 0 {
					return time.Duration(s) * time.Second
				}
			}
		}
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "max-age=") {
				secsStr := strings.TrimPrefix(part, "max-age=")
				secsStr = strings.TrimPrefix(secsStr, "MAX-AGE=")
				if s, err := strconv.Atoi(strings.Trim(secsStr, `"`)); err == nil && s >= 0 {
					return time.Duration(s) * time.Second
				}
			}
		}
	}

	return defaultTTL
}

// Lookup searches for a fresh, non-expired cache entry.
// Checks high-performance L1 in-memory cache first; on a miss, queries L2 distributed cluster cache.
func (c *RFC9111CacheEngine) Lookup(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	adapter := c.stateAdapter
	c.mu.RUnlock()

	now := time.Now().UTC()
	if exists && !now.After(entry.ExpiresAt) {
		return entry, true
	}

	// L2 Distributed Cache Check (Redis / KeyDB)
	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		data, err := adapter.Get(ctx, "cache:"+key)
		cancel()
		if err == nil && len(data) > 0 {
			var l2Entry CacheEntry
			if err := json.Unmarshal(data, &l2Entry); err == nil {
				if !now.After(l2Entry.ExpiresAt) {
					// Populate local L1 cache
					c.mu.Lock()
					c.entries[key] = &l2Entry
					c.mu.Unlock()
					return &l2Entry, true
				}
			}
		}
	}

	return nil, false
}

// Store caches a response, generating an ETag if not provided, pre-compressing compressible bodies, and recording RFC 1123 Last-Modified.
func (c *RFC9111CacheEngine) Store(key, path string, statusCode int, header http.Header, body []byte, ttl time.Duration) *CacheEntry {
	if ttl <= 0 {
		return nil
	}

	now := time.Now().UTC()
	etag := header.Get("ETag")
	if etag == "" {
		etag = GenerateETag(body)
	}

	lastMod := header.Get("Last-Modified")
	if lastMod == "" {
		lastMod = now.Format(http.TimeFormat)
	}

	cachedHeaders := make(map[string]string)
	if ctype := header.Get("Content-Type"); ctype != "" {
		cachedHeaders["Content-Type"] = ctype
	}

	var gzipBody []byte
	if IsCompressibleContentType(cachedHeaders["Content-Type"]) && len(body) >= DefaultMinCompressLength {
		if gz, err := CompressGzip(body); err == nil && len(gz) < len(body) {
			gzipBody = gz
		}
	}

	entry := &CacheEntry{
		Key:          key,
		Path:         path,
		StatusCode:   statusCode,
		Headers:      cachedHeaders,
		Body:         make([]byte, len(body)),
		GzipBody:     gzipBody,
		CachedAt:     now,
		ExpiresAt:    now.Add(ttl),
		TTL:          ttl,
		ETag:         etag,
		LastModified: lastMod,
	}
	copy(entry.Body, body)

	entryBytes := int64(len(key) + len(body) + len(gzipBody) + 256)

	c.mu.Lock()
	// Enforce memory limit: evict oldest if exceeding capacity
	if len(c.entries) >= c.maxEntries || (c.currentBytes+entryBytes) > c.maxBytes {
		c.evictOldestLocked()
	}

	if existing, found := c.entries[key]; found {
		c.currentBytes -= int64(len(existing.Key) + len(existing.Body) + len(existing.GzipBody) + 256)
	}

	c.entries[key] = entry
	c.currentBytes += entryBytes
	adapter := c.stateAdapter
	c.mu.Unlock()

	// Propagate to L2 distributed cache if configured
	if adapter != nil && adapter.Name() != "memory" {
		if data, err := json.Marshal(entry); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			_ = adapter.Set(ctx, "cache:"+key, data, ttl)
			cancel()
		}
	}

	return entry
}

// ValidateConditional checks if the client sent `If-None-Match` or `If-Modified-Since`
// and returns true if the cached entry has NOT been modified (eligible for 304 Not Modified).
func (c *RFC9111CacheEngine) ValidateConditional(r *http.Request, entry *CacheEntry) bool {
	if entry == nil {
		return false
	}

	// 1. If-None-Match check (RFC 9111 Section 3.2.1 - Highest precedence)
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		return matchETags(ifNoneMatch, entry.ETag)
	}

	// 2. If-Modified-Since check (RFC 9111 Section 3.2.4 - Only when If-None-Match absent)
	ifModSince := r.Header.Get("If-Modified-Since")
	if ifModSince != "" {
		parsedTime, err := http.ParseTime(ifModSince)
		if err == nil {
			// RFC 9111: If cached representation was not modified since parsedTime, return 304
			if !entry.CachedAt.After(parsedTime.Add(1 * time.Second)) {
				return true
			}
		}
	}

	return false
}

// matchETags performs RFC 9111 weak ETag comparison against comma-separated header candidates.
func matchETags(clientHeader, currentETag string) bool {
	clientHeader = strings.TrimSpace(clientHeader)
	if clientHeader == "*" {
		return true
	}

	cleanCurrent := cleanETag(currentETag)
	candidates := strings.Split(clientHeader, ",")
	for _, cand := range candidates {
		cand = strings.TrimSpace(cand)
		if cleanETag(cand) == cleanCurrent {
			return true
		}
	}

	return false
}

func cleanETag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "W/")
	tag = strings.TrimPrefix(tag, "w/")
	tag = strings.Trim(tag, `"`)
	return tag
}

// InvalidatePrefix evicts all cached items whose path starts with the specified prefix (RFC 9111 Section 4.4).
func (c *RFC9111CacheEngine) InvalidatePrefix(pathPrefix string) int {
	c.mu.Lock()
	evicted := 0
	for k, entry := range c.entries {
		if strings.HasPrefix(entry.Path, pathPrefix) {
			c.currentBytes -= int64(len(entry.Key) + len(entry.Body) + len(entry.GzipBody) + 256)
			delete(c.entries, k)
			evicted++
		}
	}
	adapter := c.stateAdapter
	c.mu.Unlock()

	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, _ = adapter.DeletePrefix(ctx, "cache:")
		cancel()
	}
	return evicted
}

// PurgeAll purges every entry from the cache.
func (c *RFC9111CacheEngine) PurgeAll() int {
	c.mu.Lock()
	total := len(c.entries)
	c.entries = make(map[string]*CacheEntry)
	c.currentBytes = 0
	adapter := c.stateAdapter
	c.mu.Unlock()

	if adapter != nil && adapter.Name() != "memory" {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, _ = adapter.DeletePrefix(ctx, "cache:")
		cancel()
	}
	return total
}

// Size returns the count of currently cached entries.
func (c *RFC9111CacheEngine) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *RFC9111CacheEngine) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for k, v := range c.entries {
		if oldestKey == "" || v.CachedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.CachedAt
		}
	}

	if oldestKey != "" {
		entry := c.entries[oldestKey]
		c.currentBytes -= int64(len(entry.Key) + len(entry.Body) + len(entry.GzipBody) + 256)
		delete(c.entries, oldestKey)
	}
}

func (c *RFC9111CacheEngine) reaperWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.evictExpired()
	}
}

func (c *RFC9111CacheEngine) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	for k, v := range c.entries {
		if now.After(v.ExpiresAt) {
			c.currentBytes -= int64(len(v.Key) + len(v.Body) + len(v.GzipBody) + 256)
			delete(c.entries, k)
		}
	}
}
