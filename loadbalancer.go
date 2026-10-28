package apigateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrNoHealthyNodes is returned when all backend instances in an upstream pool are down or tripped.
	ErrNoHealthyNodes = errors.New("upstream service unavailable: no healthy backend nodes in pool")

	// ErrInvalidAlgorithm is returned when an unsupported load balancing strategy is configured.
	ErrInvalidAlgorithm = errors.New("invalid load balancing algorithm")
)

const (
	// AlgorithmRoundRobin distributes requests sequentially across healthy nodes.
	AlgorithmRoundRobin = "round_robin"

	// AlgorithmLeastConn routes traffic to the healthy node with the fewest in-flight connections.
	AlgorithmLeastConn = "least_conn"
)

// UpstreamNode represents an individual backend server instance in a load-balanced pool.
type UpstreamNode struct {
	targetURL      *url.URL
	reverseProxy   *httputil.ReverseProxy
	circuitBreaker *CircuitBreaker

	// Thread-safe operational state & telemetry
	healthy        atomic.Bool
	activeConns    atomic.Int64
	totalRequests  atomic.Uint64
	failsCount     atomic.Int32
	successCount   atomic.Int32
	lastLatencyMic atomic.Int64 // last health check latency in microseconds
	lastChecked    atomic.Int64 // unix timestamp in seconds
}

// NewUpstreamNode initializes an individual backend instance with its own connection pool and circuit breaker.
func NewUpstreamNode(target *url.URL, rule RouteRule) *UpstreamNode {
	cb := NewCircuitBreaker(5, 5*time.Second)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          500,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host

		// Apply RewritePrefix or StripPrefix
		if rule.RewritePrefix != "" {
			req.URL.Path = rule.RewritePrefix + strings.TrimPrefix(req.URL.Path, rule.PathPrefix)
		} else if rule.StripPrefix {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, rule.PathPrefix)
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}
		}

		// Strip client spoofing attempts
		req.Header.Del("X-Forwarded-Host")
	}

	node := &UpstreamNode{
		targetURL:      target,
		reverseProxy:   proxy,
		circuitBreaker: cb,
	}
	node.healthy.Store(true) // assume healthy initially until probed

	proxy.ModifyResponse = func(resp *http.Response) error {
		cb.RecordResult(resp.StatusCode)
		if resp.StatusCode == http.StatusOK && resp.Request != nil &&
			(resp.Request.Method == http.MethodGet || resp.Request.Method == http.MethodHead) {
			if resp.Header.Get("ETag") == "" && resp.Body != nil {
				bodyBytes, err := io.ReadAll(resp.Body)
				if err == nil {
					_ = resp.Body.Close()
					resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					resp.Header.Set("ETag", GenerateETag(bodyBytes))
				}
			}
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		cb.RecordResult(http.StatusBadGateway)
		node.failsCount.Add(1)
		WriteBadGateway(w, req, fmt.Sprintf("upstream gateway node error: %s", err.Error()))
	}

	return node
}

// TargetURL returns the parsed target URL.
func (n *UpstreamNode) TargetURL() *url.URL {
	return n.targetURL
}

// URLString returns the string representation of the target URL.
func (n *UpstreamNode) URLString() string {
	if n.targetURL == nil {
		return ""
	}
	return n.targetURL.String()
}

// IsHealthy returns true if the node is considered healthy by both health checks and circuit breaker.
func (n *UpstreamNode) IsHealthy() bool {
	return n.healthy.Load() && n.circuitBreaker.Allow()
}

// SetHealthy manually overrides health state (useful for administrative drain or tests).
func (n *UpstreamNode) SetHealthy(h bool) {
	n.healthy.Store(h)
}

// ActiveConnections returns the number of currently active in-flight requests.
func (n *UpstreamNode) ActiveConnections() int64 {
	val := n.activeConns.Load()
	if val < 0 {
		return 0
	}
	return val
}

// TotalRequests returns the cumulative count of requests handled by this node.
func (n *UpstreamNode) TotalRequests() uint64 {
	return n.totalRequests.Load()
}

// CircuitBreaker returns the node's circuit breaker instance.
func (n *UpstreamNode) CircuitBreaker() *CircuitBreaker {
	return n.circuitBreaker
}

// Latency returns the last observed active health check latency.
func (n *UpstreamNode) Latency() time.Duration {
	return time.Duration(n.lastLatencyMic.Load()) * time.Microsecond
}

// LastChecked returns the timestamp of the last active health check.
func (n *UpstreamNode) LastChecked() time.Time {
	sec := n.lastChecked.Load()
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// ConsecutiveFailures returns the number of consecutive health probe failures.
func (n *UpstreamNode) ConsecutiveFailures() int {
	return int(n.failsCount.Load())
}

// UpstreamPool manages a collection of UpstreamNodes for a given RouteRule, providing
// high-performance load balancing (Round-Robin, Least-Connections) and proactive background health checks.
type UpstreamPool struct {
	rule         RouteRule
	algorithm    string
	nodes        []*UpstreamNode
	rrIndex      atomic.Uint64
	healthConfig HealthCheckConfig

	httpClient *http.Client
	stopChan   chan struct{}
	stopOnce   sync.Once
	ticker     *time.Ticker
}

// NewUpstreamPool creates a load-balanced upstream pool with the given backend URLs.
func NewUpstreamPool(rule RouteRule, targetURLs []*url.URL) (*UpstreamPool, error) {
	if len(targetURLs) == 0 {
		return nil, fmt.Errorf("upstream pool requires at least one target URL")
	}

	algo := strings.ToLower(strings.TrimSpace(rule.LoadBalancer))
	if algo == "" {
		algo = AlgorithmRoundRobin
	}
	if algo != AlgorithmRoundRobin && algo != AlgorithmLeastConn {
		return nil, fmt.Errorf("%w: '%s' (supported: %s, %s)", ErrInvalidAlgorithm, algo, AlgorithmRoundRobin, AlgorithmLeastConn)
	}

	hc := rule.HealthCheck
	if hc.Path == "" {
		hc.Path = "/healthz"
	}
	if hc.Interval <= 0 {
		hc.Interval = 10 * time.Second
	}
	if hc.Timeout <= 0 {
		hc.Timeout = 2 * time.Second
	}
	if hc.UnhealthyThreshold <= 0 {
		hc.UnhealthyThreshold = 2
	}
	if hc.HealthyThreshold <= 0 {
		hc.HealthyThreshold = 2
	}

	nodes := make([]*UpstreamNode, len(targetURLs))
	for i, u := range targetURLs {
		nodes[i] = NewUpstreamNode(u, rule)
	}

	// Lightweight HTTP client dedicated for health checks
	client := &http.Client{
		Timeout: hc.Timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   hc.Timeout,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			MaxIdleConns:        50,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: hc.Timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	pool := &UpstreamPool{
		rule:         rule,
		algorithm:    algo,
		nodes:        nodes,
		healthConfig: hc,
		httpClient:   client,
		stopChan:     make(chan struct{}),
	}

	if hc.Enabled {
		pool.startHealthChecking()
	}

	return pool, nil
}

// startHealthChecking initializes the periodic active health probe goroutine.
func (p *UpstreamPool) startHealthChecking() {
	p.ticker = time.NewTicker(p.healthConfig.Interval)
	go func() {
		for {
			select {
			case <-p.stopChan:
				return
			case <-p.ticker.C:
				p.ProbeAll()
			}
		}
	}()
}

// ProbeAll triggers an active health probe against all nodes in the pool simultaneously.
func (p *UpstreamPool) ProbeAll() {
	var wg sync.WaitGroup
	for _, node := range p.nodes {
		wg.Add(1)
		go func(n *UpstreamNode) {
			defer wg.Done()
			p.ProbeNode(n)
		}(node)
	}
	wg.Wait()
}

// ProbeNode executes a single health check probe against a node and updates its operational status.
func (p *UpstreamPool) ProbeNode(node *UpstreamNode) bool {
	probeURL := fmt.Sprintf("%s://%s%s", node.targetURL.Scheme, node.targetURL.Host, p.healthConfig.Path)
	req, err := http.NewRequest(http.MethodGet, probeURL, nil)
	if err != nil {
		p.recordProbeFailure(node)
		return false
	}
	req.Header.Set("User-Agent", "Aeitron-HealthChecker/1.0")

	ctx, cancel := context.WithTimeout(context.Background(), p.healthConfig.Timeout)
	defer cancel()
	req = req.WithContext(ctx)

	start := time.Now()
	resp, err := p.httpClient.Do(req)
	latency := time.Since(start)

	node.lastLatencyMic.Store(latency.Microseconds())
	node.lastChecked.Store(time.Now().Unix())

	if err != nil {
		p.recordProbeFailure(node)
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		p.recordProbeFailure(node)
		return false
	}

	p.recordProbeSuccess(node)
	return true
}

func (p *UpstreamPool) recordProbeFailure(node *UpstreamNode) {
	node.successCount.Store(0)
	fails := node.failsCount.Add(1)
	if int(fails) >= p.healthConfig.UnhealthyThreshold {
		node.healthy.Store(false)
	}
}

func (p *UpstreamPool) recordProbeSuccess(node *UpstreamNode) {
	node.failsCount.Store(0)
	succ := node.successCount.Add(1)
	if int(succ) >= p.healthConfig.HealthyThreshold {
		node.healthy.Store(true)
	}
}

// HealthyNodes returns all nodes that are currently healthy and eligible to receive traffic.
func (p *UpstreamPool) HealthyNodes() []*UpstreamNode {
	healthy := make([]*UpstreamNode, 0, len(p.nodes))
	for _, n := range p.nodes {
		if n.IsHealthy() {
			healthy = append(healthy, n)
		}
	}
	return healthy
}

// Nodes returns all configured nodes in this pool.
func (p *UpstreamPool) Nodes() []*UpstreamNode {
	return p.nodes
}

// Algorithm returns the configured load balancing strategy.
func (p *UpstreamPool) Algorithm() string {
	return p.algorithm
}

// HealthConfig returns the active health check configuration.
func (p *UpstreamPool) HealthConfig() HealthCheckConfig {
	return p.healthConfig
}

// Pick selects a backend node using the configured algorithm (Round-Robin or Least-Connections).
func (p *UpstreamPool) Pick() (*UpstreamNode, error) {
	healthy := p.HealthyNodes()

	// Fallback strategy: if all failed active checks, check if any circuit breaker allows (emergency half-open)
	if len(healthy) == 0 {
		for _, n := range p.nodes {
			if n.circuitBreaker.Allow() {
				healthy = append(healthy, n)
			}
		}
	}

	if len(healthy) == 0 {
		return nil, ErrNoHealthyNodes
	}

	if len(healthy) == 1 {
		return healthy[0], nil
	}

	switch p.algorithm {
	case AlgorithmLeastConn:
		return p.pickLeastConn(healthy), nil
	case AlgorithmRoundRobin:
		fallthrough
	default:
		return p.pickRoundRobin(healthy), nil
	}
}

func (p *UpstreamPool) pickRoundRobin(candidates []*UpstreamNode) *UpstreamNode {
	idx := p.rrIndex.Add(1) - 1
	return candidates[idx%uint64(len(candidates))]
}

func (p *UpstreamPool) pickLeastConn(candidates []*UpstreamNode) *UpstreamNode {
	var best *UpstreamNode
	minConns := int64(1<<62 - 1)

	for _, n := range candidates {
		c := n.ActiveConnections()
		if c < minConns {
			minConns = c
			best = n
		}
	}
	return best
}

// Close gracefully terminates background health checking goroutines.
func (p *UpstreamPool) Close() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
		if p.ticker != nil {
			p.ticker.Stop()
		}
	})
}
