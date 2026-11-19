package security

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"lg-for-bgp/internal/models"
)

var (
	// Strict regex for BGP Community: standard (ASN:Value), Large Community (ASN:Func:Param), or well-known named community
	reCommunity = regexp.MustCompile(`^(\d{1,10}:\d{1,10}(:\d{1,10})?|route-filter-[a-zA-Z0-9\-]+|no-[a-zA-Z0-9\-]+)$`)

	// Strict regex for safe AS-Path expressions: ONLY digits, spaces, _, ^, $, ., *, +, ?, [, ], -
	// Explicitly forbids shell metacharacters (; | & ` $ ( ) \ ' " < > % \n \r)
	reSafeASPath = regexp.MustCompile(`^[0-9_\^\$\.\*\+\?\[\]\s\-]{1,64}$`)

	// Strict identifier format for RouteViewID (matches DB VARCHAR(64))
	reViewID = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

	// Shell & control characters that are unconditionally rejected at the boundary
	forbiddenChars = ";|&`$()<>\\\"'%\n\r\t\x00"
)

// ValidateNoControlOrShellChars guarantees no shell injection or CLI newline injection is possible.
func ValidateNoControlOrShellChars(input string) error {
	if strings.TrimSpace(input) == "" {
		return errors.New("query target cannot be empty")
	}
	if len(input) > 128 {
		return errors.New("input exceeds maximum length of 128 characters")
	}
	for _, r := range input {
		if r < 32 || r == 127 {
			return errors.New("control characters are strictly forbidden")
		}
		if strings.ContainsRune(forbiddenChars, r) {
			return fmt.Errorf("forbidden metacharacter '%c' detected and blocked", r)
		}
	}
	return nil
}

// ValidatePrefixOrIP strictly parses IPv4/IPv6 addresses or CIDR prefixes using Go's net/netip.
// Also explicitly rejects IPv6 Zone/Scope IDs (%).
func ValidatePrefixOrIP(target string) (normalized string, family string, isPrefix bool, err error) {
	target = strings.TrimSpace(target)
	if err := ValidateNoControlOrShellChars(target); err != nil {
		return "", "", false, err
	}
	if strings.Contains(target, "%") {
		return "", "", false, errors.New("IPv6 zone/scope ID (%) is not allowed")
	}

	if strings.Contains(target, "/") {
		pfx, err := netip.ParsePrefix(target)
		if err != nil {
			return "", "", false, fmt.Errorf("invalid IP prefix format: %s", target)
		}
		pfx = pfx.Masked()
		fam := "ipv4"
		if pfx.Addr().Is6() {
			fam = "ipv6"
		}
		return pfx.String(), fam, true, nil
	}

	addr, err := netip.ParseAddr(target)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid IPv4/IPv6 address format: %s", target)
	}
	if addr.Zone() != "" {
		return "", "", false, errors.New("IPv6 zone identifier is not allowed")
	}
	fam := "ipv4"
	if addr.Is6() {
		fam = "ipv6"
	}
	return addr.String(), fam, false, nil
}

// ValidateASPathOrASN validates an ASN number (e.g. "2914" or "AS2914" or "23764 4134") or safe AS-Path pattern.
func ValidateASPathOrASN(target string) (cleaned string, err error) {
	target = strings.TrimSpace(target)
	if err := ValidateNoControlOrShellChars(target); err != nil {
		return "", err
	}
	// Strip optional "AS" / "as" prefixes before digits (e.g. "AS23764 AS4134" -> "23764 4134")
	tokens := strings.Fields(target)
	for i, tok := range tokens {
		upper := strings.ToUpper(tok)
		if strings.HasPrefix(upper, "AS") && len(tok) > 2 {
			tokens[i] = tok[2:]
		}
	}
	if len(tokens) > 0 {
		target = strings.Join(tokens, " ")
	}
	if target == "" || len(target) > 64 {
		return "", errors.New("ASN or AS-Path length must be between 1 and 64 characters")
	}
	for _, r := range target {
		if r < 32 || r == 127 || strings.ContainsRune(";|&\x60()<>\\\"'%\n\r\t", r) {
			return "", fmt.Errorf("AS-Path query contains forbidden character '%c'", r)
		}
	}
	if !reSafeASPath.MatchString(target) {
		return "", errors.New("AS-Path only allows digits, spaces, and safe regex anchors (^ $ _ . * + ? [ ] -)")
	}
	if num, errConv := strconv.ParseUint(target, 10, 32); errConv == nil {
		if num == 0 {
			return "", errors.New("ASN cannot be 0")
		}
	}
	return target, nil
}

// ValidateCommunity strictly validates BGP Standard or Large Community strings (e.g. "65000:1001").
func ValidateCommunity(target string) (string, error) {
	target = strings.TrimSpace(target)
	if err := ValidateNoControlOrShellChars(target); err != nil {
		return "", err
	}
	lower := strings.ToLower(target)
	switch lower {
	case "no-export", "no-advertise", "blackhole", "graceful-shutdown":
		return lower, nil
	}
	if !reCommunity.MatchString(target) {
		return "", errors.New("invalid BGP Community format; expected ASN:Value (e.g. 65000:1001) or Large Community (ASN:X:Y)")
	}
	return target, nil
}

// ValidateRouteViews filters and validates requested RouteViews against registered views and user permissions.
func ValidateRouteViews(requested []models.RouteViewID, allowed []models.RouteViewID, knownViews map[models.RouteViewID]models.RouteViewMeta) ([]models.RouteViewID, error) {
	allowedSet := make(map[models.RouteViewID]bool, len(allowed))
	for _, v := range allowed {
		allowedSet[v] = true
	}

	if len(requested) == 0 {
		return nil, errors.New("please select at least one BGP route view")
	}

	var result []models.RouteViewID
	seen := make(map[models.RouteViewID]bool)
	for _, req := range requested {
		if seen[req] {
			continue
		}
		if !reViewID.MatchString(string(req)) {
			return nil, fmt.Errorf("invalid route view identifier format: %s", req)
		}
		if knownViews != nil {
			if _, ok := knownViews[req]; !ok {
				return nil, fmt.Errorf("unknown route view identifier: %s", req)
			}
		}
		if !allowedSet[req] {
			return nil, fmt.Errorf("current account is not authorized to query route view [%s]", req)
		}
		seen[req] = true
		result = append(result, req)
	}
	return result, nil
}

// TTLCache provides a fast, bounded, thread-safe in-memory cache for BGP queries
// with automatic background expiration sweeping to prevent memory leaks.
type cacheItem struct {
	value     models.ViewQueryResult
	expiresAt time.Time
}

type TTLCache struct {
	mu        sync.RWMutex
	items     map[string]cacheItem
	maxItems  int
	stopCh    chan struct{}
	closeOnce sync.Once
}

func NewTTLCache() *TTLCache {
	c := &TTLCache{
		items:    make(map[string]cacheItem),
		maxItems: 4096,
		stopCh:   make(chan struct{}),
	}
	go c.gcLoop()
	return c
}

func (c *TTLCache) Close() {
	c.closeOnce.Do(func() {
		close(c.stopCh)
	})
}

func (c *TTLCache) gcLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for k, item := range c.items {
				if now.After(item.expiresAt) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *TTLCache) Get(key string) (models.ViewQueryResult, bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(item.expiresAt) {
		return models.ViewQueryResult{}, false
	}
	res := item.value
	res.Cached = true
	return res, true
}

func (c *TTLCache) Set(key string, val models.ViewQueryResult, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	if len(c.items) >= c.maxItems {
		// First purge expired entries
		for k, item := range c.items {
			if now.After(item.expiresAt) {
				delete(c.items, k)
			}
		}
		// If still at capacity, evict the soonest-to-expire entries (up to 10%)
		if len(c.items) >= c.maxItems {
			evictTarget := c.maxItems / 10
			if evictTarget < 1 {
				evictTarget = 1
			}
			for i := 0; i < evictTarget && len(c.items) > 0; i++ {
				var oldestKey string
				var oldestExp time.Time
				first := true
				for k, item := range c.items {
					if first || item.expiresAt.Before(oldestExp) {
						oldestKey = k
						oldestExp = item.expiresAt
						first = false
					}
				}
				if oldestKey != "" {
					delete(c.items, oldestKey)
				}
			}
		}
	}
	c.items[key] = cacheItem{
		value:     val,
		expiresAt: now.Add(ttl),
	}
	c.mu.Unlock()
}

func (c *TTLCache) Clear() {
	c.mu.Lock()
	c.items = make(map[string]cacheItem)
	c.mu.Unlock()
}

// RateLimiter implements a sliding window per-user / per-IP request rate limiter
// with periodic background eviction of idle keys to prevent unbounded memory growth.
type RateLimiter struct {
	mu        sync.Mutex
	requests  map[string][]time.Time
	stopCh    chan struct{}
	closeOnce sync.Once
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		stopCh:   make(chan struct{}),
	}
	go rl.gcLoop()
	return rl
}

func (rl *RateLimiter) Close() {
	rl.closeOnce.Do(func() {
		close(rl.stopCh)
	})
}

func (rl *RateLimiter) gcLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case now := <-ticker.C:
			cutoff := now.Add(-2 * time.Minute)
			rl.mu.Lock()
			for k, history := range rl.requests {
				var active []time.Time
				for _, t := range history {
					if t.After(cutoff) {
						active = append(active, t)
					}
				}
				if len(active) == 0 {
					delete(rl.requests, k)
				} else {
					rl.requests[k] = active
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) Allow(key string, limitPerMinute int) bool {
	if limitPerMinute <= 0 {
		limitPerMinute = 60
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)
	history := rl.requests[key]

	var recent []time.Time
	for _, t := range history {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= limitPerMinute {
		rl.requests[key] = recent
		return false
	}

	recent = append(recent, now)
	rl.requests[key] = recent
	return true
}
