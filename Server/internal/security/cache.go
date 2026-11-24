// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package security

import (
	"sync"
	"time"

	"lg-for-bgp/internal/models"
)

type cacheItem struct {
	value     models.ViewQueryResult
	expiresAt time.Time
}

// TTLCache provides a fast, bounded, thread-safe in-memory cache for BGP queries
// with automatic background expiration sweeping to prevent memory leaks.
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
		for k, item := range c.items {
			if now.After(item.expiresAt) {
				delete(c.items, k)
			}
		}
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
