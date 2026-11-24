// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package security

import (
	"sync"
	"time"
)

const defaultRateLimiterMaxKeys = 16384

// RateLimiter implements a bounded sliding-window per-user / per-IP request rate limiter
// with periodic background eviction of idle keys to prevent unbounded memory growth.
type RateLimiter struct {
	mu        sync.Mutex
	requests  map[string][]time.Time
	maxKeys   int
	stopCh    chan struct{}
	closeOnce sync.Once
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		maxKeys:  defaultRateLimiterMaxKeys,
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
			rl.sweepExpired(now)
		}
	}
}

func (rl *RateLimiter) sweepExpired(now time.Time) {
	cutoff := now.Add(-2 * time.Minute)
	rl.mu.Lock()
	defer rl.mu.Unlock()
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
}

func (rl *RateLimiter) Allow(key string, limitPerMinute int) bool {
	if limitPerMinute <= 0 {
		limitPerMinute = 60
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)
	history, exists := rl.requests[key]

	if !exists && len(rl.requests) >= rl.maxKeys {
		// Evict expired keys first; if still full, evict ~10% arbitrary oldest keys
		for k, h := range rl.requests {
			if len(h) == 0 || !h[len(h)-1].After(cutoff) {
				delete(rl.requests, k)
			}
		}
		if len(rl.requests) >= rl.maxKeys {
			evict := rl.maxKeys / 10
			if evict < 1 {
				evict = 1
			}
			for k := range rl.requests {
				delete(rl.requests, k)
				evict--
				if evict <= 0 {
					break
				}
			}
		}
	}

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
