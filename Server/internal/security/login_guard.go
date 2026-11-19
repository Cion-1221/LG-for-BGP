// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package security

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"lg-for-bgp/internal/models"
)

type loginTracker struct {
	key         string
	kind        string // "ip" or "username"
	value       string
	failures    int
	firstFail   time.Time
	lastAttempt time.Time
	lockedUntil time.Time
}

// LoginGuard protects /api/v1/auth/login against brute-force password guessing.
// It tracks failed logins per client IP and per username, automatically locking out
// after maxFailures within windowDuration, and supports admin inspection + manual unban.
type LoginGuard struct {
	mu             sync.Mutex
	entries        map[string]*loginTracker
	maxFailures    int
	windowDuration time.Duration
	lockDuration   time.Duration
	stopCh         chan struct{}
	closeOnce      sync.Once
}

func NewLoginGuard(maxFailures int, windowDuration, lockDuration time.Duration) *LoginGuard {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if windowDuration <= 0 {
		windowDuration = 15 * time.Minute
	}
	if lockDuration <= 0 {
		lockDuration = 15 * time.Minute
	}
	g := &LoginGuard{
		entries:        make(map[string]*loginTracker),
		maxFailures:    maxFailures,
		windowDuration: windowDuration,
		lockDuration:   lockDuration,
		stopCh:         make(chan struct{}),
	}
	go g.gcLoop()
	return g
}

func (g *LoginGuard) Close() {
	g.closeOnce.Do(func() {
		close(g.stopCh)
	})
}

func (g *LoginGuard) gcLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case now := <-ticker.C:
			g.pruneExpired(now)
		}
	}
}

func (g *LoginGuard) pruneExpired(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, tr := range g.entries {
		lockExpired := tr.lockedUntil.IsZero() || !now.Before(tr.lockedUntil)
		windowExpired := now.Sub(tr.lastAttempt) > g.windowDuration
		if lockExpired && windowExpired {
			delete(g.entries, k)
		}
	}
}

func ipKey(ip string) string {
	return "ip:" + strings.TrimSpace(ip)
}

func userKey(username string) string {
	return "user:" + strings.ToLower(strings.TrimSpace(username))
}

// Check verifies whether the given client IP and username are currently allowed to attempt login.
func (g *LoginGuard) Check(clientIP, username string) (allowed bool, retryAfterSec int, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	keys := []string{}
	if strings.TrimSpace(clientIP) != "" {
		keys = append(keys, ipKey(clientIP))
	}
	if strings.TrimSpace(username) != "" {
		keys = append(keys, userKey(username))
	}

	for _, k := range keys {
		if tr, ok := g.entries[k]; ok {
			if !tr.lockedUntil.IsZero() && now.Before(tr.lockedUntil) {
				rem := int(time.Until(tr.lockedUntil).Seconds()) + 1
				if rem < 1 {
					rem = 1
				}
				return false, rem, fmt.Sprintf("Too many failed login attempts (%s locked). Retry in %d seconds or contact administrator to unban.", tr.kind, rem)
			}
			// Lock expired -> reset entry
			if !tr.lockedUntil.IsZero() && !now.Before(tr.lockedUntil) {
				delete(g.entries, k)
			}
		}
	}
	return true, 0, ""
}

// RecordFailure records a failed login attempt for clientIP and username.
func (g *LoginGuard) RecordFailure(clientIP, username string) (lockedNow bool, remainingAttempts int, retryAfterSec int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	remainingAttempts = g.maxFailures

	recordOne := func(key, kind, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		tr, ok := g.entries[key]
		if !ok || now.Sub(tr.firstFail) > g.windowDuration {
			tr = &loginTracker{
				key:       key,
				kind:      kind,
				value:     val,
				firstFail: now,
			}
			g.entries[key] = tr
		}
		tr.failures++
		tr.lastAttempt = now
		if tr.failures >= g.maxFailures {
			tr.lockedUntil = now.Add(g.lockDuration)
			lockedNow = true
			rem := int(g.lockDuration.Seconds())
			if rem > retryAfterSec {
				retryAfterSec = rem
			}
			remainingAttempts = 0
		} else {
			left := g.maxFailures - tr.failures
			if left < remainingAttempts {
				remainingAttempts = left
			}
		}
	}

	recordOne(ipKey(clientIP), "ip", strings.TrimSpace(clientIP))
	recordOne(userKey(username), "username", strings.ToLower(strings.TrimSpace(username)))

	return lockedNow, remainingAttempts, retryAfterSec
}

// RecordSuccess clears failure counters upon successful authentication.
func (g *LoginGuard) RecordSuccess(clientIP, username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if strings.TrimSpace(clientIP) != "" {
		delete(g.entries, ipKey(clientIP))
	}
	if strings.TrimSpace(username) != "" {
		delete(g.entries, userKey(username))
	}
}

// ListEntries returns all currently locked or tracked login-failure records for Admin Console display.
func (g *LoginGuard) ListEntries() []models.LoginLockEntry {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	out := make([]models.LoginLockEntry, 0, len(g.entries))
	for k, tr := range g.entries {
		locked := !tr.lockedUntil.IsZero() && now.Before(tr.lockedUntil)
		windowExpired := now.Sub(tr.lastAttempt) > g.windowDuration
		if !locked && windowExpired {
			delete(g.entries, k)
			continue
		}
		rem := 0
		var lockedUntilPtr *time.Time
		if locked {
			rem = int(time.Until(tr.lockedUntil).Seconds()) + 1
			if rem < 1 {
				rem = 1
			}
			t := tr.lockedUntil
			lockedUntilPtr = &t
		}
		out = append(out, models.LoginLockEntry{
			Key:              tr.key,
			Type:             tr.kind,
			Value:            tr.value,
			Failures:         tr.failures,
			MaxFailures:      g.maxFailures,
			Locked:           locked,
			RemainingSeconds: rem,
			LastAttempt:      tr.lastAttempt,
			LockedUntil:      lockedUntilPtr,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Locked != out[j].Locked {
			return out[i].Locked
		}
		return out[i].LastAttempt.After(out[j].LastAttempt)
	})
	return out
}

// Unban removes a lock/failure entry by key ("ip:1.2.3.4", "user:admin"), bare value ("1.2.3.4", "admin"), or "all".
func (g *LoginGuard) Unban(target string) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	t := strings.TrimSpace(target)
	if t == "" {
		return 0
	}
	if strings.EqualFold(t, "all") {
		count := len(g.entries)
		g.entries = make(map[string]*loginTracker)
		return count
	}

	removed := 0
	if _, ok := g.entries[t]; ok {
		delete(g.entries, t)
		removed++
	}
	lower := strings.ToLower(t)
	for _, cand := range []string{"ip:" + t, "user:" + lower} {
		if _, ok := g.entries[cand]; ok {
			delete(g.entries, cand)
			removed++
		}
	}
	return removed
}
