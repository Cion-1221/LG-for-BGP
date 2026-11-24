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

const defaultLoginGuardMaxEntries = 16384

type loginTracker struct {
	key         string
	kind        string // "ip" or "ip+user"
	value       string // Display value, e.g. "203.0.113.10" or "admin @ 203.0.113.10"
	ip          string
	username    string
	failures    int
	firstFail   time.Time
	lastAttempt time.Time
	lockedUntil time.Time
}

// LoginGuard protects /api/v1/auth/login against brute-force password guessing without
// enabling Account Lockout DoS against legitimate users/administrators on other IPs.
//
// Security design:
//   - Tracks per-IP (`ip:<ip>`) AND per-(IP, Username) (`pair:<ip>|<user>`), NEVER a global `user:<username>` lock,
//     so an external attacker guessing "admin" cannot lock out the real administrator logging in from another IP.
//   - `RecordSuccess(ip, user)` ONLY removes `pair:<ip>|<user>` and subtracts ONLY that pair's prior failure count
//     from `ip:<ip>`, preventing an attacker from resetting their IP failure counter by signing into a throwaway account.
//   - Bounded `maxEntries` map prevents memory exhaustion under random-IP / random-username floods.
type LoginGuard struct {
	mu             sync.Mutex
	entries        map[string]*loginTracker
	maxFailures    int
	maxEntries     int
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
		maxEntries:     defaultLoginGuardMaxEntries,
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
	g.pruneExpiredLocked(now)
}

func (g *LoginGuard) pruneExpiredLocked(now time.Time) {
	for k, tr := range g.entries {
		lockExpired := tr.lockedUntil.IsZero() || !now.Before(tr.lockedUntil)
		windowExpired := now.Sub(tr.lastAttempt) > g.windowDuration
		if lockExpired && windowExpired {
			delete(g.entries, k)
		}
	}
}

func (g *LoginGuard) ensureCapacityLocked(now time.Time) {
	if len(g.entries) < g.maxEntries {
		return
	}
	g.pruneExpiredLocked(now)
	if len(g.entries) < g.maxEntries {
		return
	}
	// Evict oldest unlocked entries first, then oldest lastAttempt entries
	evict := g.maxEntries / 10
	if evict < 1 {
		evict = 1
	}
	for k, tr := range g.entries {
		if tr.lockedUntil.IsZero() || !now.Before(tr.lockedUntil) {
			delete(g.entries, k)
			evict--
			if evict <= 0 {
				return
			}
		}
	}
	for k := range g.entries {
		delete(g.entries, k)
		evict--
		if evict <= 0 {
			return
		}
	}
}

func ipKey(ip string) string {
	return "ip:" + strings.TrimSpace(ip)
}

func pairKey(ip, username string) string {
	return "pair:" + strings.TrimSpace(ip) + "|" + strings.ToLower(strings.TrimSpace(username))
}

// Check verifies whether the given client IP and (clientIP, username) pair are currently allowed to attempt login.
func (g *LoginGuard) Check(clientIP, username string) (allowed bool, retryAfterSec int, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	cleanIP := strings.TrimSpace(clientIP)
	cleanUser := strings.ToLower(strings.TrimSpace(username))

	var keys []string
	if cleanIP != "" {
		keys = append(keys, ipKey(cleanIP))
	}
	if cleanIP != "" && cleanUser != "" {
		keys = append(keys, pairKey(cleanIP, cleanUser))
	} else if cleanIP == "" && cleanUser != "" {
		keys = append(keys, pairKey("unknown", cleanUser))
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
			if !tr.lockedUntil.IsZero() && !now.Before(tr.lockedUntil) {
				delete(g.entries, k)
			}
		}
	}
	return true, 0, ""
}

// RecordFailure records a failed login attempt for clientIP and (clientIP, username).
func (g *LoginGuard) RecordFailure(clientIP, username string) (lockedNow bool, remainingAttempts int, retryAfterSec int) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	remainingAttempts = g.maxFailures
	cleanIP := strings.TrimSpace(clientIP)
	cleanUser := strings.ToLower(strings.TrimSpace(username))

	recordOne := func(key, kind, displayVal, ipVal, userVal string) {
		tr, ok := g.entries[key]
		if !ok || now.Sub(tr.firstFail) > g.windowDuration {
			g.ensureCapacityLocked(now)
			tr = &loginTracker{
				key:       key,
				kind:      kind,
				value:     displayVal,
				ip:        ipVal,
				username:  userVal,
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

	if cleanIP != "" {
		recordOne(ipKey(cleanIP), "ip", cleanIP, cleanIP, "")
	}
	if cleanUser != "" {
		ipPart := cleanIP
		if ipPart == "" {
			ipPart = "unknown"
		}
		recordOne(pairKey(ipPart, cleanUser), "ip+user", fmt.Sprintf("%s @ %s", cleanUser, ipPart), ipPart, cleanUser)
	}

	return lockedNow, remainingAttempts, retryAfterSec
}

// RecordSuccess clears failure counters ONLY for the authenticated (clientIP, username) pair,
// and subtracts only that pair's prior failures from the IP tracker so failures against other accounts persist.
func (g *LoginGuard) RecordSuccess(clientIP, username string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	cleanIP := strings.TrimSpace(clientIP)
	cleanUser := strings.ToLower(strings.TrimSpace(username))
	ipPart := cleanIP
	if ipPart == "" {
		ipPart = "unknown"
	}

	clearedPairFailures := 0
	if cleanUser != "" {
		pk := pairKey(ipPart, cleanUser)
		if tr, ok := g.entries[pk]; ok {
			if now.Sub(tr.firstFail) <= g.windowDuration {
				clearedPairFailures = tr.failures
			}
			delete(g.entries, pk)
		}
	}

	if cleanIP != "" && clearedPairFailures > 0 {
		ik := ipKey(cleanIP)
		if ipTr, ok := g.entries[ik]; ok {
			isLocked := !ipTr.lockedUntil.IsZero() && now.Before(ipTr.lockedUntil)
			if !isLocked {
				ipTr.failures -= clearedPairFailures
				if ipTr.failures <= 0 {
					delete(g.entries, ik)
				}
			}
		}
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

// Unban removes lock/failure entries by exact key ("ip:1.2.3.4", "pair:1.2.3.4|admin"),
// bare IP ("1.2.3.4"), bare username ("admin" / "user:admin"), or "all".
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

	cleanUserTarget := strings.ToLower(strings.TrimPrefix(strings.ToLower(t), "user:"))
	cleanIPTarget := strings.TrimPrefix(t, "ip:")

	for k, tr := range g.entries {
		if tr.ip != "" && tr.ip == cleanIPTarget {
			delete(g.entries, k)
			removed++
			continue
		}
		if tr.username != "" && tr.username == cleanUserTarget {
			// Also adjust or clear the corresponding IP lock if all failures on that IP were for this username
			if ik := ipKey(tr.ip); ik != "" {
				if ipTr, hasIP := g.entries[ik]; hasIP {
					ipTr.failures -= tr.failures
					if ipTr.failures <= 0 {
						delete(g.entries, ik)
						removed++
					} else if ipTr.failures < g.maxFailures {
						ipTr.lockedUntil = time.Time{}
					}
				}
			}
			delete(g.entries, k)
			removed++
		}
	}

	return removed
}
