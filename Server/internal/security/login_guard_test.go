// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package security

import (
	"testing"
	"time"
)

func TestLoginGuardLockoutNoGlobalDoSAndNoCrossAccountReset(t *testing.T) {
	g := NewLoginGuard(5, 15*time.Minute, 15*time.Minute)
	defer g.Close()

	attackerIP := "203.0.113.55"
	legitAdminIP := "10.10.0.1"
	user := "admin"

	for i := 1; i <= 4; i++ {
		if ok, _, _ := g.Check(attackerIP, user); !ok {
			t.Fatalf("expected attempt %d to be allowed before lock threshold", i)
		}
		locked, rem, _ := g.RecordFailure(attackerIP, user)
		if locked {
			t.Fatalf("did not expect lock on failure %d", i)
		}
		if rem != 5-i {
			t.Fatalf("expected %d remaining attempts, got %d", 5-i, rem)
		}
	}

	// Verify signing into an unrelated account ("customer_a") from the same IP does NOT clear failures against "admin"
	g.RecordSuccess(attackerIP, "customer_a")

	// 5th failure against admin from attackerIP triggers immediate lock!
	locked, rem, retrySec := g.RecordFailure(attackerIP, user)
	if !locked || rem != 0 || retrySec <= 0 {
		t.Fatalf("expected lock on 5th failure despite throwaway account login, got locked=%v rem=%d retry=%d", locked, rem, retrySec)
	}

	// Attacker IP is blocked
	if ok, _, _ := g.Check(attackerIP, user); ok {
		t.Fatalf("expected locked attacker IP/pair to be blocked by Check")
	}

	// CRITICAL ANTI-DOS CHECK: Legitimate admin logging in from a DIFFERENT IP MUST still be allowed!
	if ok, _, reason := g.Check(legitAdminIP, user); !ok {
		t.Fatalf("Account Lockout DoS regression: legitimate admin from %s was blocked (%s)", legitAdminIP, reason)
	}

	entries := g.ListEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 lock entries (ip + ip+user), got %d", len(entries))
	}

	// Manual unban by bare IP clears both ip:<attackerIP> and pair:<attackerIP>|admin
	if removed := g.Unban(attackerIP); removed < 2 {
		t.Fatalf("expected unban by bare IP to remove ip + pair records, removed=%d", removed)
	}
	if ok, _, _ := g.Check(attackerIP, user); !ok {
		t.Fatalf("expected unbanned IP/user to be allowed immediately")
	}

	// Re-lock and verify manual unban by username
	for i := 0; i < 5; i++ {
		g.RecordFailure(attackerIP, user)
	}
	if removed := g.Unban(user); removed == 0 {
		t.Fatalf("expected unban by username to remove matching records")
	}
	if ok, _, _ := g.Check(attackerIP, user); !ok {
		t.Fatalf("expected unbanned username to be allowed immediately")
	}
}
