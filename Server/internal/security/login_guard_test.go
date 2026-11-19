package security

import (
	"testing"
	"time"
)

func TestLoginGuardLockoutAndManualUnban(t *testing.T) {
	g := NewLoginGuard(5, 15*time.Minute, 15*time.Minute)
	defer g.Close()

	ip := "203.0.113.55"
	user := "admin"

	for i := 1; i <= 4; i++ {
		if ok, _, _ := g.Check(ip, user); !ok {
			t.Fatalf("expected attempt %d to be allowed before lock threshold", i)
		}
		locked, rem, _ := g.RecordFailure(ip, user)
		if locked {
			t.Fatalf("did not expect lock on failure %d", i)
		}
		if rem != 5-i {
			t.Fatalf("expected %d remaining attempts, got %d", 5-i, rem)
		}
	}

	// 5th failure triggers lock
	locked, rem, retrySec := g.RecordFailure(ip, user)
	if !locked || rem != 0 || retrySec <= 0 {
		t.Fatalf("expected lock on 5th failure, got locked=%v rem=%d retry=%d", locked, rem, retrySec)
	}

	// Subsequent attempt must be blocked
	if ok, _, _ := g.Check(ip, user); ok {
		t.Fatalf("expected locked IP/user to be blocked by Check")
	}

	entries := g.ListEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 lock entries (ip + username), got %d", len(entries))
	}

	// Manual unban by bare IP and bare username
	if removed := g.Unban(ip); removed == 0 {
		t.Fatalf("expected unban by bare IP to remove record")
	}
	if removed := g.Unban(user); removed == 0 {
		t.Fatalf("expected unban by bare username to remove record")
	}
	if ok, _, _ := g.Check(ip, user); !ok {
		t.Fatalf("expected unbanned IP/user to be allowed immediately")
	}
}
