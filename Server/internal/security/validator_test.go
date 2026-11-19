// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package security

import (
	"testing"

	"lg-for-bgp/internal/models"
)

func TestPreventCommandInjectionPayloads(t *testing.T) {
	maliciousPayloads := []string{
		"8.8.8.8; id",
		"8.8.8.8 | cat /etc/passwd",
		"8.8.8.8 && whoami",
		"$(id)",
		"`id`",
		"fe80::1%;id",
		"fe80::1%eth0;whoami",
		"8.8.8.8\nshow configuration",
		"8.8.8.8\r\nrequest system reboot",
		"65001; id",
		"65000:1001; id",
	}

	for _, payload := range maliciousPayloads {
		if _, _, _, err := ValidatePrefixOrIP(payload); err == nil {
			t.Errorf("Expected ValidatePrefixOrIP to reject malicious payload %q, but it passed!", payload)
		}
		if _, err := ValidateASPathOrASN(payload); err == nil {
			t.Errorf("Expected ValidateASPathOrASN to reject malicious payload %q, but it passed!", payload)
		}
		if _, err := ValidateCommunity(payload); err == nil {
			t.Errorf("Expected ValidateCommunity to reject malicious payload %q, but it passed!", payload)
		}
	}
}

func TestValidInputs(t *testing.T) {
	if norm, fam, isPfx, err := ValidatePrefixOrIP("8.8.8.8"); err != nil || norm != "8.8.8.8" || fam != "ipv4" || isPfx {
		t.Fatalf("Unexpected result for 8.8.8.8: %v, %s, %s", err, norm, fam)
	}
	if norm, fam, isPfx, err := ValidatePrefixOrIP("2001:4860:4860::8888/32"); err != nil || norm != "2001:4860::/32" || fam != "ipv6" || !isPfx {
		t.Fatalf("Unexpected result for IPv6 prefix: %v, %s, %s", err, norm, fam)
	}
	if asn, err := ValidateASPathOrASN("AS2914"); err != nil || asn != "2914" {
		t.Fatalf("Unexpected result for AS2914: %v, %s", err, asn)
	}
	if comm, err := ValidateCommunity("65000:65000:100"); err != nil || comm != "65000:65000:100" {
		t.Fatalf("Unexpected result for Large Community: %v, %s", err, comm)
	}
}

func TestTenantViewRBAC(t *testing.T) {
	known := map[models.RouteViewID]models.RouteViewMeta{
		models.ViewLogicalSystemOpt: {ID: models.ViewLogicalSystemOpt},
		models.ViewVRFGlobalDIA:     {ID: models.ViewVRFGlobalDIA},
		models.ViewVRFTransitA:      {ID: models.ViewVRFTransitA},
	}
	allowed := []models.RouteViewID{models.ViewLogicalSystemOpt, models.ViewVRFGlobalDIA}

	views, err := ValidateRouteViews([]models.RouteViewID{models.ViewLogicalSystemOpt}, allowed, known)
	if err != nil || len(views) != 1 {
		t.Fatalf("Expected allowed view to succeed, got err=%v", err)
	}

	if _, err := ValidateRouteViews([]models.RouteViewID{models.ViewVRFTransitA}, allowed, known); err == nil {
		t.Fatalf("Expected unauthorized view request to be rejected!")
	}
}
