// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package security

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"lg-for-bgp/internal/models"
)

var (
	// Strict regex for BGP Community: standard (ASN:Value), Large Community (ASN:Func:Param), or well-known named community
	reCommunity = regexp.MustCompile(`^(\d{1,10}:\d{1,10}(:\d{1,10})?|route-filter-[a-zA-Z0-9\-]+|no-[a-zA-Z0-9\-]+)$`)

	// Strict regex for safe AS-Path expressions: ONLY digits, spaces, _, ^, $, ., *, +, ?, [, ], -
	// Explicitly forbids shell metacharacters (; | & ` ( ) \ ' " < > % \n \r)
	reSafeASPath = regexp.MustCompile(`^[0-9_\^\$\.\*\+\?\[\]\s\-]{1,64}$`)

	// Strips optional "AS"/"as" prefix before ASN digits even when preceded by ^ or _ (e.g. "^AS2914 AS4134$" -> "^2914 4134$")
	reASPrefixToken = regexp.MustCompile(`(?i)(^|[\s\^_])as([0-9]+)`)

	// Strict identifier format for RouteViewID (matches DB VARCHAR(64))
	reViewID = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

	// Shell & control characters that are unconditionally rejected at the boundary
	forbiddenChars = ";|&`$()<>\\\"'%\n\r\t\x00"

	// Allowed characters for AS-Path expressions (note: '$' is allowed as end-of-path anchor, while shell chars remain blocked)
	forbiddenASPathChars = ";|&`()<>\\\"'%\n\r\t\x00"
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

// ValidateASPathOrASN validates an ASN number (e.g. "2914", "AS2914", "^AS2914", "4134$", "23764 4134")
// while preserving optional ^ (neighbor/entry ASN) and $ (origin ASN) anchors.
func ValidateASPathOrASN(target string) (cleaned string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("query target cannot be empty")
	}
	if len(target) > 64 {
		return "", errors.New("ASN or AS-Path length must be between 1 and 64 characters")
	}
	for _, r := range target {
		if r < 32 || r == 127 || strings.ContainsRune(forbiddenASPathChars, r) {
			return "", fmt.Errorf("AS-Path query contains forbidden character '%c'", r)
		}
	}
	// Reject "$(...)" command substitution forms explicitly (already blocked by '(' above, kept as defense-in-depth)
	if strings.Contains(target, "$(") {
		return "", errors.New("forbidden metacharacter sequence in AS-Path")
	}

	target = reASPrefixToken.ReplaceAllString(target, "${1}${2}")
	target = strings.Join(strings.Fields(target), " ")
	if target == "" || len(target) > 64 {
		return "", errors.New("ASN or AS-Path length must be between 1 and 64 characters")
	}
	if !reSafeASPath.MatchString(target) {
		return "", errors.New("AS-Path only allows digits, spaces, and safe regex anchors (^ $ _ . * + ? [ ] -)")
	}
	// If "$"" is used, it may only appear at the end of the expression as an origin anchor
	if idx := strings.IndexByte(target, '$'); idx != -1 && idx != len(target)-1 {
		return "", errors.New("'$' anchor is only allowed at the end of an AS-Path expression")
	}
	if idx := strings.LastIndexByte(target, '^'); idx > 0 {
		return "", errors.New("'^' anchor is only allowed at the start of an AS-Path expression")
	}

	// Ensure at least one valid non-zero 32-bit ASN is present
	stripped := strings.NewReplacer("^", " ", "$", " ", "_", " ").Replace(target)
	validASNCount := 0
	for _, tok := range strings.Fields(stripped) {
		tok = strings.Trim(tok, ".*+?[]-")
		if tok == "" {
			continue
		}
		num, errConv := strconv.ParseUint(tok, 10, 32)
		if errConv != nil {
			return "", fmt.Errorf("invalid ASN token %q in AS-Path expression", tok)
		}
		if num == 0 {
			return "", errors.New("ASN cannot be 0")
		}
		validASNCount++
	}
	if validASNCount == 0 {
		return "", errors.New("AS-Path expression must contain at least one valid ASN (1..4294967295)")
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
