// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"crypto/hmac"
	"os"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
)

func normalizeFilterRouteLimit(v int) int {
	if v <= 0 {
		return 50
	}
	if v > 5000 {
		return 5000
	}
	return v
}

// SetConfiguredAdminPath sets the admin portal path specified in config.yaml.
func (s *AppStore) SetConfiguredAdminPath(adminPath string) {
	slug := strings.Trim(strings.TrimSpace(adminPath), "/")
	if slug == "" {
		return
	}
	s.mu.Lock()
	s.configuredAdminSlug = slug
	s.data.Settings.AdminSecretSlug = slug
	s.mu.Unlock()
}

// GetPublicSettings returns SystemSettings with AdminSecretSlug stripped out so public visitors cannot see it.
func (s *AppStore) GetPublicSettings() models.SystemSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.data.Settings
	cp.AdminSecretSlug = ""
	cp.MaxFilterRoutesV4 = normalizeFilterRouteLimit(cp.MaxFilterRoutesV4)
	cp.MaxFilterRoutesV6 = normalizeFilterRouteLimit(cp.MaxFilterRoutesV6)
	return cp
}

// GetAdminSettings returns full SystemSettings including AdminSecretSlug for authenticated administrators.
func (s *AppStore) GetAdminSettings() models.SystemSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.data.Settings
	cp.MaxFilterRoutesV4 = normalizeFilterRouteLimit(cp.MaxFilterRoutesV4)
	cp.MaxFilterRoutesV6 = normalizeFilterRouteLimit(cp.MaxFilterRoutesV6)
	if s.configuredAdminSlug != "" {
		cp.AdminSecretSlug = s.configuredAdminSlug
	} else if envSlug := strings.Trim(os.Getenv("LG_ADMIN_SECRET_SLUG"), "/"); envSlug != "" {
		cp.AdminSecretSlug = envSlug
	}
	return cp
}

// GetSettings is an alias for internal engine reads.
func (s *AppStore) GetSettings() models.SystemSettings {
	return s.GetPublicSettings()
}

// VerifyAdminSlug performs constant-time comparison of the candidate URL slug against the admin path in config.yaml.
func (s *AppStore) VerifyAdminSlug(candidate string) bool {
	candidate = strings.Trim(strings.TrimSpace(candidate), "/")
	if candidate == "" {
		return false
	}
	s.mu.RLock()
	confSlug := s.configuredAdminSlug
	dbSlug := strings.Trim(s.data.Settings.AdminSecretSlug, "/")
	s.mu.RUnlock()

	secretSlug := dbSlug
	if confSlug != "" {
		secretSlug = confSlug
	} else if envSlug := strings.Trim(os.Getenv("LG_ADMIN_SECRET_SLUG"), "/"); envSlug != "" {
		secretSlug = envSlug
	}
	if secretSlug == "" {
		secretSlug = "console"
	}
	return hmac.Equal([]byte(candidate), []byte(secretSlug))
}

func (s *AppStore) UpdateSettings(newSettings models.SystemSettings) (models.SystemSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newSettings.UpdatedAt = time.Now()
	newSettings.AdminSecretSlug = strings.Trim(strings.TrimSpace(newSettings.AdminSecretSlug), "/")
	if s.configuredAdminSlug != "" {
		newSettings.AdminSecretSlug = s.configuredAdminSlug
	} else if newSettings.AdminSecretSlug == "" {
		newSettings.AdminSecretSlug = s.data.Settings.AdminSecretSlug
	}
	newSettings.MaxFilterRoutesV4 = normalizeFilterRouteLimit(newSettings.MaxFilterRoutesV4)
	newSettings.MaxFilterRoutesV6 = normalizeFilterRouteLimit(newSettings.MaxFilterRoutesV6)
	s.data.Settings = newSettings
	err := s.upsertSettingsDBLocked()
	return s.data.Settings, err
}
