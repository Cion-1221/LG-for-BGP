// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"lg-for-bgp/internal/models"
)

type PersistentData struct {
	Settings   models.SystemSettings  `json:"settings"`
	Users      []models.UserAccount   `json:"users"`
	POPs       []models.POPGroup      `json:"pops"`
	RRNodes    []models.RRNodeConfig  `json:"rr_nodes"`
	RouteViews []models.RouteViewMeta `json:"route_views"`
	AuditLogs  []models.AuditLogEntry `json:"audit_logs"`
}

type DBPoolOptions struct {
	MaxOpenConns           int
	MaxIdleConns           int
	ConnMaxLifetimeMinutes int
	ConnMaxIdleTimeMinutes int
}

type AppStore struct {
	mu                  sync.RWMutex
	db                  *sql.DB
	dbDriver            string // "mysql", "sqlite", or "" (file/memory)
	poolOpts            DBPoolOptions
	filePath            string
	jwtSecret           []byte
	jwtExpiryDays       int
	bootInstanceID      string // Ephemeral per-process boot ID; invalidates old sessions whenever lg-server restarts
	configuredAdminSlug string // Loaded from config.yaml (e.g. /admin, /console, etc.)
	auditRetentionDays  int
	auditMaxRows        int
	auditCleanerStarted bool
	stopCh              chan struct{}
	closeOnce           sync.Once
	data                PersistentData
}

func (s *AppStore) DBDriver() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dbDriver != "" {
		return s.dbDriver
	}
	if s.filePath == "" || s.filePath == "memory" {
		return "memory"
	}
	return "file"
}

func (s *AppStore) Close() error {
	s.closeOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		if s.dbDriver == "sqlite" {
			// Ensure WAL frames are flushed cleanly to the main database file on shutdown
			_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		}
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

func (s *AppStore) SetJWTConfig(secret string, refreshDays int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(secret) != "" {
		s.jwtSecret = []byte(secret)
	}
	if refreshDays > 0 {
		s.jwtExpiryDays = refreshDays
	}
}

func (s *AppStore) SetDBPoolOptions(opts DBPoolOptions) {
	s.mu.Lock()
	s.poolOpts = opts
	if s.db != nil {
		if s.dbDriver == "sqlite" {
			// SQLite works best with a single serialized connection in database/sql to avoid SQLITE_BUSY.
			s.db.SetMaxOpenConns(1)
			s.db.SetMaxIdleConns(1)
			s.db.SetConnMaxLifetime(0)
			s.db.SetConnMaxIdleTime(0)
		} else {
			if opts.MaxOpenConns > 0 {
				s.db.SetMaxOpenConns(opts.MaxOpenConns)
			}
			if opts.MaxIdleConns > 0 {
				s.db.SetMaxIdleConns(opts.MaxIdleConns)
			}
			if opts.ConnMaxLifetimeMinutes > 0 {
				s.db.SetConnMaxLifetime(time.Duration(opts.ConnMaxLifetimeMinutes) * time.Minute)
			}
			if opts.ConnMaxIdleTimeMinutes > 0 {
				s.db.SetConnMaxIdleTime(time.Duration(opts.ConnMaxIdleTimeMinutes) * time.Minute)
			}
		}
	}
	s.mu.Unlock()
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

// NewAppStore initializes the store using MySQL/MariaDB or SQLite3 when a corresponding DSN/path is provided,
// or falls back to local JSON/in-memory store for unit tests / standalone development.
func NewAppStore(dsnOrPath string) (*AppStore, error) {
	secret := os.Getenv("LG_JWT_SECRET")
	if secret == "" {
		secret = "open-source-bgp-looking-glass-default-jwt-secret"
	}

	if strings.TrimSpace(dsnOrPath) == "" {
		if envDSN := strings.TrimSpace(os.Getenv("LG_DB_DSN")); envDSN != "" {
			dsnOrPath = envDSN
		}
	}

	bootBytes := make([]byte, 16)
	_, _ = rand.Read(bootBytes)

	s := &AppStore{
		jwtSecret:          []byte(secret),
		bootInstanceID:     hex.EncodeToString(bootBytes),
		auditRetentionDays: 30,
		auditMaxRows:       50000,
		stopCh:             make(chan struct{}),
	}

	if isMySQLDSN(dsnOrPath) {
		if err := s.initMySQL(dsnOrPath); err != nil {
			return nil, err
		}
		return s, nil
	}

	if isSQLiteDSN(dsnOrPath) {
		if err := s.initSQLite(dsnOrPath); err != nil {
			return nil, err
		}
		return s, nil
	}

	s.filePath = dsnOrPath
	if err := s.loadOrInitFile(); err != nil {
		return nil, err
	}
	return s, nil
}

func isMySQLDSN(val string) bool {
	return strings.Contains(val, "@tcp(") || strings.Contains(val, "@unix(") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(val)), "mysql://")
}

func isSQLiteDSN(val string) bool {
	v := strings.TrimSpace(val)
	lower := strings.ToLower(v)
	if lower == ":memory:" {
		return true
	}
	if strings.HasPrefix(lower, "sqlite://") || strings.HasPrefix(lower, "sqlite:") || strings.HasPrefix(lower, "sqlite3:") {
		return true
	}
	return strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".sqlite3")
}

// LegacySHA256Hash computes the legacy salted SHA-256 password hash used by earlier versions,
// kept solely for transparent login migration to bcrypt.
func LegacySHA256Hash(password string) string {
	h := sha256.Sum256([]byte("lg-for-bgp-salt:" + password))
	return hex.EncodeToString(h[:])
}

// HashPassword hashes a plaintext password using bcrypt (salted, adaptive work factor).
func HashPassword(password string) string {
	// bcrypt truncates/errors past 72 bytes; pre-digest overly long passphrases consistently
	pwBytes := []byte(password)
	if len(pwBytes) > 72 {
		sum := sha256.Sum256(pwBytes)
		pwBytes = []byte("sha256:" + hex.EncodeToString(sum[:]))
	}
	hashed, err := bcrypt.GenerateFromPassword(pwBytes, bcrypt.DefaultCost)
	if err != nil {
		// Unreachable for <=72-byte input, defensive fallback
		return LegacySHA256Hash(password)
	}
	return string(hashed)
}

// VerifyPassword verifies a plaintext password against a stored bcrypt or legacy SHA-256 hash.
// Returns (matched, needsUpgrade) where needsUpgrade is true when a legacy hash matched and should be upgraded to bcrypt.
func VerifyPassword(storedHash, password string) (bool, bool) {
	if strings.HasPrefix(storedHash, "$2a$") || strings.HasPrefix(storedHash, "$2b$") || strings.HasPrefix(storedHash, "$2y$") {
		pwBytes := []byte(password)
		if len(pwBytes) > 72 {
			sum := sha256.Sum256(pwBytes)
			pwBytes = []byte("sha256:" + hex.EncodeToString(sum[:]))
		}
		return bcrypt.CompareHashAndPassword([]byte(storedHash), pwBytes) == nil, false
	}
	// Legacy SHA-256 verification with constant-time comparison
	legacy := LegacySHA256Hash(password)
	if hmac.Equal([]byte(storedHash), []byte(legacy)) {
		return true, true
	}
	return false, false
}

func defaultInitialData() PersistentData {
	now := time.Now()
	defaultSlug := strings.Trim(os.Getenv("LG_ADMIN_SECRET_SLUG"), "/")
	if defaultSlug == "" {
		defaultSlug = "console"
	}

	return PersistentData{
		Settings: models.SystemSettings{
			AccessMode:         models.AccessModePublic,
			AdminSecretSlug:    defaultSlug,
			PublicAllowedViews: []models.RouteViewID{},
			DefaultRRNode:      "auto",
			DefaultEngine:      "gobgp",
			CacheTTLSeconds:    30,
			RateLimitPerMinute: 60,
			OrganizationName:   "BGP Looking Glass Portal",
			PrimaryASN:         65000,
			DatacenterCode:     "CORE-POP-01",
			AllowRawOutput:     true,
			UpdatedAt:          now,
		},
		RouteViews: []models.RouteViewMeta{},
		POPs:       []models.POPGroup{},
		RRNodes:    []models.RRNodeConfig{},
		Users: []models.UserAccount{
			{
				ID:                 "u-admin",
				Username:           "admin",
				PasswordHash:       HashPassword("Admin@123456"),
				DisplayName:        "System Administrator",
				Company:            "Network Operations",
				CustomerASN:        65000,
				Role:               "admin",
				AllowedViews:       []models.RouteViewID{},
				RateLimitPerMinute: 300,
				Enabled:            true,
				MustChangePassword: true,
				Notes:              "Default superuser account for system administration",
				CreatedAt:          now,
			},
		},
		AuditLogs: []models.AuditLogEntry{},
	}
}

func (s *AppStore) loadOrInitFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.filePath != "" && s.filePath != "memory" {
		if _, err := os.Stat(s.filePath); err == nil {
			raw, errRead := os.ReadFile(s.filePath)
			if errRead == nil {
				if errUnmarshal := json.Unmarshal(raw, &s.data); errUnmarshal == nil && len(s.data.Users) > 0 {
					if s.data.Settings.AdminSecretSlug == "" {
						s.data.Settings.AdminSecretSlug = "console"
					}
					s.migrateLegacyViewBindingsLocked()
					return nil
				}
			}
		}
	}

	s.data = defaultInitialData()
	return s.persistFileLocked()
}

func (s *AppStore) persistFileLocked() error {
	if s.filePath == "" || s.filePath == "memory" {
		return nil
	}
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, raw, 0600)
}

// GetPublicSettings returns SystemSettings with AdminSecretSlug stripped out so public visitors cannot see it.
func (s *AppStore) GetPublicSettings() models.SystemSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.data.Settings
	cp.AdminSecretSlug = ""
	return cp
}

// GetAdminSettings returns full SystemSettings including AdminSecretSlug for authenticated administrators.
func (s *AppStore) GetAdminSettings() models.SystemSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.data.Settings
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
	s.data.Settings = newSettings
	err := s.upsertSettingsDBLocked()
	return s.data.Settings, err
}

func (s *AppStore) GetRouteViews() []models.RouteViewMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RouteViewMeta, len(s.data.RouteViews))
	for i, v := range s.data.RouteViews {
		cp := v
		if len(v.RRNodeIDs) > 0 {
			cp.RRNodeIDs = append([]string(nil), v.RRNodeIDs...)
		} else {
			cp.RRNodeIDs = []string{}
		}
		out[i] = cp
	}
	return out
}

func (s *AppStore) GetRouteViewMap() map[models.RouteViewID]models.RouteViewMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[models.RouteViewID]models.RouteViewMeta, len(s.data.RouteViews))
	for _, v := range s.data.RouteViews {
		cp := v
		if len(v.RRNodeIDs) > 0 {
			cp.RRNodeIDs = append([]string(nil), v.RRNodeIDs...)
		} else {
			cp.RRNodeIDs = []string{}
		}
		m[v.ID] = cp
	}
	return m
}

func sanitizeIDSlug(val string) string {
	val = strings.ToLower(strings.TrimSpace(val))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range val {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func normalizeRRNodeIDs(raw []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, id := range raw {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if strings.EqualFold(trimmed, "all") {
			return []string{"all"}
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func normalizeLoadedRouteView(v *models.RouteViewMeta) {
	v.POP = strings.TrimSpace(v.POP)
	if v.POP == "" {
		v.POP = "all"
	}
	v.RRNodeIDs = normalizeRRNodeIDs(v.RRNodeIDs)
	v.Type = strings.ToLower(strings.TrimSpace(v.Type))
	if v.Type != "auto" && v.Type != "gobgp" && v.Type != "bird2" && v.Type != "frr" {
		v.Type = "auto"
	}
	v.VRFName = strings.TrimSpace(v.VRFName)
	if v.VRFName == "" || strings.EqualFold(v.VRFName, "global") || strings.EqualFold(v.VRFName, "default") || strings.EqualFold(v.VRFName, "master") {
		v.VRFName = "global"
		v.ShortName = "GLOBAL"
		v.JunosContextType = "global-rib"
		v.JunosContextName = "global"
		v.JunosTable = "inet.0 / inet6.0 (Global RIB)"
	} else {
		v.ShortName = v.VRFName
		v.JunosContextType = "routing-instances"
		v.JunosContextName = v.VRFName
		v.JunosTable = v.VRFName + ".inet.0"
	}
	v.BirdTableV4 = v.VRFName
	v.FrrViewName = v.VRFName
}

// migrateLegacyViewBindingsLocked backfills RRNodeIDs for pre-existing VRFs created before VRF<->RR binding existed.
func (s *AppStore) migrateLegacyViewBindingsLocked() bool {
	changed := false
	for i := range s.data.RouteViews {
		v := &s.data.RouteViews[i]
		if len(v.RRNodeIDs) > 0 {
			continue
		}
		pop := strings.TrimSpace(v.POP)
		if pop == "" || strings.EqualFold(pop, "all") {
			v.RRNodeIDs = []string{"all"}
			changed = true
			continue
		}
		var matchedRRs []string
		for _, n := range s.data.RRNodes {
			if strings.EqualFold(strings.TrimSpace(n.Location), pop) {
				matchedRRs = append(matchedRRs, n.ID)
			}
		}
		if len(matchedRRs) > 0 {
			v.RRNodeIDs = matchedRRs
			changed = true
		}
	}
	return changed
}

// deriveViewPOPLocked derives the legacy POP label from bound RRNodeIDs for display/compatibility.
func (s *AppStore) deriveViewPOPLocked(rrNodeIDs []string, fallbackPOP string) string {
	if len(rrNodeIDs) == 1 && strings.EqualFold(rrNodeIDs[0], "all") {
		return "all"
	}
	if len(rrNodeIDs) == 0 {
		if p := strings.TrimSpace(fallbackPOP); p != "" {
			return p
		}
		return "none"
	}
	rrMap := make(map[string]models.RRNodeConfig, len(s.data.RRNodes))
	for _, n := range s.data.RRNodes {
		rrMap[n.ID] = n
	}
	popSet := make(map[string]string)
	for _, id := range rrNodeIDs {
		if n, ok := rrMap[id]; ok && strings.TrimSpace(n.Location) != "" {
			popSet[strings.ToUpper(strings.TrimSpace(n.Location))] = strings.TrimSpace(n.Location)
		}
	}
	if len(popSet) == 1 {
		for _, p := range popSet {
			return p
		}
	}
	if len(popSet) > 1 {
		return "multi"
	}
	if p := strings.TrimSpace(fallbackPOP); p != "" {
		return p
	}
	return "all"
}

func (s *AppStore) UpsertRouteView(view models.RouteViewMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	view.VRFName = strings.TrimSpace(view.VRFName)
	if view.VRFName == "" || strings.EqualFold(view.VRFName, "global") || strings.EqualFold(view.VRFName, "default") || strings.EqualFold(view.VRFName, "master") {
		view.VRFName = "global"
	}
	view.Type = strings.ToLower(strings.TrimSpace(view.Type))
	if view.Type != "auto" && view.Type != "gobgp" && view.Type != "bird2" && view.Type != "frr" {
		view.Type = "auto"
	}

	view.RRNodeIDs = normalizeRRNodeIDs(view.RRNodeIDs)
	// Backwards-compatible fallback when caller sets POP without RRNodeIDs
	if len(view.RRNodeIDs) == 0 {
		p := strings.TrimSpace(view.POP)
		if p == "" || strings.EqualFold(p, "all") {
			view.RRNodeIDs = []string{"all"}
		} else {
			for _, n := range s.data.RRNodes {
				if strings.EqualFold(strings.TrimSpace(n.Location), p) {
					view.RRNodeIDs = append(view.RRNodeIDs, n.ID)
				}
			}
		}
	}

	view.POP = s.deriveViewPOPLocked(view.RRNodeIDs, view.POP)

	if strings.TrimSpace(string(view.ID)) == "" {
		slug := sanitizeIDSlug(view.VRFName)
		if slug == "" || slug == "global" {
			slug = "global_rib"
		}
		if len(view.RRNodeIDs) == 1 && !strings.EqualFold(view.RRNodeIDs[0], "all") {
			if rrSlug := sanitizeIDSlug(view.RRNodeIDs[0]); rrSlug != "" {
				slug = rrSlug + "_" + slug
			}
		} else if view.POP != "" && !strings.EqualFold(view.POP, "all") && !strings.EqualFold(view.POP, "multi") && !strings.EqualFold(view.POP, "none") {
			if popSlug := sanitizeIDSlug(view.POP); popSlug != "" {
				slug = popSlug + "_" + slug
			}
		}
		if len(slug) > 64 {
			slug = strings.TrimRight(slug[:64], "_")
		}
		// Ensure auto-generated ID doesn't accidentally overwrite an unrelated existing view
		candidate := models.RouteViewID(slug)
		exists := func(id models.RouteViewID) bool {
			for _, ex := range s.data.RouteViews {
				if ex.ID == id {
					return true
				}
			}
			return false
		}
		if exists(candidate) {
			for n := 2; n < 100; n++ {
				suffix := fmt.Sprintf("_%d", n)
				base := slug
				if len(base)+len(suffix) > 64 {
					base = base[:64-len(suffix)]
				}
				alt := models.RouteViewID(base + suffix)
				if !exists(alt) {
					candidate = alt
					break
				}
			}
		}
		view.ID = candidate
	}

	if view.ShortName == "" {
		if view.VRFName == "global" {
			view.ShortName = "GLOBAL"
		} else {
			view.ShortName = view.VRFName
		}
	}
	if view.JunosContextName == "" {
		view.JunosContextName = view.VRFName
	}
	if view.JunosContextType == "" {
		if view.VRFName == "global" {
			view.JunosContextType = "global-rib"
		} else {
			view.JunosContextType = "routing-instances"
		}
	}
	if view.JunosTable == "" {
		if view.VRFName == "global" {
			view.JunosTable = "inet.0 / inet6.0 (Global RIB)"
		} else {
			view.JunosTable = view.VRFName + ".inet.0"
		}
	}
	view.BirdTableV4 = view.VRFName
	view.FrrViewName = view.VRFName
	view.JuniperSourceIPv4 = strings.TrimSpace(view.JuniperSourceIPv4)

	for i, existing := range s.data.RouteViews {
		if existing.ID == view.ID {
			s.data.RouteViews[i] = view
			if err := s.upsertRouteViewDBLocked(view, i); err != nil {
				return err
			}
			if s.pruneStaleViewIDsLocked() {
				return s.syncAllowedViewsDBLocked()
			}
			return nil
		}
	}

	idx := len(s.data.RouteViews)
	s.data.RouteViews = append(s.data.RouteViews, view)
	// Also append to PublicAllowedViews and admin/noc AllowedViews by default so new VRFs are immediately queryable
	s.data.Settings.PublicAllowedViews = append(s.data.Settings.PublicAllowedViews, view.ID)
	for i := range s.data.Users {
		if s.data.Users[i].Role == "admin" || s.data.Users[i].Role == "noc" {
			s.data.Users[i].AllowedViews = append(s.data.Users[i].AllowedViews, view.ID)
		}
	}
	s.pruneStaleViewIDsLocked()
	if err := s.upsertRouteViewDBLocked(view, idx); err != nil {
		return err
	}
	return s.syncAllowedViewsDBLocked()
}

// pruneStaleViewIDsLocked removes any deleted/non-existent VRF view IDs from PublicAllowedViews and all user accounts,
// and ensures admin accounts always have the exact list of currently existing VRF views.
// Returns true if any list was modified.
func (s *AppStore) pruneStaleViewIDsLocked() bool {
	validSet := make(map[models.RouteViewID]bool, len(s.data.RouteViews))
	allIDs := make([]models.RouteViewID, 0, len(s.data.RouteViews))
	for _, v := range s.data.RouteViews {
		validSet[v.ID] = true
		allIDs = append(allIDs, v.ID)
	}

	changed := false
	var cleanPub []models.RouteViewID
	seenPub := make(map[models.RouteViewID]bool)
	for _, id := range s.data.Settings.PublicAllowedViews {
		if validSet[id] && !seenPub[id] {
			cleanPub = append(cleanPub, id)
			seenPub[id] = true
		} else {
			changed = true
		}
	}
	if cleanPub == nil {
		cleanPub = []models.RouteViewID{}
	}
	if len(cleanPub) != len(s.data.Settings.PublicAllowedViews) {
		changed = true
	}
	s.data.Settings.PublicAllowedViews = cleanPub

	for i := range s.data.Users {
		if s.data.Users[i].Role == "admin" {
			if len(s.data.Users[i].AllowedViews) != len(allIDs) {
				changed = true
			} else {
				for j := range allIDs {
					if s.data.Users[i].AllowedViews[j] != allIDs[j] {
						changed = true
						break
					}
				}
			}
			cp := make([]models.RouteViewID, len(allIDs))
			copy(cp, allIDs)
			s.data.Users[i].AllowedViews = cp
			continue
		}
		var cleanUserViews []models.RouteViewID
		seenUser := make(map[models.RouteViewID]bool)
		for _, id := range s.data.Users[i].AllowedViews {
			if validSet[id] && !seenUser[id] {
				cleanUserViews = append(cleanUserViews, id)
				seenUser[id] = true
			} else {
				changed = true
			}
		}
		if cleanUserViews == nil {
			cleanUserViews = []models.RouteViewID{}
		}
		s.data.Users[i].AllowedViews = cleanUserViews
	}
	return changed
}

func (s *AppStore) DeleteRouteView(id models.RouteViewID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var filtered []models.RouteViewMeta
	for _, v := range s.data.RouteViews {
		if v.ID != id {
			filtered = append(filtered, v)
		}
	}
	s.data.RouteViews = filtered
	s.pruneStaleViewIDsLocked()
	if s.db != nil {
		if _, err := s.db.Exec("DELETE FROM lg_vrfs WHERE id = ?", string(id)); err != nil {
			return err
		}
		return s.syncAllowedViewsDBLocked()
	}
	return s.persistFileLocked()
}

func (s *AppStore) GetPOPs() []models.POPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.POPGroup, len(s.data.POPs))
	copy(out, s.data.POPs)
	return out
}

func (s *AppStore) ensurePOPsFromRRNodesLocked() []models.POPGroup {
	seen := make(map[string]bool, len(s.data.POPs))
	for _, p := range s.data.POPs {
		seen[strings.ToUpper(strings.TrimSpace(p.ID))] = true
	}
	var added []models.POPGroup
	for _, n := range s.data.RRNodes {
		loc := strings.TrimSpace(n.Location)
		if loc == "" {
			continue
		}
		key := strings.ToUpper(loc)
		if !seen[key] {
			seen[key] = true
			newPOP := models.POPGroup{
				ID:          loc,
				Name:        loc,
				Description: "",
				SortOrder:   len(s.data.POPs) + 1,
			}
			s.data.POPs = append(s.data.POPs, newPOP)
			added = append(added, newPOP)
		}
	}
	return added
}

func (s *AppStore) UpsertPOP(pop models.POPGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pop.ID = strings.TrimSpace(pop.ID)
	pop.Name = strings.TrimSpace(pop.Name)
	if pop.ID == "" && pop.Name != "" {
		pop.ID = strings.ToUpper(strings.ReplaceAll(pop.Name, " ", "-"))
	}
	if pop.ID == "" {
		return errors.New("PoP ID / Code is required")
	}
	if pop.Name == "" {
		pop.Name = pop.ID
	}
	if pop.SortOrder <= 0 {
		pop.SortOrder = len(s.data.POPs) + 1
	}
	for i, existing := range s.data.POPs {
		if strings.EqualFold(existing.ID, pop.ID) {
			pop.ID = existing.ID
			s.data.POPs[i] = pop
			return s.upsertPOPDBLocked(pop, i+1)
		}
	}
	s.data.POPs = append(s.data.POPs, pop)
	return s.upsertPOPDBLocked(pop, len(s.data.POPs))
}

func (s *AppStore) DeletePOP(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	// Enforce strict RR -> 1 PoP invariant: cannot delete a PoP while RRs are still bound to it
	boundCount := 0
	for _, n := range s.data.RRNodes {
		if strings.EqualFold(strings.TrimSpace(n.Location), id) {
			boundCount++
		}
	}
	if boundCount > 0 {
		return fmt.Errorf("cannot delete PoP %q: %d RR node(s) are still bound to this PoP; reassign or delete those RR nodes first", id, boundCount)
	}

	var filtered []models.POPGroup
	for _, p := range s.data.POPs {
		if !strings.EqualFold(p.ID, id) {
			filtered = append(filtered, p)
		}
	}
	s.data.POPs = filtered
	if s.db != nil {
		_, err := s.db.Exec("DELETE FROM lg_pops WHERE id = ?", id)
		return err
	}
	return s.persistFileLocked()
}

func (s *AppStore) GetRRNodes() []models.RRNodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RRNodeConfig, len(s.data.RRNodes))
	copy(out, s.data.RRNodes)
	return out
}

// GetPublicRRNodes returns RR nodes with sensitive internal fields (AgentToken, Endpoint, LoopbackIP) stripped out
// so public visitors cannot discover internal collector / agent IPs or ports.
func (s *AppStore) GetPublicRRNodes() []models.RRNodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RRNodeConfig, len(s.data.RRNodes))
	for i, n := range s.data.RRNodes {
		cp := n
		cp.AgentToken = ""
		cp.Endpoint = ""
		cp.LoopbackIP = ""
		out[i] = cp
	}
	return out
}

func (s *AppStore) UpsertRRNode(node models.RRNodeConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	node.ID = strings.TrimSpace(node.ID)
	if node.ID == "" {
		node.ID = fmt.Sprintf("rr-%02d", len(s.data.RRNodes)+1)
	}
	node.Name = strings.TrimSpace(node.Name)
	if node.Name == "" {
		node.Name = strings.ToUpper(node.ID)
	}
	node.EngineType = strings.ToLower(strings.TrimSpace(node.EngineType))
	if node.EngineType != "gobgp" && node.EngineType != "bird2" && node.EngineType != "frr" {
		node.EngineType = "gobgp"
	}
	node.Endpoint = strings.TrimSpace(node.Endpoint)
	if node.Endpoint == "" {
		switch node.EngineType {
		case "gobgp":
			node.Endpoint = "127.0.0.1:50051"
		case "bird2":
			node.Endpoint = "/run/bird/bird.ctl"
		case "frr":
			node.Endpoint = "/run/frr"
		}
	}
	node.AgentToken = strings.TrimSpace(node.AgentToken)
	node.LoopbackIP = strings.TrimSpace(node.LoopbackIP)
	if node.LoopbackIP == "" {
		node.LoopbackIP = "127.0.0.1"
	}
	node.Role = strings.ToLower(strings.TrimSpace(node.Role))
	if node.Role != "primary" && node.Role != "backup" && node.Role != "secondary" {
		node.Role = "primary"
	}
	node.Location = strings.TrimSpace(node.Location)
	if node.Location == "" || strings.EqualFold(node.Location, "all") {
		if len(s.data.POPs) > 0 {
			node.Location = s.data.POPs[0].ID
		} else {
			node.Location = "CORE-POP-01"
		}
	}
	if node.LastChecked == "" {
		node.LastChecked = time.Now().Format(time.RFC3339)
	}

	updated := false
	for i, existing := range s.data.RRNodes {
		if existing.ID == node.ID {
			s.data.RRNodes[i] = node
			updated = true
			break
		}
	}
	if !updated {
		s.data.RRNodes = append(s.data.RRNodes, node)
	}

	addedPOPs := s.ensurePOPsFromRRNodesLocked()
	if err := s.upsertRRNodeDBLocked(node); err != nil {
		return err
	}
	for _, p := range addedPOPs {
		_ = s.upsertPOPDBLocked(p, p.SortOrder)
	}
	// Refresh derived POP metadata on any VRFs bound to this RR
	for idx := range s.data.RouteViews {
		v := &s.data.RouteViews[idx]
		for _, rid := range v.RRNodeIDs {
			if rid == node.ID {
				nextPOP := s.deriveViewPOPLocked(v.RRNodeIDs, v.POP)
				if nextPOP != v.POP {
					v.POP = nextPOP
					_ = s.upsertRouteViewDBLocked(*v, idx)
				}
				break
			}
		}
	}
	return nil
}

// UpdateRRNodeHealth incrementally updates only healthy + last_checked for a single RR node.
func (s *AppStore) UpdateRRNodeHealth(id string, healthy bool, lastChecked string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.RRNodes {
		if s.data.RRNodes[i].ID == id {
			s.data.RRNodes[i].Healthy = healthy
			s.data.RRNodes[i].LastChecked = lastChecked
			return s.updateRRNodeHealthDBLocked(id, healthy, lastChecked)
		}
	}
	return fmt.Errorf("RR node %q not found", id)
}

func (s *AppStore) DeleteRRNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var filtered []models.RRNodeConfig
	for _, n := range s.data.RRNodes {
		if n.ID != id {
			filtered = append(filtered, n)
		}
	}
	s.data.RRNodes = filtered

	// Remove deleted RR ID from any VRF's RRNodeIDs so no dangling RR reference remains
	var modifiedViewIdxs []int
	for idx := range s.data.RouteViews {
		v := &s.data.RouteViews[idx]
		if len(v.RRNodeIDs) == 0 || (len(v.RRNodeIDs) == 1 && strings.EqualFold(v.RRNodeIDs[0], "all")) {
			continue
		}
		var kept []string
		removed := false
		for _, rid := range v.RRNodeIDs {
			if rid == id {
				removed = true
				continue
			}
			kept = append(kept, rid)
		}
		if removed {
			if kept == nil {
				kept = []string{}
			}
			v.RRNodeIDs = kept
			v.POP = s.deriveViewPOPLocked(v.RRNodeIDs, "none")
			modifiedViewIdxs = append(modifiedViewIdxs, idx)
		}
	}

	if s.db != nil {
		if _, err := s.db.Exec("DELETE FROM lg_rr_nodes WHERE id = ?", id); err != nil {
			return err
		}
		for _, idx := range modifiedViewIdxs {
			if err := s.upsertRouteViewDBLocked(s.data.RouteViews[idx], idx); err != nil {
				return err
			}
		}
		return nil
	}
	return s.persistFileLocked()
}

func (s *AppStore) GetUsers() []models.UserAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.UserAccount, len(s.data.Users))
	for i, u := range s.data.Users {
		uCopy := u
		uCopy.PasswordHash = ""
		out[i] = uCopy
	}
	return out
}

func (s *AppStore) Authenticate(username, password string) (*models.UserAccount, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.EqualFold(u.Username, username) {
			if !u.Enabled {
				return nil, "", errors.New("account has been disabled by administrator")
			}
			ok, needsUpgrade := VerifyPassword(u.PasswordHash, password)
			if !ok {
				return nil, "", errors.New("invalid username or password")
			}
			if needsUpgrade {
				// Transparent zero-downtime upgrade from legacy SHA-256 to salted bcrypt
				u.PasswordHash = HashPassword(password)
				_ = s.updateUserPasswordDBLocked(u.ID, u.PasswordHash, u.MustChangePassword)
				log.Printf("[AUTH] Upgraded legacy password hash to bcrypt for user %q", u.Username)
			}
			now := time.Now()
			u.LastLoginAt = &now
			_ = s.updateUserLastLoginDBLocked(u.ID, now)

			uSafe := *u
			token, err := s.issueTokenWithHashLocked(uSafe, u.PasswordHash)
			uSafe.PasswordHash = ""
			return &uSafe, token, err
		}
	}
	return nil, "", errors.New("invalid username or password")
}

func (s *AppStore) GetUserByUsername(username string) (*models.UserAccount, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if strings.EqualFold(u.Username, username) && u.Enabled {
			uCopy := u
			uCopy.PasswordHash = ""
			return &uCopy, true
		}
	}
	return nil, false
}

func (s *AppStore) SaveUser(account models.UserAccount, rawPassword string) (*models.UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(account.Username) == "" {
		return nil, errors.New("username cannot be empty")
	}

	for i, existing := range s.data.Users {
		if existing.ID == account.ID || strings.EqualFold(existing.Username, account.Username) {
			account.ID = existing.ID
			account.CreatedAt = existing.CreatedAt
			account.LastLoginAt = existing.LastLoginAt
			if strings.TrimSpace(rawPassword) != "" {
				account.PasswordHash = HashPassword(rawPassword)
			} else {
				account.PasswordHash = existing.PasswordHash
			}
			s.data.Users[i] = account
			s.pruneStaleViewIDsLocked()
			if err := s.upsertUserDBLocked(s.data.Users[i]); err != nil {
				return nil, err
			}
			out := s.data.Users[i]
			out.PasswordHash = ""
			return &out, nil
		}
	}

	if strings.TrimSpace(rawPassword) == "" {
		return nil, errors.New("password is required when creating a new account")
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	account.ID = "u-" + hex.EncodeToString(b)
	account.PasswordHash = HashPassword(rawPassword)
	account.CreatedAt = time.Now()
	s.data.Users = append(s.data.Users, account)
	s.pruneStaleViewIDsLocked()
	saved := s.data.Users[len(s.data.Users)-1]
	if err := s.upsertUserDBLocked(saved); err != nil {
		return nil, err
	}
	out := saved
	out.PasswordHash = ""
	return &out, nil
}

// ChangePassword allows an authenticated user to change their own password and clears MustChangePassword.
func (s *AppStore) ChangePassword(username, currentPassword, newPassword string) (*models.UserAccount, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newPassword = strings.TrimSpace(newPassword)
	if len(newPassword) < 6 {
		return nil, "", errors.New("new password must be at least 6 characters long")
	}

	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.EqualFold(u.Username, username) {
			ok, _ := VerifyPassword(u.PasswordHash, currentPassword)
			if !ok {
				return nil, "", errors.New("current password is incorrect")
			}
			u.PasswordHash = HashPassword(newPassword)
			u.MustChangePassword = false
			if err := s.updateUserPasswordDBLocked(u.ID, u.PasswordHash, false); err != nil {
				return nil, "", err
			}
			uSafe := *u
			token, err := s.issueTokenWithHashLocked(uSafe, u.PasswordHash)
			uSafe.PasswordHash = ""
			return &uSafe, token, err
		}
	}
	return nil, "", errors.New("user account not found")
}

func (s *AppStore) DeleteUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var filtered []models.UserAccount
	for _, u := range s.data.Users {
		if u.ID == userID {
			if u.Username == "admin" {
				return errors.New("cannot delete default administrator account 'admin'")
			}
			continue
		}
		filtered = append(filtered, u)
	}
	s.data.Users = filtered
	if s.db != nil {
		_, err := s.db.Exec("DELETE FROM lg_users WHERE id = ?", userID)
		return err
	}
	return s.persistFileLocked()
}

func (s *AppStore) AppendAuditLog(entry models.AuditLogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.Timestamp = time.Now()
	log.Printf("[AUDIT] user=%s ip=%s action=%s type=%s target=%s views=[%s] rr=%s duration=%dms",
		entry.Username, entry.ClientIP, entry.Action, entry.QueryType, entry.Target, entry.Views, entry.RRNode, entry.DurationMs)
	s.data.AuditLogs = append([]models.AuditLogEntry{entry}, s.data.AuditLogs...)
	if len(s.data.AuditLogs) > 1000 {
		s.data.AuditLogs = s.data.AuditLogs[:1000]
	}
	if s.db != nil {
		_, _ = s.db.Exec(`
			INSERT INTO lg_audit_logs (timestamp, username, client_ip, action, query_type, target, views, rr_node, duration_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, s.dbTimeArg(entry.Timestamp), entry.Username, entry.ClientIP, entry.Action, entry.QueryType, entry.Target, entry.Views, entry.RRNode, entry.DurationMs)
	} else {
		_ = s.persistFileLocked()
	}
}

func (s *AppStore) GetAuditLogs() []models.AuditLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AuditLogEntry, len(s.data.AuditLogs))
	copy(out, s.data.AuditLogs)
	return out
}

type tokenPayload struct {
	Username string `json:"sub"`
	Role     string `json:"role"`
	BootID   string `json:"bid"`
	PwdTag   string `json:"ptg"`
	Exp      int64  `json:"exp"`
}

func (s *AppStore) pwdTagOf(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:6])
}

func (s *AppStore) IssueToken(user models.UserAccount) (string, error) {
	pHash := user.PasswordHash
	if pHash == "" {
		for _, u := range s.data.Users {
			if strings.EqualFold(u.Username, user.Username) {
				pHash = u.PasswordHash
				break
			}
		}
	}
	return s.issueTokenWithHashLocked(user, pHash)
}

func (s *AppStore) issueTokenWithHashLocked(user models.UserAccount, pHash string) (string, error) {
	days := s.jwtExpiryDays
	if days <= 0 {
		days = 7
	}
	payload := tokenPayload{
		Username: user.Username,
		Role:     user.Role,
		BootID:   s.bootInstanceID,
		PwdTag:   s.pwdTagOf(pHash),
		Exp:      time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix(),
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(rawJSON)
	mac := hmac.New(sha256.New, append(append([]byte{}, s.jwtSecret...), []byte(":"+s.bootInstanceID)...))
	mac.Write([]byte(b64Payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return b64Payload + "." + sig, nil
}

func (s *AppStore) VerifyToken(token string) (*models.UserAccount, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	s.mu.RLock()
	secretWithBoot := append(append([]byte{}, s.jwtSecret...), []byte(":"+s.bootInstanceID)...)
	bootID := s.bootInstanceID
	s.mu.RUnlock()

	mac := hmac.New(sha256.New, secretWithBoot)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("session expired or server restarted")
	}
	rawJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var payload tokenPayload
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		return nil, err
	}
	if payload.BootID != bootID {
		return nil, errors.New("server restarted, please sign in again")
	}
	if time.Now().Unix() > payload.Exp {
		return nil, errors.New("token expired")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if strings.EqualFold(u.Username, payload.Username) && u.Enabled {
			if payload.PwdTag != "" && payload.PwdTag != s.pwdTagOf(u.PasswordHash) {
				return nil, errors.New("password has changed, please sign in again")
			}
			uCopy := u
			uCopy.PasswordHash = ""
			return &uCopy, nil
		}
	}
	return nil, errors.New("user not found or disabled")
}
