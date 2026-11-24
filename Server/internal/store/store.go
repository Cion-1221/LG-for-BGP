// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

	// Dedicated asynchronous audit subsystem (decoupled from AppStore.mu hot path)
	auditMu             sync.RWMutex
	auditLogs           []models.AuditLogEntry
	auditCh             chan models.AuditLogEntry
	auditStopCh         chan struct{}
	auditWG             sync.WaitGroup
	auditRetentionDays  int
	auditMaxRows        int
	auditCleanerStarted bool

	stopCh    chan struct{}
	closeOnce sync.Once
	data      PersistentData
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
		auditLogs:          make([]models.AuditLogEntry, 0, 128),
		auditCh:            make(chan models.AuditLogEntry, 4096),
		auditStopCh:        make(chan struct{}),
		auditRetentionDays: 30,
		auditMaxRows:       50000,
		stopCh:             make(chan struct{}),
	}

	if isMySQLDSN(dsnOrPath) {
		if err := s.initMySQL(dsnOrPath); err != nil {
			return nil, err
		}
		s.startAuditWorker()
		return s, nil
	}

	if isSQLiteDSN(dsnOrPath) {
		if err := s.initSQLite(dsnOrPath); err != nil {
			return nil, err
		}
		s.startAuditWorker()
		return s, nil
	}

	s.filePath = dsnOrPath
	if err := s.loadOrInitFile(); err != nil {
		return nil, err
	}
	s.startAuditWorker()
	return s, nil
}

func (s *AppStore) Close() error {
	s.closeOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
		if s.auditStopCh != nil {
			close(s.auditStopCh)
		}
	})
	// Wait for the async audit batch worker to drain and persist all queued entries
	s.auditWG.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		if s.dbDriver == "sqlite" {
			_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		}
		err := s.db.Close()
		s.db = nil
		return err
	}
	return nil
}

func (s *AppStore) SetDBPoolOptions(opts DBPoolOptions) {
	s.mu.Lock()
	s.poolOpts = opts
	if s.db != nil {
		if s.dbDriver == "sqlite" {
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
			MaxFilterRoutesV4:  50,
			MaxFilterRoutesV6:  50,
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
					for i := range s.data.RouteViews {
						normalizeLoadedRouteView(&s.data.RouteViews[i])
					}
					s.migrateLegacyViewBindingsLocked()
					s.auditMu.Lock()
					s.auditLogs = append([]models.AuditLogEntry(nil), s.data.AuditLogs...)
					s.auditMu.Unlock()
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
	s.auditMu.RLock()
	s.data.AuditLogs = make([]models.AuditLogEntry, len(s.auditLogs))
	copy(s.data.AuditLogs, s.auditLogs)
	s.auditMu.RUnlock()

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
