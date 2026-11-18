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

	"lg-for-bgp/internal/models"
)

type PersistentData struct {
	Settings    models.SystemSettings       `json:"settings"`
	Users       []models.UserAccount        `json:"users"`
	Communities []models.CommunityDictEntry `json:"communities"`
	POPs        []models.POPGroup           `json:"pops"`
	RRNodes     []models.RRNodeConfig       `json:"rr_nodes"`
	RouteViews  []models.RouteViewMeta      `json:"route_views"`
	AuditLogs   []models.AuditLogEntry      `json:"audit_logs"`
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
	poolOpts            DBPoolOptions
	filePath            string
	jwtSecret           []byte
	jwtExpiryDays       int
	bootInstanceID      string // Ephemeral per-process boot ID; invalidates old sessions whenever lg-server restarts
	configuredAdminSlug string // Loaded from config.yaml (e.g. /admin, /console, etc.)
	data                PersistentData
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
	s.mu.Unlock()
}

// SetConfiguredAdminPath sets the admin portal path specified in lg-server.conf.
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

// NewAppStore initializes the store using MySQL/MariaDB if a DSN is provided (via LG_DB_DSN or parameter),
// or falls back to local file store for unit tests / standalone development.
func NewAppStore(dsnOrPath string) (*AppStore, error) {
	secret := os.Getenv("LG_JWT_SECRET")
	if secret == "" {
		secret = "open-source-bgp-looking-glass-default-jwt-secret"
	}

	envDSN := strings.TrimSpace(os.Getenv("LG_DB_DSN"))
	if envDSN != "" {
		dsnOrPath = envDSN
	}

	bootBytes := make([]byte, 16)
	_, _ = rand.Read(bootBytes)

	s := &AppStore{
		jwtSecret:      []byte(secret),
		bootInstanceID: hex.EncodeToString(bootBytes),
	}

	if isMySQLDSN(dsnOrPath) {
		if err := s.initMySQL(dsnOrPath); err != nil {
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
	return strings.Contains(val, "@tcp(") || strings.Contains(val, "@unix(") || strings.HasPrefix(val, "mysql://")
}

func HashPassword(password string) string {
	h := sha256.Sum256([]byte("lg-for-bgp-salt:" + password))
	return hex.EncodeToString(h[:])
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
		Communities: []models.CommunityDictEntry{},
		AuditLogs:   []models.AuditLogEntry{},
	}
}

func (s *AppStore) loadOrInitFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.filePath != "" && s.filePath != "memory" {
		if _, err := os.Stat(s.filePath); err == nil {
			raw, errRead := os.ReadFile(s.filePath)
			if errRead == nil {
				if errUnmarshal := json.Unmarshal(raw, &s.data); errUnmarshal == nil && len(s.data.RouteViews) > 0 {
					if s.data.Settings.AdminSecretSlug == "" {
						s.data.Settings.AdminSecretSlug = "_console_8f92a1c4"
					}
					return nil
				}
			}
		}
	}

	s.data = defaultInitialData()
	return s.persistLocked()
}

func (s *AppStore) persistLocked() error {
	if s.db != nil {
		return s.syncAllToMySQLLocked()
	}
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

// VerifyAdminSlug performs constant-time comparison of the candidate URL slug against the admin path in lg-server.conf.
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
	err := s.persistLocked()
	return s.data.Settings, err
}

func (s *AppStore) GetRouteViews() []models.RouteViewMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RouteViewMeta, len(s.data.RouteViews))
	copy(out, s.data.RouteViews)
	return out
}

func (s *AppStore) GetRouteViewMap() map[models.RouteViewID]models.RouteViewMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[models.RouteViewID]models.RouteViewMeta, len(s.data.RouteViews))
	for _, v := range s.data.RouteViews {
		m[v.ID] = v
	}
	return m
}

func (s *AppStore) UpsertRouteView(view models.RouteViewMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	view.VRFName = strings.TrimSpace(view.VRFName)
	if view.VRFName == "" || strings.EqualFold(view.VRFName, "global") || strings.EqualFold(view.VRFName, "default") || strings.EqualFold(view.VRFName, "master") {
		view.VRFName = "global"
	}
	if strings.TrimSpace(string(view.ID)) == "" {
		slug := strings.ToLower(strings.ReplaceAll(view.VRFName, "-", "_"))
		if slug == "global" {
			slug = fmt.Sprintf("global_%s", strings.ToLower(strings.TrimSpace(view.Type)))
		}
		view.ID = models.RouteViewID(slug)
	}
	view.Type = strings.ToLower(strings.TrimSpace(view.Type))
	if view.Type != "gobgp" && view.Type != "bird2" && view.Type != "frr" {
		view.Type = "gobgp"
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
	view.POP = strings.TrimSpace(view.POP)
	if view.POP == "" {
		view.POP = "all"
	}
	if view.JuniperSourceIPv4 == "" {
		view.JuniperSourceIPv4 = "10.255.0.10"
	}

	for i, existing := range s.data.RouteViews {
		if existing.ID == view.ID {
			s.data.RouteViews[i] = view
			s.pruneStaleViewIDsLocked()
			return s.persistLocked()
		}
	}
	s.data.RouteViews = append(s.data.RouteViews, view)
	// Also append to PublicAllowedViews and admin AllowedViews by default so new VRFs are immediately queryable
	s.data.Settings.PublicAllowedViews = append(s.data.Settings.PublicAllowedViews, view.ID)
	for i := range s.data.Users {
		if s.data.Users[i].Role == "admin" || s.data.Users[i].Role == "noc" {
			s.data.Users[i].AllowedViews = append(s.data.Users[i].AllowedViews, view.ID)
		}
	}
	s.pruneStaleViewIDsLocked()
	return s.persistLocked()
}

// pruneStaleViewIDsLocked removes any deleted/non-existent VRF view IDs from PublicAllowedViews and all user accounts,
// and ensures admin accounts always have the exact list of currently existing VRF views.
func (s *AppStore) pruneStaleViewIDsLocked() {
	validSet := make(map[models.RouteViewID]bool, len(s.data.RouteViews))
	allIDs := make([]models.RouteViewID, 0, len(s.data.RouteViews))
	for _, v := range s.data.RouteViews {
		validSet[v.ID] = true
		allIDs = append(allIDs, v.ID)
	}

	var cleanPub []models.RouteViewID
	seenPub := make(map[models.RouteViewID]bool)
	for _, id := range s.data.Settings.PublicAllowedViews {
		if validSet[id] && !seenPub[id] {
			cleanPub = append(cleanPub, id)
			seenPub[id] = true
		}
	}
	if cleanPub == nil {
		cleanPub = []models.RouteViewID{}
	}
	s.data.Settings.PublicAllowedViews = cleanPub

	for i := range s.data.Users {
		if s.data.Users[i].Role == "admin" {
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
			}
		}
		if cleanUserViews == nil {
			cleanUserViews = []models.RouteViewID{}
		}
		s.data.Users[i].AllowedViews = cleanUserViews
	}
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
		_, _ = s.db.Exec("DELETE FROM lg_vrfs WHERE id = ?", string(id))
	}
	return s.persistLocked()
}

func (s *AppStore) GetPOPs() []models.POPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.POPGroup, len(s.data.POPs))
	copy(out, s.data.POPs)
	return out
}

func (s *AppStore) ensurePOPsFromRRNodesLocked() {
	seen := make(map[string]bool, len(s.data.POPs))
	for _, p := range s.data.POPs {
		seen[strings.ToUpper(strings.TrimSpace(p.ID))] = true
	}
	for _, n := range s.data.RRNodes {
		loc := strings.TrimSpace(n.Location)
		if loc == "" {
			continue
		}
		key := strings.ToUpper(loc)
		if !seen[key] {
			seen[key] = true
			s.data.POPs = append(s.data.POPs, models.POPGroup{
				ID:          loc,
				Name:        loc,
				Description: "",
				SortOrder:   len(s.data.POPs) + 1,
			})
		}
	}
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
			return s.persistLocked()
		}
	}
	s.data.POPs = append(s.data.POPs, pop)
	return s.persistLocked()
}

func (s *AppStore) DeletePOP(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	var filtered []models.POPGroup
	for _, p := range s.data.POPs {
		if !strings.EqualFold(p.ID, id) {
			filtered = append(filtered, p)
		}
	}
	s.data.POPs = filtered
	if s.db != nil {
		_, _ = s.db.Exec("DELETE FROM lg_pops WHERE id = ?", id)
	}
	return s.persistLocked()
}

func (s *AppStore) GetRRNodes() []models.RRNodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RRNodeConfig, len(s.data.RRNodes))
	copy(out, s.data.RRNodes)
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
	node.LoopbackIP = strings.TrimSpace(node.LoopbackIP)
	if node.LoopbackIP == "" {
		node.LoopbackIP = "127.0.0.1"
	}
	node.Role = strings.ToLower(strings.TrimSpace(node.Role))
	if node.Role != "primary" && node.Role != "backup" && node.Role != "secondary" {
		node.Role = "primary"
	}
	node.Location = strings.TrimSpace(node.Location)
	if node.Location == "" {
		if len(s.data.POPs) > 0 {
			node.Location = s.data.POPs[0].ID
		} else {
			node.Location = "CORE-POP-01"
		}
	}
	if node.LastChecked == "" {
		node.LastChecked = time.Now().Format(time.RFC3339)
	}
	for i, existing := range s.data.RRNodes {
		if existing.ID == node.ID {
			s.data.RRNodes[i] = node
			s.ensurePOPsFromRRNodesLocked()
			return s.persistLocked()
		}
	}
	s.data.RRNodes = append(s.data.RRNodes, node)
	s.ensurePOPsFromRRNodesLocked()
	return s.persistLocked()
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
	if s.db != nil {
		_, _ = s.db.Exec("DELETE FROM lg_rr_nodes WHERE id = ?", id)
	}
	return s.persistLocked()
}

func (s *AppStore) GetCommunities() []models.CommunityDictEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.CommunityDictEntry, len(s.data.Communities))
	copy(out, s.data.Communities)
	return out
}

func (s *AppStore) UpsertCommunity(entry models.CommunityDictEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.data.Communities {
		if c.Community == entry.Community {
			s.data.Communities[i] = entry
			return s.persistLocked()
		}
	}
	s.data.Communities = append(s.data.Communities, entry)
	return s.persistLocked()
}

func (s *AppStore) DeleteCommunity(community string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var filtered []models.CommunityDictEntry
	for _, c := range s.data.Communities {
		if c.Community != community {
			filtered = append(filtered, c)
		}
	}
	s.data.Communities = filtered
	if s.db != nil {
		_, _ = s.db.Exec("DELETE FROM lg_communities WHERE community = ?", community)
	}
	return s.persistLocked()
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

	hash := HashPassword(password)
	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.EqualFold(u.Username, username) {
			if !u.Enabled {
				return nil, "", errors.New("account has been disabled by administrator")
			}
			if u.PasswordHash != hash {
				return nil, "", errors.New("invalid username or password")
			}
			now := time.Now()
			u.LastLoginAt = &now
			_ = s.persistLocked()

			uSafe := *u
			uSafe.PasswordHash = ""
			token, err := s.IssueToken(uSafe)
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
			if err := s.persistLocked(); err != nil {
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
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	out := s.data.Users[len(s.data.Users)-1]
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

	curHash := HashPassword(currentPassword)
	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.EqualFold(u.Username, username) {
			if u.PasswordHash != curHash {
				return nil, "", errors.New("current password is incorrect")
			}
			u.PasswordHash = HashPassword(newPassword)
			u.MustChangePassword = false
			if err := s.persistLocked(); err != nil {
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
		_, _ = s.db.Exec("DELETE FROM lg_users WHERE id = ?", userID)
	}
	return s.persistLocked()
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
		`, entry.Timestamp, entry.Username, entry.ClientIP, entry.Action, entry.QueryType, entry.Target, entry.Views, entry.RRNode, entry.DurationMs)
	} else {
		_ = s.persistLocked()
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
	if len(hash) >= 12 {
		return hash[:12]
	}
	return hash
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
