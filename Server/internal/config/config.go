// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"lg-for-bgp/internal/logger"
)

type ServerSection struct {
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	AdminPath      string   `yaml:"admin_path"`
	UIDir          string   `yaml:"ui_dir"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

type DatabaseSection struct {
	Driver                 string `yaml:"driver"` // "mysql" (or "mariadb") | "sqlite" (or "sqlite3")
	Path                   string `yaml:"path"`   // SQLite database file path (used when driver is "sqlite")
	Host                   string `yaml:"host"`
	Port                   int    `yaml:"port"`
	User                   string `yaml:"user"`
	Password               string `yaml:"password"`
	DBName                 string `yaml:"dbname"`
	MaxOpenConns           int    `yaml:"max_open_conns"`
	MaxIdleConns           int    `yaml:"max_idle_conns"`
	ConnMaxLifetimeMinutes int    `yaml:"conn_max_lifetime_minutes"`
	ConnMaxIdleTimeMinutes int    `yaml:"conn_max_idle_time_minutes"`
	AuditRetentionDays     int    `yaml:"audit_retention_days"` // Auto-prune audit logs older than N days (default 30)
	AuditMaxRows           int    `yaml:"audit_max_rows"`       // Max audit log rows retained in DB (default 50000)
}

type JWTSection struct {
	Secret           string `yaml:"secret"`
	RefreshTokenDays int    `yaml:"refresh_token_days"`
}

// AppConfig represents the full YAML configuration file (config.yaml).
type AppConfig struct {
	Server   ServerSection     `yaml:"server"`
	Database DatabaseSection   `yaml:"database"`
	JWT      JWTSection        `yaml:"jwt"`
	Log      logger.LogConfig  `yaml:"log"`
}

func DefaultConfig() AppConfig {
	return AppConfig{
		Server: ServerSection{
			Host:      "127.0.0.1",
			Port:      8080,
			AdminPath: "/console",
			TrustedProxies: []string{
				"127.0.0.1",
				"::1",
			},
		},
		Database: DatabaseSection{
			Driver:                 "mysql",
			Path:                   "./data/lg.db",
			Host:                   "127.0.0.1",
			Port:                   3306,
			User:                   "lg_user",
			Password:               "ChangeMe_StrongDBPass_2026!",
			DBName:                 "lg_for_bgp",
			MaxOpenConns:           25,
			MaxIdleConns:           5,
			ConnMaxLifetimeMinutes: 30,
			ConnMaxIdleTimeMinutes: 5,
			AuditRetentionDays:     30,
			AuditMaxRows:           50000,
		},
		JWT: JWTSection{
			Secret:           "ChangeMe_LG_For_BGP_JWT_Secret_Key_2026",
			RefreshTokenDays: 3,
		},
		Log: logger.LogConfig{
			Dir:        "./logs",
			Filename:   "lg-server",
			MaxAgeDays: 14,
			MaxBackups: 14,
			Compress:   true,
			Level:      "info",
			Format:     "json",
			Stdout:     true,
			AccessLog:  true,
		},
	}
}

func LoadYAMLConfig(path string) (AppConfig, error) {
	cfg := DefaultConfig()

	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	var rawProbe struct {
		Database struct {
			Driver string `yaml:"driver"`
			Path   string `yaml:"path"`
			Host   string `yaml:"host"`
		} `yaml:"database"`
	}
	_ = yaml.Unmarshal(raw, &rawProbe)

	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse YAML config %s: %w", path, err)
	}

	// If YAML omitted `database.driver`, auto-detect sqlite when only `database.path` was supplied.
	if strings.TrimSpace(rawProbe.Database.Driver) == "" {
		if strings.TrimSpace(rawProbe.Database.Path) != "" && strings.TrimSpace(rawProbe.Database.Host) == "" {
			cfg.Database.Driver = "sqlite"
		} else {
			cfg.Database.Driver = "mysql"
		}
	}
	if strings.TrimSpace(cfg.Database.Path) == "" {
		cfg.Database.Path = "./data/lg.db"
	}

	if cfg.Server.Port <= 0 {
		cfg.Server.Port = 8080
	}
	if strings.TrimSpace(cfg.Server.AdminPath) == "" {
		cfg.Server.AdminPath = "/console"
	} else if !strings.HasPrefix(cfg.Server.AdminPath, "/") {
		cfg.Server.AdminPath = "/" + strings.TrimSpace(cfg.Server.AdminPath)
	}
	if cfg.Database.Port <= 0 {
		cfg.Database.Port = 3306
	}
	if cfg.Database.MaxOpenConns <= 0 {
		cfg.Database.MaxOpenConns = 100
	}
	if cfg.Database.MaxIdleConns <= 0 {
		cfg.Database.MaxIdleConns = 10
	}
	if cfg.Database.ConnMaxLifetimeMinutes <= 0 {
		cfg.Database.ConnMaxLifetimeMinutes = 60
	}
	if cfg.Database.ConnMaxIdleTimeMinutes <= 0 {
		cfg.Database.ConnMaxIdleTimeMinutes = 10
	}
	if cfg.Database.AuditRetentionDays <= 0 {
		cfg.Database.AuditRetentionDays = 30
	}
	if cfg.Database.AuditMaxRows <= 0 {
		cfg.Database.AuditMaxRows = 50000
	}
	if cfg.JWT.RefreshTokenDays <= 0 {
		cfg.JWT.RefreshTokenDays = 7
	}
	if strings.TrimSpace(cfg.Log.Dir) == "" {
		cfg.Log.Dir = "logs"
	}
	if strings.TrimSpace(cfg.Log.Filename) == "" {
		cfg.Log.Filename = "lg-server"
	}
	if cfg.Log.MaxAgeDays <= 0 {
		cfg.Log.MaxAgeDays = 7
	}
	if cfg.Log.MaxBackups <= 0 {
		cfg.Log.MaxBackups = 7
	}
	if strings.TrimSpace(cfg.Log.Format) == "" {
		cfg.Log.Format = "json"
	}

	return cfg, nil
}

// ListenAddress formats `<host>:<port>` (e.g. `127.0.0.1:8080` or `:8080`).
func (c AppConfig) ListenAddress() string {
	h := strings.TrimSpace(c.Server.Host)
	return fmt.Sprintf("%s:%d", h, c.Server.Port)
}

// DatabaseDriver returns the normalized database driver ("mysql" or "sqlite"),
// or an error for unsupported driver names.
func (c AppConfig) DatabaseDriver() (string, error) {
	d := strings.ToLower(strings.TrimSpace(c.Database.Driver))
	switch d {
	case "", "mysql", "mariadb":
		return "mysql", nil
	case "sqlite", "sqlite3":
		return "sqlite", nil
	default:
		return "", fmt.Errorf("unsupported database.driver %q (supported: mysql, mariadb, sqlite, sqlite3)", c.Database.Driver)
	}
}

// DatabaseDSN constructs the database connection string for the configured driver.
func (c AppConfig) DatabaseDSN() (string, error) {
	driver, err := c.DatabaseDriver()
	if err != nil {
		return "", err
	}
	if driver == "sqlite" {
		p := strings.TrimSpace(c.Database.Path)
		if p == "" {
			p = "./data/lg.db"
		}
		if strings.HasPrefix(strings.ToLower(p), "sqlite:") {
			return p, nil
		}
		return "sqlite:" + p, nil
	}
	return c.MySQLDSN(), nil
}

// DatabaseSummary returns a safe, password-free description of the active database target for logging.
func (c AppConfig) DatabaseSummary(effectiveDSN string) string {
	lower := strings.ToLower(strings.TrimSpace(effectiveDSN))
	if strings.HasPrefix(lower, "sqlite://") {
		return fmt.Sprintf("sqlite (%s)", strings.TrimPrefix(effectiveDSN, "sqlite://"))
	}
	if strings.HasPrefix(lower, "sqlite:") {
		return fmt.Sprintf("sqlite (%s)", strings.TrimPrefix(effectiveDSN, "sqlite:"))
	}
	if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") || strings.HasSuffix(lower, ".sqlite3") || lower == ":memory:" {
		return fmt.Sprintf("sqlite (%s)", effectiveDSN)
	}
	if strings.Contains(effectiveDSN, "@tcp(") || strings.Contains(effectiveDSN, "@unix(") || strings.HasPrefix(lower, "mysql://") {
		return fmt.Sprintf("mysql (%s:%d/%s)", c.Database.Host, c.Database.Port, c.Database.DBName)
	}
	if strings.TrimSpace(effectiveDSN) == "" {
		return "in-memory"
	}
	return fmt.Sprintf("file (%s)", effectiveDSN)
}

// MySQLDSN constructs the go-sql-driver/mysql DSN from the `database` YAML block.
func (c AppConfig) MySQLDSN() string {
	if strings.TrimSpace(c.Database.Host) == "" || strings.TrimSpace(c.Database.DBName) == "" {
		return ""
	}
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.DBName,
	)
}
