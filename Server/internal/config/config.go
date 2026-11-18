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
}

type DatabaseSection struct {
	Host                   string `yaml:"host"`
	Port                   int    `yaml:"port"`
	User                   string `yaml:"user"`
	Password               string `yaml:"password"`
	DBName                 string `yaml:"dbname"`
	MaxOpenConns           int    `yaml:"max_open_conns"`
	MaxIdleConns           int    `yaml:"max_idle_conns"`
	ConnMaxLifetimeMinutes int    `yaml:"conn_max_lifetime_minutes"`
	ConnMaxIdleTimeMinutes int    `yaml:"conn_max_idle_time_minutes"`
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
			Host:                   "127.0.0.1",
			Port:                   3306,
			User:                   "lg_user",
			Password:               "ChangeMe_StrongDBPass_2026!",
			DBName:                 "lg_for_bgp",
			MaxOpenConns:           25,
			MaxIdleConns:           5,
			ConnMaxLifetimeMinutes: 30,
			ConnMaxIdleTimeMinutes: 5,
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

	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse YAML config %s: %w", path, err)
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
