// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadYAMLConfigSQLiteAndMySQL(t *testing.T) {
	tmp := t.TempDir()

	// 1. Explicit SQLite config (VyOS style)
	sqliteYAML := `
server:
  host: "127.0.0.1"
  port: 8080
  admin_path: "/console"
database:
  driver: "sqlite"
  path: "/config/user-data/lg-for-bgp/lg.db"
`
	p1 := filepath.Join(tmp, "sqlite.yaml")
	if err := os.WriteFile(p1, []byte(sqliteYAML), 0600); err != nil {
		t.Fatal(err)
	}
	cfg1, err := LoadYAMLConfig(p1)
	if err != nil {
		t.Fatalf("LoadYAMLConfig sqlite failed: %v", err)
	}
	drv1, err := cfg1.DatabaseDriver()
	if err != nil || drv1 != "sqlite" {
		t.Fatalf("expected sqlite driver, got %q, err=%v", drv1, err)
	}
	dsn1, err := cfg1.DatabaseDSN()
	if err != nil || dsn1 != "sqlite:/config/user-data/lg-for-bgp/lg.db" {
		t.Fatalf("unexpected sqlite DSN: %q, err=%v", dsn1, err)
	}
	if sum := cfg1.DatabaseSummary(dsn1); !strings.Contains(sum, "sqlite (/config/user-data/lg-for-bgp/lg.db)") {
		t.Fatalf("unexpected sqlite summary: %q", sum)
	}

	// 2. Legacy MySQL config without `driver:` field stays backwards-compatible
	legacyMySQLYAML := `
database:
  host: "10.0.0.5"
  port: 3306
  user: "lg_user"
  password: "SuperSecretPassword!"
  dbname: "lg_prod"
`
	p2 := filepath.Join(tmp, "mysql.yaml")
	if err := os.WriteFile(p2, []byte(legacyMySQLYAML), 0600); err != nil {
		t.Fatal(err)
	}
	cfg2, err := LoadYAMLConfig(p2)
	if err != nil {
		t.Fatalf("LoadYAMLConfig legacy mysql failed: %v", err)
	}
	drv2, err := cfg2.DatabaseDriver()
	if err != nil || drv2 != "mysql" {
		t.Fatalf("expected mysql driver for legacy YAML, got %q, err=%v", drv2, err)
	}
	dsn2, err := cfg2.DatabaseDSN()
	if err != nil || !strings.Contains(dsn2, "10.0.0.5:3306)/lg_prod") {
		t.Fatalf("unexpected mysql DSN: %q, err=%v", dsn2, err)
	}
	sum2 := cfg2.DatabaseSummary(dsn2)
	if strings.Contains(sum2, "SuperSecretPassword") {
		t.Fatalf("DatabaseSummary leaked database password: %q", sum2)
	}

	// 3. Minimal SQLite config with only `path:` auto-detects sqlite
	autoSQLiteYAML := `
database:
  path: "./custom/edge.db"
`
	p3 := filepath.Join(tmp, "auto-sqlite.yaml")
	if err := os.WriteFile(p3, []byte(autoSQLiteYAML), 0600); err != nil {
		t.Fatal(err)
	}
	cfg3, err := LoadYAMLConfig(p3)
	if err != nil {
		t.Fatalf("LoadYAMLConfig auto-sqlite failed: %v", err)
	}
	drv3, err := cfg3.DatabaseDriver()
	if err != nil || drv3 != "sqlite" {
		t.Fatalf("expected auto-detected sqlite driver, got %q, err=%v", drv3, err)
	}

	// 4. Unsupported driver fails fast
	badYAML := `
database:
  driver: "postgres"
`
	p4 := filepath.Join(tmp, "bad.yaml")
	if err := os.WriteFile(p4, []byte(badYAML), 0600); err != nil {
		t.Fatal(err)
	}
	cfg4, err := LoadYAMLConfig(p4)
	if err != nil {
		t.Fatalf("LoadYAMLConfig bad yaml parse failed: %v", err)
	}
	if _, err := cfg4.DatabaseDSN(); err == nil {
		t.Fatalf("expected error for unsupported database driver")
	}
}
