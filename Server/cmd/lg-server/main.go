package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lg-for-bgp/internal/api"
	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/config"
	"lg-for-bgp/internal/logger"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

func main() {
	configFile := flag.String("config", findDefaultConfigPath(), "Path to backend YAML configuration file (config.yaml)")
	listenFlag := flag.String("listen", "", "Override HTTP API listen address (e.g. 127.0.0.1:8080)")
	dbFlag := flag.String("db", "", "Override database DSN (MySQL/MariaDB DSN or sqlite:/path/to/lg.db)")
	adminPathFlag := flag.String("admin-path", "", "Override admin console URL path (e.g. /admin or /console)")
	uiDirFlag := flag.String("ui-dir", "", "Optional path to built UI/dist directory")
	flag.Parse()

	cfg, err := config.LoadYAMLConfig(*configFile)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "[WARN] Could not parse YAML config %s: %v\n", *configFile, err)
	}

	// Setup daily rotating file logger (today: lg-server.log, rotated: lg-server-YYYY-MM-DD.log, auto-prune > retention_days)
	rotLogger, errLog := logger.SetupLogger(cfg.Log)
	if errLog != nil {
		log.Printf("[WARN] Failed to initialize file logger: %v (logging to stdout only)", errLog)
	} else {
		defer rotLogger.Close()
	}

	listenAddr := cfg.ListenAddress()
	if v := os.Getenv("LG_LISTEN_ADDR"); v != "" {
		listenAddr = v
	}
	if *listenFlag != "" {
		listenAddr = *listenFlag
	}

	if v := os.Getenv("LG_DB_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	if v := os.Getenv("LG_DB_PATH"); v != "" {
		cfg.Database.Path = v
	}

	dsn, err := cfg.DatabaseDSN()
	if err != nil {
		log.Fatalf("[FATAL] Invalid database configuration: %v", err)
	}
	if v := os.Getenv("LG_DB_DSN"); v != "" {
		dsn = v
	}
	if *dbFlag != "" {
		dsn = *dbFlag
	}

	if v := os.Getenv("LG_ADMIN_PATH"); v != "" {
		cfg.Server.AdminPath = v
	}
	if *adminPathFlag != "" {
		cfg.Server.AdminPath = *adminPathFlag
	}

	if v := os.Getenv("LG_UI_DIR"); v != "" {
		cfg.Server.UIDir = v
	}
	if *uiDirFlag != "" {
		cfg.Server.UIDir = *uiDirFlag
	}

	if strings.TrimSpace(cfg.JWT.Secret) == "" || strings.Contains(cfg.JWT.Secret, "ChangeMe_") {
		log.Println("[WARN] Security Notice: jwt.secret is using the default placeholder value! Generate a strong random secret (e.g. `openssl rand -hex 32`) in config.yaml.")
	}

	st, err := store.NewAppStore(dsn)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize database store: %v", err)
	}
	defer func() {
		_ = st.Close()
	}()
	st.SetJWTConfig(cfg.JWT.Secret, cfg.JWT.RefreshTokenDays)
	st.SetConfiguredAdminPath(cfg.Server.AdminPath)
	st.SetDBPoolOptions(store.DBPoolOptions{
		MaxOpenConns:           cfg.Database.MaxOpenConns,
		MaxIdleConns:           cfg.Database.MaxIdleConns,
		ConnMaxLifetimeMinutes: cfg.Database.ConnMaxLifetimeMinutes,
		ConnMaxIdleTimeMinutes: cfg.Database.ConnMaxIdleTimeMinutes,
	})
	st.SetAuditRetention(cfg.Database.AuditRetentionDays, cfg.Database.AuditMaxRows)

	cache := security.NewTTLCache()
	defer cache.Close()
	eng := bgp.NewEngine(st, cache)
	srv := api.NewServer(st, eng, cache, cfg.Server.UIDir, cfg.Server.TrustedProxies...)
	defer srv.Close()
	srv.SetAccessLog(cfg.Log.AccessLog)
	if len(cfg.Server.AllowedOrigins) > 0 {
		srv.SetAllowedOrigins(cfg.Server.AllowedOrigins)
	}

	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      srv.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	adminSettings := st.GetAdminSettings()

	log.Println("================================================================================")
	log.Println("  LG-for-BGP Multi-Instance BGP Looking Glass API Server")
	log.Println("================================================================================")
	log.Printf("  YAML Config File   : %s", *configFile)
	log.Printf("  Database Backend   : %s (Audit Retention: %dd / max %d rows)",
		cfg.DatabaseSummary(dsn), cfg.Database.AuditRetentionDays, cfg.Database.AuditMaxRows)
	log.Printf("  API Listen Address : http://%s", listenAddr)
	log.Printf("  Admin Portal Path  : /%s", adminSettings.AdminSecretSlug)
	log.Printf("  Log Directory      : %s (Active: %s.log, MaxAge: %dd, MaxBackups: %d, Compress: %v)",
		cfg.Log.Dir, cfg.Log.Filename, cfg.Log.MaxAgeDays, cfg.Log.MaxBackups, cfg.Log.Compress)
	log.Println("================================================================================")

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("[FATAL] HTTP server error: %v", err)
		}
	case <-sigCtx.Done():
		log.Println("[INFO] Received shutdown signal; draining active requests and flushing database...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[WARN] HTTP server graceful shutdown timeout: %v", err)
		}
		bgp.CloseAllGRPCConnections()
		srv.Close()
		cache.Close()
		if err := st.Close(); err != nil {
			log.Printf("[WARN] Database close error: %v", err)
		}
		log.Println("[INFO] lg-server stopped cleanly.")
	}
}

func findDefaultConfigPath() string {
	candidates := []string{
		"config.yaml",
		"/etc/lg-for-bgp/config.yaml",
		"/opt/lg-for-bgp/config.yaml",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "config.yaml"
}
