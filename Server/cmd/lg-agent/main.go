// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
	"lg-for-bgp/internal/store"
)

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:9090", "HTTP(S) listen address for lg-agent (bind to private/tunnel IP in production)")
	engineFlag := flag.String("engine", "auto", "Local BGP daemon engine: bird2, frr, or auto")
	socketFlag := flag.String("socket", "local", "Local control socket path (e.g. /run/bird/bird.ctl for bird2, /run/frr for frr, or local)")
	tokenFlag := flag.String("token", "", "Shared Bearer authentication token (can also be set via LG_AGENT_TOKEN)")
	tlsCertFlag := flag.String("tls-cert", "", "Optional TLS server certificate path for native HTTPS")
	tlsKeyFlag := flag.String("tls-key", "", "Optional TLS server private key path for native HTTPS")
	flag.Parse()

	token := strings.TrimSpace(*tokenFlag)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("LG_AGENT_TOKEN"))
	}
	if token == "" {
		log.Println("[WARN] lg-agent started WITHOUT an authentication token (-token / LG_AGENT_TOKEN). Restrict access via firewall/tunnel or set a token!")
	}

	engineMode := strings.ToLower(strings.TrimSpace(*engineFlag))
	if engineMode == "" || engineMode == "auto" {
		if _, err := exec.LookPath("vtysh"); err == nil {
			engineMode = "frr"
		} else if _, err := exec.LookPath("birdc"); err == nil {
			engineMode = "bird2"
		} else {
			engineMode = "frr"
		}
	}

	st, err := store.NewAppStore("memory")
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize in-memory store: %v", err)
	}
	defer func() { _ = st.Close() }()
	cache := security.NewTTLCache()
	defer cache.Close()
	eng := bgp.NewEngine(st, cache)

	agentSrv := &agentServer{
		eng:        eng,
		engineMode: engineMode,
		socketPath: strings.TrimSpace(*socketFlag),
		token:      token,
		localNode: models.RRNodeConfig{
			ID:         "local-agent",
			Name:       "lg-agent",
			EngineType: engineMode,
			Endpoint:   strings.TrimSpace(*socketFlag),
			Enabled:    true,
		},
	}

	srv := &http.Server{
		Addr:         *listenAddr,
		Handler:      agentSrv.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 35 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	useTLS := strings.TrimSpace(*tlsCertFlag) != "" && strings.TrimSpace(*tlsKeyFlag) != ""
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	go func() {
		log.Println("================================================================================")
		log.Println("  LG-for-BGP Lightweight Remote Collector Agent (lg-agent)")
		log.Printf("  Listen Address : %s://%s", scheme, *listenAddr)
		log.Printf("  BGP Engine     : %s (socket: %s)", engineMode, *socketFlag)
		log.Printf("  Bearer Auth    : %v | Native TLS: %v", token != "", useTLS)
		log.Println("================================================================================")
		var serveErr error
		if useTLS {
			serveErr = srv.ListenAndServeTLS(*tlsCertFlag, *tlsKeyFlag)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("[FATAL] lg-agent HTTP server error: %v", serveErr)
		}
	}()

	<-sigCtx.Done()
	log.Println("[INFO] Shutting down lg-agent gracefully...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}
