// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
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
	listenAddr := flag.String("listen", "0.0.0.0:9090", "HTTP listen address for lg-agent (bind to private/tunnel IP in production)")
	engineFlag := flag.String("engine", "auto", "Local BGP daemon engine: bird2, frr, or auto")
	socketFlag := flag.String("socket", "local", "Local control socket path (e.g. /run/bird/bird.ctl for bird2, /run/frr for frr, or local)")
	tokenFlag := flag.String("token", "", "Shared Bearer authentication token (can also be set via LG_AGENT_TOKEN)")
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

	localNode := models.RRNodeConfig{
		ID:         "local-agent",
		Name:       "lg-agent",
		EngineType: engineMode,
		Endpoint:   strings.TrimSpace(*socketFlag),
		Enabled:    true,
	}

	checkAuth := func(w http.ResponseWriter, r *http.Request) bool {
		if token == "" {
			return true
		}
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		got := ""
		if strings.HasPrefix(auth, "Bearer ") {
			got = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized agent token"})
			return false
		}
		return true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) {
			return
		}
		status := "ok"
		msg := ""
		sock := strings.TrimSpace(*socketFlag)
		switch engineMode {
		case "bird2":
			if _, err := exec.LookPath("birdc"); err != nil {
				status = "error"
				msg = fmt.Sprintf("birdc not found in PATH: %v", err)
			} else if sock != "" && !strings.EqualFold(sock, "local") {
				if _, err := os.Stat(sock); err != nil {
					status = "error"
					msg = fmt.Sprintf("BIRD 2 socket %s not found: %v", sock, err)
				} else {
					msg = fmt.Sprintf("BIRD 2 agent ready (socket %s)", sock)
				}
			} else {
				msg = "BIRD 2 agent ready (birdc default socket)"
			}
		case "frr":
			if _, err := exec.LookPath("vtysh"); err != nil {
				status = "error"
				msg = fmt.Sprintf("vtysh not found in PATH: %v", err)
			} else if sock != "" && !strings.EqualFold(sock, "local") {
				if _, err := os.Stat(sock); err != nil {
					status = "error"
					msg = fmt.Sprintf("FRR socket directory %s not found: %v", sock, err)
				} else {
					msg = fmt.Sprintf("FRR agent ready (vty_socket %s)", sock)
				}
			} else {
				msg = "FRR agent ready (vtysh default socket)"
			}
		default:
			status = "error"
			msg = fmt.Sprintf("unsupported engine %q", engineMode)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bgp.AgentHealthResponse{
			Status:  status,
			Engine:  engineMode,
			Socket:  sock,
			Message: msg,
		})
	})

	mux.HandleFunc("/agent/v1/query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkAuth(w, r) {
			return
		}
		var req bgp.AgentQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: "invalid JSON payload"})
			return
		}

		// Re-validate untrusted query arguments inside the agent boundary (defense-in-depth)
		qType := strings.ToLower(strings.TrimSpace(req.QueryType))
		switch qType {
		case "prefix":
			norm, _, _, err := security.ValidatePrefixOrIP(req.Target)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: err.Error()})
				return
			}
			req.Target = norm
		case "aspath":
			cleaned, err := security.ValidateASPathOrASN(req.Target)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: err.Error()})
				return
			}
			req.Target = cleaned
		case "community":
			cleaned, err := security.ValidateCommunity(req.Target)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: err.Error()})
				return
			}
			req.Target = cleaned
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: "unsupported query_type"})
			return
		}

		engType := strings.ToLower(strings.TrimSpace(req.Engine))
		if engType == "" || engType == "auto" {
			engType = engineMode
		}

		var (
			paths   []models.BGPRoutePath
			matched string
			rawOut  string
			ok      bool
		)
		switch engType {
		case "bird2":
			paths, matched, rawOut, ok = eng.RunLocalBird2Query(r.Context(), localNode, req.View, qType, req.Target)
		case "frr":
			paths, matched, rawOut, ok = eng.RunLocalFrrQuery(r.Context(), localNode, req.View, qType, req.Target)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: "unsupported engine"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{
			OK:            ok,
			MatchedPrefix: matched,
			Paths:         paths,
			RawOutput:     rawOut,
		})
	})

	mux.HandleFunc("/agent/v1/neighbors", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkAuth(w, r) {
			return
		}
		var req bgp.AgentNeighborsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(bgp.AgentNeighborsResponse{OK: false, Error: "invalid JSON payload"})
			return
		}

		engType := strings.ToLower(strings.TrimSpace(req.Engine))
		if engType == "" || engType == "auto" {
			engType = engineMode
		}

		var (
			neighbors []models.BGPNeighborSummary
			ok        bool
		)
		switch engType {
		case "bird2":
			neighbors, ok = eng.RunLocalBird2Neighbors(r.Context(), localNode, req.Views)
		case "frr":
			neighbors, ok = eng.RunLocalFrrNeighbors(r.Context(), localNode, req.Views)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bgp.AgentNeighborsResponse{
			OK:        ok,
			Neighbors: neighbors,
		})
	})

	srv := &http.Server{
		Addr:         *listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 35 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Println("================================================================================")
		log.Println("  LG-for-BGP Lightweight Remote Collector Agent (lg-agent)")
		log.Printf("  Listen Address : http://%s", *listenAddr)
		log.Printf("  BGP Engine     : %s (socket: %s)", engineMode, *socketFlag)
		log.Printf("  Bearer Auth    : %v", token != "")
		log.Println("================================================================================")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] lg-agent HTTP server error: %v", err)
		}
	}()

	<-sigCtx.Done()
	log.Println("[INFO] Shutting down lg-agent gracefully...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}
