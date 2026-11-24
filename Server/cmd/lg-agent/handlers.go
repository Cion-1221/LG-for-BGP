// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"lg-for-bgp/internal/bgp"
	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

const maxAgentRequestBodyBytes = 64 * 1024

type agentServer struct {
	eng        *bgp.Engine
	engineMode string
	socketPath string
	token      string
	localNode  models.RRNodeConfig
}

func (a *agentServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/health", a.handleHealth)
	mux.HandleFunc("/agent/v1/query", a.handleQuery)
	mux.HandleFunc("/agent/v1/neighbors", a.handleNeighbors)
	return mux
}

func (a *agentServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if a.token == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	got := ""
	if strings.HasPrefix(auth, "Bearer ") {
		got = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized agent token"})
		return false
	}
	return true
}

func (a *agentServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !a.checkAuth(w, r) {
		return
	}
	status := "ok"
	msg := ""
	sock := a.socketPath
	switch a.engineMode {
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
		msg = fmt.Sprintf("unsupported engine %q", a.engineMode)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bgp.AgentHealthResponse{
		Status:  status,
		Engine:  a.engineMode,
		Socket:  sock,
		Message: msg,
	})
}

func (a *agentServer) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.checkAuth(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentRequestBodyBytes)

	var req bgp.AgentQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(bgp.AgentQueryResponse{OK: false, Error: "invalid or oversized JSON payload"})
		return
	}

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
		engType = a.engineMode
	}

	queryNode := a.localNode
	if n := strings.TrimSpace(req.RRNodeName); n != "" {
		queryNode.Name = n
	}

	var (
		totalPaths int
		matched    string
		rawOut     string
		ok         bool
	)
	switch engType {
	case "bird2":
		totalPaths, matched, rawOut, ok = a.eng.RunLocalBird2QueryWithLimits(r.Context(), queryNode, req.View, qType, req.Target, req.MaxIPv4, req.MaxIPv6)
	case "frr":
		totalPaths, matched, rawOut, ok = a.eng.RunLocalFrrQueryWithLimits(r.Context(), queryNode, req.View, qType, req.Target, req.MaxIPv4, req.MaxIPv6)
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
		TotalPaths:    totalPaths,
		RawOutput:     rawOut,
	})
}

func (a *agentServer) handleNeighbors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.checkAuth(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentRequestBodyBytes)

	var req bgp.AgentNeighborsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(bgp.AgentNeighborsResponse{OK: false, Error: "invalid or oversized JSON payload"})
		return
	}

	engType := strings.ToLower(strings.TrimSpace(req.Engine))
	if engType == "" || engType == "auto" {
		engType = a.engineMode
	}

	var (
		neighbors []models.BGPNeighborSummary
		ok        bool
	)
	switch engType {
	case "bird2":
		neighbors, ok = a.eng.RunLocalBird2Neighbors(r.Context(), a.localNode, req.Views)
	case "frr":
		neighbors, ok = a.eng.RunLocalFrrNeighbors(r.Context(), a.localNode, req.Views)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(bgp.AgentNeighborsResponse{
		OK:        ok,
		Neighbors: neighbors,
	})
}
