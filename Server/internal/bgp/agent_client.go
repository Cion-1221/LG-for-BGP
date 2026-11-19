// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package bgp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
)

// AgentQueryRequest is the JSON payload sent by lg-server to a remote lg-agent collector.
type AgentQueryRequest struct {
	Engine       string               `json:"engine"`     // "bird2" or "frr"
	QueryType    string               `json:"query_type"` // "prefix", "aspath", "community"
	Target       string               `json:"target"`
	View         models.RouteViewMeta `json:"view"`
	RRNodeName   string               `json:"rr_node_name,omitempty"`
	RRLoopbackIP string               `json:"rr_loopback_ip,omitempty"`
}

// AgentQueryResponse is returned by lg-agent for POST /agent/v1/query.
type AgentQueryResponse struct {
	OK            bool                  `json:"ok"`
	MatchedPrefix string                `json:"matched_prefix"`
	Paths         []models.BGPRoutePath `json:"paths"`
	RawOutput     string                `json:"raw_output"`
	Error         string                `json:"error,omitempty"`
}

// AgentNeighborsRequest is sent by lg-server to POST /agent/v1/neighbors.
type AgentNeighborsRequest struct {
	Engine string                 `json:"engine"` // "bird2" or "frr"
	Views  []models.RouteViewMeta `json:"views"`
}

// AgentNeighborsResponse is returned by lg-agent for POST /agent/v1/neighbors.
type AgentNeighborsResponse struct {
	OK        bool                        `json:"ok"`
	Neighbors []models.BGPNeighborSummary `json:"neighbors"`
	Error     string                      `json:"error,omitempty"`
}

// AgentHealthResponse is returned by lg-agent for GET /agent/v1/health.
type AgentHealthResponse struct {
	Status  string `json:"status"`
	Engine  string `json:"engine"`
	Socket  string `json:"socket,omitempty"`
	Message string `json:"message"`
}

var agentHTTPClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
	},
}

// IsRemoteAgentEndpoint returns true if an RR endpoint is an HTTP(S) URL targeting lg-agent.
func IsRemoteAgentEndpoint(endpoint string) bool {
	lower := strings.ToLower(strings.TrimSpace(endpoint))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// ProbeRemoteAgent verifies connectivity and daemon health on a remote lg-agent endpoint.
func ProbeRemoteAgent(ctx context.Context, endpoint, token string) (*AgentHealthResponse, error) {
	base := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(pctx, http.MethodGet, base+"/agent/v1/health", nil)
	if err != nil {
		return nil, err
	}
	if tok := strings.TrimSpace(token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var health AgentHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, fmt.Errorf("invalid agent health JSON: %w", err)
	}
	if !strings.EqualFold(health.Status, "ok") {
		return &health, fmt.Errorf("agent unhealthy: %s", health.Message)
	}
	return &health, nil
}

func (e *Engine) queryRemoteAgent(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	engineType string,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	timeout := 6 * time.Second
	if queryType == "aspath" || queryType == "community" {
		timeout = 28 * time.Second
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	payload := AgentQueryRequest{
		Engine:       engineType,
		QueryType:    queryType,
		Target:       target,
		View:         view,
		RRNodeName:   rrNode.Name,
		RRLoopbackIP: rrNode.LoopbackIP,
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, "", "", false
	}

	base := strings.TrimRight(strings.TrimSpace(rrNode.Endpoint), "/")
	req, err := http.NewRequestWithContext(qctx, http.MethodPost, base+"/agent/v1/query", bytes.NewReader(rawBody))
	if err != nil {
		return nil, "", "", false
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(rrNode.AgentToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return nil, "", "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", false
	}

	var out AgentQueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, "", "", false
	}
	if !out.OK {
		return nil, "", "", false
	}
	if out.Paths == nil {
		out.Paths = []models.BGPRoutePath{}
	}
	return out.Paths, out.MatchedPrefix, out.RawOutput, true
}

func (e *Engine) queryRemoteAgentNeighbors(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	engineType string,
	views []models.RouteViewMeta,
) ([]models.BGPNeighborSummary, bool) {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	payload := AgentNeighborsRequest{
		Engine: engineType,
		Views:  views,
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}

	base := strings.TrimRight(strings.TrimSpace(rrNode.Endpoint), "/")
	req, err := http.NewRequestWithContext(qctx, http.MethodPost, base+"/agent/v1/neighbors", bytes.NewReader(rawBody))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(rrNode.AgentToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := agentHTTPClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var out AgentNeighborsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, false
	}
	if !out.OK {
		return nil, false
	}
	for i := range out.Neighbors {
		out.Neighbors[i].POP = rrNode.Location
		out.Neighbors[i].RRNodeID = rrNode.ID
		out.Neighbors[i].RRNodeName = rrNode.Name
		out.Neighbors[i].EngineType = engineType
	}
	return out.Neighbors, true
}
