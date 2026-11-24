// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
)

func (s *AppStore) GetRouteViews() []models.RouteViewMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RouteViewMeta, len(s.data.RouteViews))
	for i, v := range s.data.RouteViews {
		cp := v
		if len(v.RRNodeIDs) > 0 {
			cp.RRNodeIDs = append([]string(nil), v.RRNodeIDs...)
		} else {
			cp.RRNodeIDs = []string{}
		}
		out[i] = cp
	}
	return out
}

func (s *AppStore) GetRouteViewMap() map[models.RouteViewID]models.RouteViewMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[models.RouteViewID]models.RouteViewMeta, len(s.data.RouteViews))
	for _, v := range s.data.RouteViews {
		cp := v
		if len(v.RRNodeIDs) > 0 {
			cp.RRNodeIDs = append([]string(nil), v.RRNodeIDs...)
		} else {
			cp.RRNodeIDs = []string{}
		}
		m[v.ID] = cp
	}
	return m
}

func sanitizeIDSlug(val string) string {
	val = strings.ToLower(strings.TrimSpace(val))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range val {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore && b.Len() > 0 {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func normalizeRRNodeIDs(raw []string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, id := range raw {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if strings.EqualFold(trimmed, "all") {
			return []string{"all"}
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func normalizeLoadedRouteView(v *models.RouteViewMeta) {
	v.POP = strings.TrimSpace(v.POP)
	if v.POP == "" {
		v.POP = "all"
	}
	v.RRNodeIDs = normalizeRRNodeIDs(v.RRNodeIDs)
	v.Type = strings.ToLower(strings.TrimSpace(v.Type))
	if v.Type != "auto" && v.Type != "gobgp" && v.Type != "bird2" && v.Type != "frr" {
		v.Type = "auto"
	}
	v.VRFName = strings.TrimSpace(v.VRFName)
	v.BirdTableV6 = strings.TrimSpace(v.BirdTableV6)
	if v.VRFName == "" || strings.EqualFold(v.VRFName, "global") || strings.EqualFold(v.VRFName, "default") || strings.EqualFold(v.VRFName, "master") {
		v.VRFName = "global"
		v.ShortName = "GLOBAL"
		v.JunosContextType = "global-rib"
		v.JunosContextName = "global"
		v.JunosTable = "inet.0 / inet6.0 (Global RIB)"
		v.BirdTableV4 = "master4"
		if v.BirdTableV6 == "" {
			v.BirdTableV6 = "master6"
		}
	} else {
		v.ShortName = v.VRFName
		v.JunosContextType = "routing-instances"
		v.JunosContextName = v.VRFName
		v.JunosTable = v.VRFName + ".inet.0"
		v.BirdTableV4 = v.VRFName
		if v.BirdTableV6 == "" {
			v.BirdTableV6 = v.VRFName + "-v6"
		}
	}
	v.FrrViewName = v.VRFName
}

// migrateLegacyViewBindingsLocked backfills RRNodeIDs for pre-existing VRFs created before VRF<->RR binding existed.
func (s *AppStore) migrateLegacyViewBindingsLocked() bool {
	changed := false
	for i := range s.data.RouteViews {
		v := &s.data.RouteViews[i]
		if len(v.RRNodeIDs) > 0 {
			continue
		}
		pop := strings.TrimSpace(v.POP)
		if pop == "" || strings.EqualFold(pop, "all") {
			v.RRNodeIDs = []string{"all"}
			changed = true
			continue
		}
		var matchedRRs []string
		for _, n := range s.data.RRNodes {
			if strings.EqualFold(strings.TrimSpace(n.Location), pop) {
				matchedRRs = append(matchedRRs, n.ID)
			}
		}
		if len(matchedRRs) > 0 {
			v.RRNodeIDs = matchedRRs
			changed = true
		}
	}
	return changed
}

// deriveViewPOPLocked derives the legacy POP label from bound RRNodeIDs for display/compatibility.
func (s *AppStore) deriveViewPOPLocked(rrNodeIDs []string, fallbackPOP string) string {
	if len(rrNodeIDs) == 1 && strings.EqualFold(rrNodeIDs[0], "all") {
		return "all"
	}
	if len(rrNodeIDs) == 0 {
		if p := strings.TrimSpace(fallbackPOP); p != "" {
			return p
		}
		return "none"
	}
	rrMap := make(map[string]models.RRNodeConfig, len(s.data.RRNodes))
	for _, n := range s.data.RRNodes {
		rrMap[n.ID] = n
	}
	popSet := make(map[string]string)
	for _, id := range rrNodeIDs {
		if n, ok := rrMap[id]; ok && strings.TrimSpace(n.Location) != "" {
			popSet[strings.ToUpper(strings.TrimSpace(n.Location))] = strings.TrimSpace(n.Location)
		}
	}
	if len(popSet) == 1 {
		for _, p := range popSet {
			return p
		}
	}
	if len(popSet) > 1 {
		return "multi"
	}
	if p := strings.TrimSpace(fallbackPOP); p != "" {
		return p
	}
	return "all"
}

func (s *AppStore) UpsertRouteView(view models.RouteViewMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	view.VRFName = strings.TrimSpace(view.VRFName)
	if view.VRFName == "" || strings.EqualFold(view.VRFName, "global") || strings.EqualFold(view.VRFName, "default") || strings.EqualFold(view.VRFName, "master") {
		view.VRFName = "global"
	}
	view.Type = strings.ToLower(strings.TrimSpace(view.Type))
	if view.Type != "auto" && view.Type != "gobgp" && view.Type != "bird2" && view.Type != "frr" {
		view.Type = "auto"
	}

	view.RRNodeIDs = normalizeRRNodeIDs(view.RRNodeIDs)
	if len(view.RRNodeIDs) == 0 {
		p := strings.TrimSpace(view.POP)
		if p == "" || strings.EqualFold(p, "all") {
			view.RRNodeIDs = []string{"all"}
		} else {
			for _, n := range s.data.RRNodes {
				if strings.EqualFold(strings.TrimSpace(n.Location), p) {
					view.RRNodeIDs = append(view.RRNodeIDs, n.ID)
				}
			}
		}
	}

	view.POP = s.deriveViewPOPLocked(view.RRNodeIDs, view.POP)

	if strings.TrimSpace(string(view.ID)) == "" {
		slug := sanitizeIDSlug(view.VRFName)
		if slug == "" || slug == "global" {
			slug = "global_rib"
		}
		if len(view.RRNodeIDs) == 1 && !strings.EqualFold(view.RRNodeIDs[0], "all") {
			if rrSlug := sanitizeIDSlug(view.RRNodeIDs[0]); rrSlug != "" {
				slug = rrSlug + "_" + slug
			}
		} else if view.POP != "" && !strings.EqualFold(view.POP, "all") && !strings.EqualFold(view.POP, "multi") && !strings.EqualFold(view.POP, "none") {
			if popSlug := sanitizeIDSlug(view.POP); popSlug != "" {
				slug = popSlug + "_" + slug
			}
		}
		if len(slug) > 64 {
			slug = strings.TrimRight(slug[:64], "_")
		}
		candidate := models.RouteViewID(slug)
		exists := func(id models.RouteViewID) bool {
			for _, ex := range s.data.RouteViews {
				if ex.ID == id {
					return true
				}
			}
			return false
		}
		if exists(candidate) {
			for n := 2; n < 100; n++ {
				suffix := fmt.Sprintf("_%d", n)
				base := slug
				if len(base)+len(suffix) > 64 {
					base = base[:64-len(suffix)]
				}
				alt := models.RouteViewID(base + suffix)
				if !exists(alt) {
					candidate = alt
					break
				}
			}
		}
		view.ID = candidate
	}

	view.BirdTableV6 = strings.TrimSpace(view.BirdTableV6)
	if view.VRFName == "global" {
		if view.ShortName == "" {
			view.ShortName = "GLOBAL"
		}
		if view.JunosContextType == "" {
			view.JunosContextType = "global-rib"
		}
		if view.JunosContextName == "" {
			view.JunosContextName = "global"
		}
		if view.JunosTable == "" {
			view.JunosTable = "inet.0 / inet6.0 (Global RIB)"
		}
		view.BirdTableV4 = "master4"
		if view.BirdTableV6 == "" {
			view.BirdTableV6 = "master6"
		}
	} else {
		if view.ShortName == "" {
			view.ShortName = view.VRFName
		}
		if view.JunosContextType == "" {
			view.JunosContextType = "routing-instances"
		}
		if view.JunosContextName == "" {
			view.JunosContextName = view.VRFName
		}
		if view.JunosTable == "" {
			view.JunosTable = view.VRFName + ".inet.0"
		}
		view.BirdTableV4 = view.VRFName
		if view.BirdTableV6 == "" {
			view.BirdTableV6 = view.VRFName + "-v6"
		}
	}
	view.FrrViewName = view.VRFName
	view.JuniperSourceIPv4 = strings.TrimSpace(view.JuniperSourceIPv4)
	view.JuniperSourceIPv6 = strings.TrimSpace(view.JuniperSourceIPv6)

	for i, existing := range s.data.RouteViews {
		if existing.ID == view.ID {
			s.data.RouteViews[i] = view
			if err := s.upsertRouteViewDBLocked(view, i); err != nil {
				return err
			}
			if s.pruneStaleViewIDsLocked() {
				return s.syncAllowedViewsDBLocked()
			}
			return nil
		}
	}

	idx := len(s.data.RouteViews)
	s.data.RouteViews = append(s.data.RouteViews, view)
	s.data.Settings.PublicAllowedViews = append(s.data.Settings.PublicAllowedViews, view.ID)
	for i := range s.data.Users {
		if s.data.Users[i].Role == "admin" || s.data.Users[i].Role == "noc" {
			s.data.Users[i].AllowedViews = append(s.data.Users[i].AllowedViews, view.ID)
		}
	}
	s.pruneStaleViewIDsLocked()
	if err := s.upsertRouteViewDBLocked(view, idx); err != nil {
		return err
	}
	return s.syncAllowedViewsDBLocked()
}

func (s *AppStore) pruneStaleViewIDsLocked() bool {
	validSet := make(map[models.RouteViewID]bool, len(s.data.RouteViews))
	allIDs := make([]models.RouteViewID, 0, len(s.data.RouteViews))
	for _, v := range s.data.RouteViews {
		validSet[v.ID] = true
		allIDs = append(allIDs, v.ID)
	}

	changed := false
	var cleanPub []models.RouteViewID
	seenPub := make(map[models.RouteViewID]bool)
	for _, id := range s.data.Settings.PublicAllowedViews {
		if validSet[id] && !seenPub[id] {
			cleanPub = append(cleanPub, id)
			seenPub[id] = true
		} else {
			changed = true
		}
	}
	if cleanPub == nil {
		cleanPub = []models.RouteViewID{}
	}
	if len(cleanPub) != len(s.data.Settings.PublicAllowedViews) {
		changed = true
	}
	s.data.Settings.PublicAllowedViews = cleanPub

	for i := range s.data.Users {
		if s.data.Users[i].Role == "admin" {
			if len(s.data.Users[i].AllowedViews) != len(allIDs) {
				changed = true
			} else {
				for j := range allIDs {
					if s.data.Users[i].AllowedViews[j] != allIDs[j] {
						changed = true
						break
					}
				}
			}
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
			} else {
				changed = true
			}
		}
		if cleanUserViews == nil {
			cleanUserViews = []models.RouteViewID{}
		}
		s.data.Users[i].AllowedViews = cleanUserViews
	}
	return changed
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
		if _, err := s.db.Exec("DELETE FROM lg_vrfs WHERE id = ?", string(id)); err != nil {
			return err
		}
		return s.syncAllowedViewsDBLocked()
	}
	return s.persistFileLocked()
}

func (s *AppStore) GetPOPs() []models.POPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.POPGroup, len(s.data.POPs))
	copy(out, s.data.POPs)
	return out
}

func (s *AppStore) ensurePOPsFromRRNodesLocked() []models.POPGroup {
	seen := make(map[string]bool, len(s.data.POPs))
	for _, p := range s.data.POPs {
		seen[strings.ToUpper(strings.TrimSpace(p.ID))] = true
	}
	var added []models.POPGroup
	for _, n := range s.data.RRNodes {
		loc := strings.TrimSpace(n.Location)
		if loc == "" {
			continue
		}
		key := strings.ToUpper(loc)
		if !seen[key] {
			seen[key] = true
			newPOP := models.POPGroup{
				ID:          loc,
				Name:        loc,
				Description: "",
				SortOrder:   len(s.data.POPs) + 1,
			}
			s.data.POPs = append(s.data.POPs, newPOP)
			added = append(added, newPOP)
		}
	}
	return added
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
			return s.upsertPOPDBLocked(pop, i+1)
		}
	}
	s.data.POPs = append(s.data.POPs, pop)
	return s.upsertPOPDBLocked(pop, len(s.data.POPs))
}

func (s *AppStore) DeletePOP(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	boundCount := 0
	for _, n := range s.data.RRNodes {
		if strings.EqualFold(strings.TrimSpace(n.Location), id) {
			boundCount++
		}
	}
	if boundCount > 0 {
		return fmt.Errorf("cannot delete PoP %q: %d RR node(s) are still bound to this PoP; reassign or delete those RR nodes first", id, boundCount)
	}

	var filtered []models.POPGroup
	for _, p := range s.data.POPs {
		if !strings.EqualFold(p.ID, id) {
			filtered = append(filtered, p)
		}
	}
	s.data.POPs = filtered
	if s.db != nil {
		_, err := s.db.Exec("DELETE FROM lg_pops WHERE id = ?", id)
		return err
	}
	return s.persistFileLocked()
}

func (s *AppStore) GetRRNodes() []models.RRNodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RRNodeConfig, len(s.data.RRNodes))
	copy(out, s.data.RRNodes)
	return out
}

// GetPublicRRNodes returns RR nodes with sensitive internal fields stripped out
// so public visitors cannot discover internal collector / agent IPs or ports.
func (s *AppStore) GetPublicRRNodes() []models.RRNodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.RRNodeConfig, len(s.data.RRNodes))
	for i, n := range s.data.RRNodes {
		cp := n
		cp.AgentToken = ""
		cp.Endpoint = ""
		cp.LoopbackIP = ""
		out[i] = cp
	}
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
	node.AgentToken = strings.TrimSpace(node.AgentToken)
	node.LoopbackIP = strings.TrimSpace(node.LoopbackIP)
	if node.LoopbackIP == "" {
		node.LoopbackIP = "127.0.0.1"
	}
	node.Role = strings.ToLower(strings.TrimSpace(node.Role))
	if node.Role != "primary" && node.Role != "backup" && node.Role != "secondary" {
		node.Role = "primary"
	}
	node.Location = strings.TrimSpace(node.Location)
	if node.Location == "" || strings.EqualFold(node.Location, "all") {
		if len(s.data.POPs) > 0 {
			node.Location = s.data.POPs[0].ID
		} else {
			node.Location = "CORE-POP-01"
		}
	}
	if node.LastChecked == "" {
		node.LastChecked = time.Now().Format(time.RFC3339)
	}

	updated := false
	for i, existing := range s.data.RRNodes {
		if existing.ID == node.ID {
			s.data.RRNodes[i] = node
			updated = true
			break
		}
	}
	if !updated {
		s.data.RRNodes = append(s.data.RRNodes, node)
	}

	addedPOPs := s.ensurePOPsFromRRNodesLocked()
	if err := s.upsertRRNodeDBLocked(node); err != nil {
		return err
	}
	for _, p := range addedPOPs {
		_ = s.upsertPOPDBLocked(p, p.SortOrder)
	}
	for idx := range s.data.RouteViews {
		v := &s.data.RouteViews[idx]
		for _, rid := range v.RRNodeIDs {
			if rid == node.ID {
				nextPOP := s.deriveViewPOPLocked(v.RRNodeIDs, v.POP)
				if nextPOP != v.POP {
					v.POP = nextPOP
					_ = s.upsertRouteViewDBLocked(*v, idx)
				}
				break
			}
		}
	}
	return nil
}

func (s *AppStore) UpdateRRNodeHealth(id string, healthy bool, lastChecked string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.RRNodes {
		if s.data.RRNodes[i].ID == id {
			s.data.RRNodes[i].Healthy = healthy
			s.data.RRNodes[i].LastChecked = lastChecked
			return s.updateRRNodeHealthDBLocked(id, healthy, lastChecked)
		}
	}
	return fmt.Errorf("RR node %q not found", id)
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

	var modifiedViewIdxs []int
	for idx := range s.data.RouteViews {
		v := &s.data.RouteViews[idx]
		if len(v.RRNodeIDs) == 0 || (len(v.RRNodeIDs) == 1 && strings.EqualFold(v.RRNodeIDs[0], "all")) {
			continue
		}
		var kept []string
		removed := false
		for _, rid := range v.RRNodeIDs {
			if rid == id {
				removed = true
				continue
			}
			kept = append(kept, rid)
		}
		if removed {
			if kept == nil {
				kept = []string{}
			}
			v.RRNodeIDs = kept
			v.POP = s.deriveViewPOPLocked(v.RRNodeIDs, "none")
			modifiedViewIdxs = append(modifiedViewIdxs, idx)
		}
	}

	if s.db != nil {
		if _, err := s.db.Exec("DELETE FROM lg_rr_nodes WHERE id = ?", id); err != nil {
			return err
		}
		for _, idx := range modifiedViewIdxs {
			if err := s.upsertRouteViewDBLocked(s.data.RouteViews[idx], idx); err != nil {
				return err
			}
		}
		return nil
	}
	return s.persistFileLocked()
}
