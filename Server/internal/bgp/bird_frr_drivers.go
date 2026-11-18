package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
	"lg-for-bgp/internal/security"
)

var reSafeVRFName = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)

// isGlobalRIB returns true when VRFName is empty or set to "global" / "default" / "master"
// indicating a single-table router/RR without VRFs.
func isGlobalRIB(vrfName string) bool {
	v := strings.ToLower(strings.TrimSpace(vrfName))
	return v == "" || v == "global" || v == "default" || v == "master" || v == "master4" || v == "master6"
}

// resolveVRFName returns the VRF / RIB table name configured on the RouteViewMeta.
// Returns "global" when configured for a single global routing table.
func resolveVRFName(view models.RouteViewMeta) string {
	vrf := strings.TrimSpace(view.VRFName)
	if vrf == "" {
		vrf = strings.TrimSpace(view.JunosContextName)
	}
	if isGlobalRIB(vrf) {
		return "global"
	}
	return vrf
}

// queryLiveBird2VRF queries BIRD 2:
// - Single Global Table (`vrf_name` empty or `global`): `show route for <target> all` (queries default master4/master6)
// - Multi-Table VRF (`vrf_name` specified): `show route table '<vrf_name>' for <target> all`
func (e *Engine) queryLiveBird2VRF(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	birdcBin, err := exec.LookPath("birdc")
	if err != nil {
		return nil, "", "", false
	}

	vrfName := resolveVRFName(view)
	tableClause := ""
	if !isGlobalRIB(vrfName) {
		if !reSafeVRFName.MatchString(vrfName) {
			return nil, "", "", false
		}
		tableClause = fmt.Sprintf("table '%s' ", vrfName)
	}

	var birdCmd string
	switch queryType {
	case "prefix":
		normalized, _, _, errVal := security.ValidatePrefixOrIP(target)
		if errVal != nil {
			return nil, "", "", false
		}
		birdCmd = fmt.Sprintf("show route %sfor %s all", tableClause, normalized)
	case "aspath":
		cleaned, errVal := security.ValidateASPathOrASN(target)
		if errVal != nil {
			return nil, "", "", false
		}
		asnNum, errNum := strconv.ParseUint(strings.Trim(cleaned, "^$_.*+? "), 10, 32)
		if errNum != nil {
			return nil, "", "", false
		}
		birdCmd = fmt.Sprintf("show route %swhere bgp_path ~ [= * %d * =] all", tableClause, asnNum)
	case "community":
		cleaned, errVal := security.ValidateCommunity(target)
		if errVal != nil {
			return nil, "", "", false
		}
		parts := strings.Split(cleaned, ":")
		if len(parts) == 2 {
			birdCmd = fmt.Sprintf("show route %swhere (%s, %s) ~ bgp_community all", tableClause, parts[0], parts[1])
		} else {
			return nil, "", "", false
		}
	default:
		return nil, "", "", false
	}

	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var birdArgs []string
	sock := strings.TrimSpace(rrNode.Endpoint)
	if sock != "" && !strings.EqualFold(sock, "local") && !strings.Contains(sock, ":") {
		birdArgs = append(birdArgs, "-s", sock)
	}
	birdArgs = append(birdArgs, "-r", birdCmd)

	cmd := exec.CommandContext(cctx, birdcBin, birdArgs...)
	outBytes, err := cmd.Output()
	if err != nil || len(outBytes) == 0 {
		return nil, "", "", false
	}

	rawOut := string(outBytes)
	if strings.Contains(rawOut, "syntax error") {
		return nil, "", "", false
	}
	if strings.Contains(rawOut, "Network not in table") {
		return []models.BGPRoutePath{}, "No matching route", rawOut, true
	}

	paths, matched := e.parseBird2Output(rawOut, view, target)
	return paths, matched, rawOut, true
}

func (e *Engine) parseBird2Output(rawOut string, view models.RouteViewMeta, target string) ([]models.BGPRoutePath, string) {
	lines := strings.Split(rawOut, "\n")
	var paths []models.BGPRoutePath
	var matchedPrefix string
	var cur *models.BGPRoutePath
	var curComms []string
	seq := uint32(1)

	flush := func() {
		if cur != nil {
			cur.Communities = e.TranslateCommunities(curComms)
			paths = append(paths, *cur)
			cur = nil
			curComms = nil
		}
	}

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "BIRD ") || strings.HasPrefix(line, "Table ") {
			continue
		}
		if !strings.HasPrefix(rawLine, "\t") && !strings.HasPrefix(rawLine, " ") && strings.Contains(line, "unicast") {
			flush()
			fields := strings.Fields(line)
			if len(fields) > 0 && (strings.Contains(fields[0], "/") || strings.Contains(fields[0], ":")) {
				matchedPrefix = fields[0]
			}
			if matchedPrefix == "" {
				matchedPrefix = target
			}
			best := strings.Contains(line, " * ")
			fam := "ipv4"
			if strings.Contains(matchedPrefix, ":") {
				fam = "ipv6"
			}
			cur = &models.BGPRoutePath{
				PathID:         seq,
				Prefix:         matchedPrefix,
				AddressFamily:  fam,
				Best:           best,
				Origin:         "IGP",
				LocalPref:      100,
				PeerIP:         view.JuniperSourceIPv4,
				RPKIStatus:     "NotFound",
				Age:            "Active",
				ValidationNote: "BIRD 2 Route",
			}
			seq++
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(line, "BGP.next_hop:") {
			cur.NextHop = strings.TrimSpace(strings.TrimPrefix(line, "BGP.next_hop:"))
		} else if strings.HasPrefix(line, "via ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && cur.NextHop == "" {
				cur.NextHop = parts[1]
			}
		} else if strings.HasPrefix(line, "BGP.local_pref:") {
			if v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "BGP.local_pref:")), 10, 32); err == nil {
				cur.LocalPref = uint32(v)
			}
		} else if strings.HasPrefix(line, "BGP.med:") {
			if v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "BGP.med:")), 10, 32); err == nil {
				cur.MED = uint32(v)
			}
		} else if strings.HasPrefix(line, "BGP.as_path:") {
			asStr := strings.TrimSpace(strings.TrimPrefix(line, "BGP.as_path:"))
			cur.ASPathString = asStr
			for _, tok := range strings.Fields(asStr) {
				if n, err := strconv.ParseUint(tok, 10, 32); err == nil {
					hop := e.ResolveASN(uint32(n))
					cur.ASPath = append(cur.ASPath, hop)
					cur.OriginASN = hop.ASN
					cur.OriginName = hop.Name
				}
			}
		} else if strings.HasPrefix(line, "BGP.community:") {
			commRaw := strings.TrimSpace(strings.TrimPrefix(line, "BGP.community:"))
			commRaw = strings.ReplaceAll(commRaw, "(", "")
			commRaw = strings.ReplaceAll(commRaw, ")", "")
			for _, tok := range strings.Fields(commRaw) {
				curComms = append(curComms, strings.ReplaceAll(tok, ",", ":"))
			}
		}
	}
	flush()
	if matchedPrefix == "" {
		matchedPrefix = "No matching route"
	}
	return paths, matchedPrefix
}

type frrJSONResponse struct {
	Prefix string `json:"prefix"`
	Paths  []struct {
		Bestpath *struct {
			Overall bool `json:"overall"`
		} `json:"bestpath"`
		PathID uint32 `json:"pathId"`
		Origin string `json:"origin"`
		Metric uint32 `json:"metric"`
		LocPrf uint32 `json:"locPrf"`
		Valid  bool   `json:"valid"`
		ASPath *struct {
			String string `json:"string"`
		} `json:"aspath"`
		Nexthops []struct {
			IP  string `json:"ip"`
			AFI string `json:"afi"`
		} `json:"nexthops"`
		Peer *struct {
			PeerID string `json:"peerId"`
		} `json:"peer"`
		Community *struct {
			List []string `json:"list"`
		} `json:"community"`
	} `json:"paths"`
}

// queryLiveFrrVRF queries FRRouting (FRR):
// - Single Global Table (`vrf_name` empty or `global`): `show bgp <ipv4|ipv6> unicast <target> json`
// - Multi-Table View (`vrf_name` specified): `show bgp view <vrf_name> <ipv4|ipv6> unicast <target> json`
func (e *Engine) queryLiveFrrVRF(
	ctx context.Context,
	rrNode models.RRNodeConfig,
	view models.RouteViewMeta,
	queryType string,
	target string,
) ([]models.BGPRoutePath, string, string, bool) {
	vtyshBin, err := exec.LookPath("vtysh")
	if err != nil {
		return nil, "", "", false
	}

	vrfName := resolveVRFName(view)
	viewClause := ""
	if !isGlobalRIB(vrfName) {
		if !reSafeVRFName.MatchString(vrfName) {
			return nil, "", "", false
		}
		viewClause = fmt.Sprintf("view %s ", vrfName)
	}

	if queryType != "prefix" {
		return nil, "", "", false
	}

	normalized, fam, _, errVal := security.ValidatePrefixOrIP(target)
	if errVal != nil {
		return nil, "", "", false
	}
	afStr := "ipv4"
	if fam == "ipv6" {
		afStr = "ipv6"
	}

	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var vtyBaseArgs []string
	vtySock := strings.TrimSpace(rrNode.Endpoint)
	if vtySock != "" && !strings.EqualFold(vtySock, "local") && !strings.Contains(vtySock, ":") {
		vtyBaseArgs = append(vtyBaseArgs, "--vty_socket", vtySock)
	}

	vtyCmdJSON := fmt.Sprintf("show bgp %s%s unicast %s json", viewClause, afStr, normalized)
	cmdJSON := exec.CommandContext(cctx, vtyshBin, append(append([]string{}, vtyBaseArgs...), "-c", vtyCmdJSON)...)
	jsonBytes, err := cmdJSON.Output()
	if err != nil || len(jsonBytes) == 0 {
		return nil, "", "", false
	}

	var parsed frrJSONResponse
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil || len(parsed.Paths) == 0 {
		return nil, "", "", false
	}

	vtyCmdRaw := fmt.Sprintf("show bgp %s%s unicast %s", viewClause, afStr, normalized)
	rawBytes, _ := exec.CommandContext(cctx, vtyshBin, append(append([]string{}, vtyBaseArgs...), "-c", vtyCmdRaw)...).Output()

	var results []models.BGPRoutePath
	for idx, p := range parsed.Paths {
		best := (p.Bestpath != nil && p.Bestpath.Overall) || idx == 0
		nh := ""
		if len(p.Nexthops) > 0 {
			nh = p.Nexthops[0].IP
		}
		var asns []uint32
		if p.ASPath != nil && p.ASPath.String != "" && p.ASPath.String != "Local" {
			for _, tok := range strings.Fields(p.ASPath.String) {
				if n, errConv := strconv.ParseUint(tok, 10, 32); errConv == nil {
					asns = append(asns, uint32(n))
				}
			}
		}
		var comms []string
		if p.Community != nil {
			comms = p.Community.List
		}
		peerIP := view.JuniperSourceIPv4
		if p.Peer != nil && p.Peer.PeerID != "" {
			peerIP = p.Peer.PeerID
		}
		pathID := p.PathID
		if pathID == 0 {
			pathID = uint32(idx + 1)
		}
		results = append(results, e.buildPath(
			pathID,
			parsed.Prefix,
			fam,
			best,
			nh,
			fmt.Sprintf("Original eBGP Next-Hop (FRR %s)", vrfName),
			asns,
			p.LocPrf,
			p.Metric,
			comms,
			peerIP,
			"Valid",
			"Active",
			"Selected in FRR RIB",
		))
	}

	return results, parsed.Prefix, string(rawBytes), true
}
