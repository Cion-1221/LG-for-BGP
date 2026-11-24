// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"lg-for-bgp/internal/models"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	clientIP := s.clientIP(r)
	uname := strings.TrimSpace(body.Username)

	if allowed, retryAfter, reason := s.loginGuard.Check(clientIP, uname); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: uname,
			ClientIP: clientIP,
			Action:   "LOGIN_BLOCKED_RATE_LIMIT",
		})
		writeError(w, http.StatusTooManyRequests, reason)
		return
	}

	user, token, err := s.store.Authenticate(uname, body.Password)
	if err != nil {
		lockedNow, remaining, retryAfter := s.loginGuard.RecordFailure(clientIP, uname)
		action := "LOGIN_FAILED"
		if lockedNow {
			action = "LOGIN_LOCKED_OUT"
		}
		s.store.AppendAuditLog(models.AuditLogEntry{
			Username: uname,
			ClientIP: clientIP,
			Action:   action,
		})
		if lockedNow {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many failed login attempts. IP/Session temporarily locked for %d seconds.", retryAfter))
			return
		}
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("%s (%d attempts remaining before temporary lock)", err.Error(), remaining))
		return
	}

	s.loginGuard.RecordSuccess(clientIP, uname)
	s.store.AppendAuditLog(models.AuditLogEntry{
		Username: user.Username,
		ClientIP: clientIP,
		Action:   "LOGIN_SUCCESS",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated or session expired")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	u := s.currentUser(r)
	if u == nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to change password")
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	updatedUser, newToken, err := s.store.ChangePassword(u.Username, body.CurrentPassword, body.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.store.AppendAuditLog(models.AuditLogEntry{
		Username: u.Username,
		ClientIP: s.clientIP(r),
		Action:   "CHANGE_PASSWORD",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": newToken,
		"user":  updatedUser,
	})
}
