// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"lg-for-bgp/internal/models"
)

func (s *AppStore) SetJWTConfig(secret string, refreshDays int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(secret) != "" {
		s.jwtSecret = []byte(secret)
	}
	if refreshDays > 0 {
		s.jwtExpiryDays = refreshDays
	}
}

// LegacySHA256Hash computes the legacy salted SHA-256 password hash used by earlier versions,
// kept solely for transparent login migration to bcrypt.
func LegacySHA256Hash(password string) string {
	h := sha256.Sum256([]byte("lg-for-bgp-salt:" + password))
	return hex.EncodeToString(h[:])
}

// HashPassword hashes a plaintext password using bcrypt (salted, adaptive work factor).
// Exact password bytes are preserved without whitespace mutation.
func HashPassword(password string) string {
	pwBytes := []byte(password)
	if len(pwBytes) > 72 {
		sum := sha256.Sum256(pwBytes)
		pwBytes = []byte("sha256:" + hex.EncodeToString(sum[:]))
	}
	hashed, err := bcrypt.GenerateFromPassword(pwBytes, bcrypt.DefaultCost)
	if err != nil {
		return LegacySHA256Hash(password)
	}
	return string(hashed)
}

// VerifyPassword verifies a plaintext password against a stored bcrypt or legacy SHA-256 hash.
// Returns (matched, needsUpgrade) where needsUpgrade is true when a legacy hash matched and should be upgraded to bcrypt.
func VerifyPassword(storedHash, password string) (bool, bool) {
	if strings.HasPrefix(storedHash, "$2a$") || strings.HasPrefix(storedHash, "$2b$") || strings.HasPrefix(storedHash, "$2y$") {
		pwBytes := []byte(password)
		if len(pwBytes) > 72 {
			sum := sha256.Sum256(pwBytes)
			pwBytes = []byte("sha256:" + hex.EncodeToString(sum[:]))
		}
		return bcrypt.CompareHashAndPassword([]byte(storedHash), pwBytes) == nil, false
	}
	legacy := LegacySHA256Hash(password)
	if hmac.Equal([]byte(storedHash), []byte(legacy)) {
		return true, true
	}
	return false, false
}

type tokenPayload struct {
	Username string `json:"sub"`
	Role     string `json:"role"`
	BootID   string `json:"bid"`
	PwdTag   string `json:"ptg"`
	Exp      int64  `json:"exp"`
}

func (s *AppStore) pwdTagOf(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:6])
}

func (s *AppStore) IssueToken(user models.UserAccount) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pHash := user.PasswordHash
	if pHash == "" {
		for _, u := range s.data.Users {
			if strings.EqualFold(u.Username, user.Username) {
				pHash = u.PasswordHash
				break
			}
		}
	}
	return s.issueTokenWithHashLocked(user, pHash)
}

func (s *AppStore) issueTokenWithHashLocked(user models.UserAccount, pHash string) (string, error) {
	days := s.jwtExpiryDays
	if days <= 0 {
		days = 7
	}
	payload := tokenPayload{
		Username: user.Username,
		Role:     user.Role,
		BootID:   s.bootInstanceID,
		PwdTag:   s.pwdTagOf(pHash),
		Exp:      time.Now().Add(time.Duration(days) * 24 * time.Hour).Unix(),
	}
	rawJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(rawJSON)
	mac := hmac.New(sha256.New, append(append([]byte{}, s.jwtSecret...), []byte(":"+s.bootInstanceID)...))
	mac.Write([]byte(b64Payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return b64Payload + "." + sig, nil
}

func (s *AppStore) VerifyToken(token string) (*models.UserAccount, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}
	s.mu.RLock()
	secretWithBoot := append(append([]byte{}, s.jwtSecret...), []byte(":"+s.bootInstanceID)...)
	bootID := s.bootInstanceID
	s.mu.RUnlock()

	mac := hmac.New(sha256.New, secretWithBoot)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return nil, errors.New("session expired or server restarted")
	}
	rawJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var payload tokenPayload
	if err := json.Unmarshal(rawJSON, &payload); err != nil {
		return nil, err
	}
	if payload.BootID != bootID {
		return nil, errors.New("server restarted, please sign in again")
	}
	if time.Now().Unix() > payload.Exp {
		return nil, errors.New("token expired")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if strings.EqualFold(u.Username, payload.Username) && u.Enabled {
			if payload.PwdTag != "" && payload.PwdTag != s.pwdTagOf(u.PasswordHash) {
				return nil, errors.New("password has changed, please sign in again")
			}
			uCopy := u
			uCopy.PasswordHash = ""
			return &uCopy, nil
		}
	}
	return nil, errors.New("user not found or disabled")
}
