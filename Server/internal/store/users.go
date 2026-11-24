// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"time"

	"lg-for-bgp/internal/models"
)

const minPasswordLength = 6

func validateRawPassword(rawPassword string) error {
	if strings.TrimSpace(rawPassword) == "" {
		return errors.New("password cannot be empty or whitespace only")
	}
	if len(rawPassword) < minPasswordLength {
		return errors.New("password must be at least 6 characters long")
	}
	return nil
}

func (s *AppStore) GetUsers() []models.UserAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.UserAccount, len(s.data.Users))
	for i, u := range s.data.Users {
		uCopy := u
		uCopy.PasswordHash = ""
		out[i] = uCopy
	}
	return out
}

func (s *AppStore) Authenticate(username, password string) (*models.UserAccount, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.EqualFold(u.Username, username) {
			if !u.Enabled {
				return nil, "", errors.New("account has been disabled by administrator")
			}
			// Exact password comparison without TrimSpace mutation
			ok, needsUpgrade := VerifyPassword(u.PasswordHash, password)
			if !ok {
				return nil, "", errors.New("invalid username or password")
			}
			if needsUpgrade {
				u.PasswordHash = HashPassword(password)
				_ = s.updateUserPasswordDBLocked(u.ID, u.PasswordHash, u.MustChangePassword)
				log.Printf("[AUTH] Upgraded legacy password hash to bcrypt for user %q", u.Username)
			}
			now := time.Now()
			u.LastLoginAt = &now
			_ = s.updateUserLastLoginDBLocked(u.ID, now)

			uSafe := *u
			token, err := s.issueTokenWithHashLocked(uSafe, u.PasswordHash)
			uSafe.PasswordHash = ""
			return &uSafe, token, err
		}
	}
	return nil, "", errors.New("invalid username or password")
}

func (s *AppStore) GetUserByUsername(username string) (*models.UserAccount, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.data.Users {
		if strings.EqualFold(u.Username, username) && u.Enabled {
			uCopy := u
			uCopy.PasswordHash = ""
			return &uCopy, true
		}
	}
	return nil, false
}

func (s *AppStore) SaveUser(account models.UserAccount, rawPassword string) (*models.UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	account.Username = strings.TrimSpace(account.Username)
	if account.Username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if account.RateLimitPerMinute <= 0 {
		account.RateLimitPerMinute = 60
	}

	for i, existing := range s.data.Users {
		if existing.ID == account.ID || strings.EqualFold(existing.Username, account.Username) {
			if strings.EqualFold(existing.Username, "admin") && !account.Enabled {
				return nil, errors.New("cannot disable the default superuser account 'admin'")
			}
			if strings.EqualFold(existing.Username, "admin") && account.Role != "admin" {
				return nil, errors.New("cannot demote the default superuser account 'admin'")
			}
			account.ID = existing.ID
			account.CreatedAt = existing.CreatedAt
			account.LastLoginAt = existing.LastLoginAt
			if rawPassword != "" {
				if err := validateRawPassword(rawPassword); err != nil {
					return nil, err
				}
				account.PasswordHash = HashPassword(rawPassword)
			} else {
				account.PasswordHash = existing.PasswordHash
			}
			s.data.Users[i] = account
			s.pruneStaleViewIDsLocked()
			if err := s.upsertUserDBLocked(s.data.Users[i]); err != nil {
				return nil, err
			}
			out := s.data.Users[i]
			out.PasswordHash = ""
			return &out, nil
		}
	}

	if err := validateRawPassword(rawPassword); err != nil {
		if rawPassword == "" {
			return nil, errors.New("password is required when creating a new account")
		}
		return nil, err
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	account.ID = "u-" + hex.EncodeToString(b)
	account.PasswordHash = HashPassword(rawPassword)
	account.CreatedAt = time.Now()
	s.data.Users = append(s.data.Users, account)
	s.pruneStaleViewIDsLocked()
	saved := s.data.Users[len(s.data.Users)-1]
	if err := s.upsertUserDBLocked(saved); err != nil {
		return nil, err
	}
	out := saved
	out.PasswordHash = ""
	return &out, nil
}

// ChangePassword allows an authenticated user to change their own password and clears MustChangePassword.
// Never applies TrimSpace to either currentPassword or newPassword so leading/trailing characters match Authenticate().
func (s *AppStore) ChangePassword(username, currentPassword, newPassword string) (*models.UserAccount, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validateRawPassword(newPassword); err != nil {
		return nil, "", errors.New("new " + err.Error())
	}

	for i := range s.data.Users {
		u := &s.data.Users[i]
		if strings.EqualFold(u.Username, username) {
			ok, _ := VerifyPassword(u.PasswordHash, currentPassword)
			if !ok {
				return nil, "", errors.New("current password is incorrect")
			}
			u.PasswordHash = HashPassword(newPassword)
			u.MustChangePassword = false
			if err := s.updateUserPasswordDBLocked(u.ID, u.PasswordHash, false); err != nil {
				return nil, "", err
			}
			uSafe := *u
			token, err := s.issueTokenWithHashLocked(uSafe, u.PasswordHash)
			uSafe.PasswordHash = ""
			return &uSafe, token, err
		}
	}
	return nil, "", errors.New("user account not found")
}

func (s *AppStore) DeleteUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var filtered []models.UserAccount
	for _, u := range s.data.Users {
		if u.ID == userID {
			if strings.EqualFold(u.Username, "admin") {
				return errors.New("cannot delete default administrator account 'admin'")
			}
			continue
		}
		filtered = append(filtered, u)
	}
	s.data.Users = filtered
	if s.db != nil {
		_, err := s.db.Exec("DELETE FROM lg_users WHERE id = ?", userID)
		return err
	}
	return s.persistFileLocked()
}
