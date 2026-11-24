// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package store

import (
	"log"
	"time"

	"lg-for-bgp/internal/models"
)

const (
	maxInMemoryAuditLogs = 1000
	auditFlushBatchSize  = 64
	auditFlushInterval   = 250 * time.Millisecond
)

func (s *AppStore) startAuditWorker() {
	s.auditWG.Add(1)
	go s.auditBatchLoop()
}

func (s *AppStore) auditBatchLoop() {
	defer s.auditWG.Done()
	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()

	batch := make([]models.AuditLogEntry, 0, auditFlushBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.persistAuditBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case entry := <-s.auditCh:
			batch = append(batch, entry)
			if len(batch) >= auditFlushBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.auditStopCh:
			// Drain any remaining queued entries before shutdown
			for {
				select {
				case entry := <-s.auditCh:
					batch = append(batch, entry)
					if len(batch) >= auditFlushBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *AppStore) persistAuditBatch(batch []models.AuditLogEntry) {
	if len(batch) == 0 {
		return
	}
	s.mu.RLock()
	db := s.db
	driver := s.dbDriver
	filePath := s.filePath
	s.mu.RUnlock()

	if db != nil {
		tx, err := db.Begin()
		if err != nil {
			// Fallback to individual inserts if transaction cannot start
			for _, entry := range batch {
				_, _ = db.Exec(`
					INSERT INTO lg_audit_logs (timestamp, username, client_ip, action, query_type, target, views, rr_node, duration_ms)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				`, formatDBTimeForDriver(driver, entry.Timestamp), entry.Username, entry.ClientIP, entry.Action, entry.QueryType, entry.Target, entry.Views, entry.RRNode, entry.DurationMs)
			}
			return
		}
		stmt, errStmt := tx.Prepare(`
			INSERT INTO lg_audit_logs (timestamp, username, client_ip, action, query_type, target, views, rr_node, duration_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if errStmt != nil {
			_ = tx.Rollback()
			return
		}
		for _, entry := range batch {
			_, _ = stmt.Exec(
				formatDBTimeForDriver(driver, entry.Timestamp),
				entry.Username,
				entry.ClientIP,
				entry.Action,
				entry.QueryType,
				entry.Target,
				entry.Views,
				entry.RRNode,
				entry.DurationMs,
			)
		}
		_ = stmt.Close()
		_ = tx.Commit()
		return
	}

	if filePath != "" && filePath != "memory" {
		s.mu.Lock()
		_ = s.persistFileLocked()
		s.mu.Unlock()
	}
}

func formatDBTimeForDriver(driver string, t time.Time) interface{} {
	if driver == "sqlite" {
		return formatSQLiteTime(t)
	}
	return t
}

// AppendAuditLog records an audit entry in memory immediately (under a lightweight dedicated lock)
// and enqueues it for asynchronous batched persistence so HTTP query hot paths never block on SQL I/O.
func (s *AppStore) AppendAuditLog(entry models.AuditLogEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	log.Printf("[AUDIT] user=%s ip=%s action=%s type=%s target=%s views=[%s] rr=%s duration=%dms",
		entry.Username, entry.ClientIP, entry.Action, entry.QueryType, entry.Target, entry.Views, entry.RRNode, entry.DurationMs)

	s.auditMu.Lock()
	if len(s.auditLogs) >= maxInMemoryAuditLogs {
		copy(s.auditLogs[1:], s.auditLogs[:maxInMemoryAuditLogs-1])
		s.auditLogs[0] = entry
	} else {
		s.auditLogs = append(s.auditLogs, models.AuditLogEntry{})
		copy(s.auditLogs[1:], s.auditLogs[:len(s.auditLogs)-1])
		s.auditLogs[0] = entry
	}
	s.auditMu.Unlock()

	select {
	case s.auditCh <- entry:
	default:
		// Channel saturated under extreme burst: drop oldest or persist synchronously in background
		go s.persistAuditBatch([]models.AuditLogEntry{entry})
	}
}

// GetAuditLogs returns a snapshot of the most recent audit log entries without acquiring AppStore.mu.
func (s *AppStore) GetAuditLogs() []models.AuditLogEntry {
	s.auditMu.RLock()
	defer s.auditMu.RUnlock()
	out := make([]models.AuditLogEntry, len(s.auditLogs))
	copy(out, s.auditLogs)
	return out
}

// SetAuditRetention configures automatic pruning of old lg_audit_logs rows in SQLite / MySQL.
func (s *AppStore) SetAuditRetention(retentionDays, maxRows int) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if maxRows <= 0 {
		maxRows = 50000
	}
	s.mu.Lock()
	s.auditRetentionDays = retentionDays
	s.auditMaxRows = maxRows
	hasDB := s.db != nil
	startLoop := !s.auditCleanerStarted && hasDB
	if startLoop {
		s.auditCleanerStarted = true
	}
	s.mu.Unlock()

	if hasDB {
		s.PruneAuditLogs()
	}
	if startLoop {
		s.auditWG.Add(1)
		go s.auditRetentionLoop()
	}
}

func (s *AppStore) auditRetentionLoop() {
	defer s.auditWG.Done()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.PruneAuditLogs()
		}
	}
}

// PruneAuditLogs deletes expired or excess audit log rows from MySQL/MariaDB or SQLite
// to keep database size bounded on long-running deployments (especially VyOS flash storage).
func (s *AppStore) PruneAuditLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return
	}
	days := s.auditRetentionDays
	if days <= 0 {
		days = 30
	}
	maxRows := s.auditMaxRows
	if maxRows <= 0 {
		maxRows = 50000
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	res1, err := s.db.Exec(`DELETE FROM lg_audit_logs WHERE timestamp < ?`, s.dbTimeArg(cutoff))
	var deleted int64
	if err == nil && res1 != nil {
		if n, e := res1.RowsAffected(); e == nil {
			deleted += n
		}
	}

	if s.dbDriver == "sqlite" {
		res2, err2 := s.db.Exec(`
			DELETE FROM lg_audit_logs
			WHERE id NOT IN (SELECT id FROM lg_audit_logs ORDER BY id DESC LIMIT ?)
		`, maxRows)
		if err2 == nil && res2 != nil {
			if n, e := res2.RowsAffected(); e == nil {
				deleted += n
			}
		}
		if deleted > 0 {
			_, _ = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		}
	} else {
		var thresholdID int64
		errRow := s.db.QueryRow(`SELECT id FROM lg_audit_logs ORDER BY id DESC LIMIT 1 OFFSET ?`, maxRows).Scan(&thresholdID)
		if errRow == nil && thresholdID > 0 {
			res2, err2 := s.db.Exec(`DELETE FROM lg_audit_logs WHERE id <= ?`, thresholdID)
			if err2 == nil && res2 != nil {
				if n, e := res2.RowsAffected(); e == nil {
					deleted += n
				}
			}
		}
	}

	if deleted > 0 {
		log.Printf("[DB] Pruned %d expired/excess audit log rows (retention=%dd, max_rows=%d)", deleted, days, maxRows)
	}
}
