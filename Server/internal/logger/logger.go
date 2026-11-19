// Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
package logger

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogConfig matches the production YAML `log:` block.
type LogConfig struct {
	Dir        string `yaml:"dir"`
	Filename   string `yaml:"filename"`
	MaxAgeDays int    `yaml:"max_age_days"`
	MaxBackups int    `yaml:"max_backups"`
	Compress   bool   `yaml:"compress"`
	Level      string `yaml:"level"`
	Format     string `yaml:"format"` // "json" or "text"
	Stdout     bool   `yaml:"stdout"`
	AccessLog  bool   `yaml:"access_log"`
}

// DailyRotateWriter writes today's logs to `<dir>/lg-server.log`,
// rotates previous days' logs to `<dir>/lg-server-YYYY-MM-DD.log` (or `.log.gz` when `compress: true`),
// and enforces both `max_age_days` and `max_backups`.
type DailyRotateWriter struct {
	mu          sync.Mutex
	dir         string
	baseName    string
	maxAgeDays  int
	maxBackups  int
	compress    bool
	currentDate string
	file        *os.File
}

func SetupLogger(cfg LogConfig) (*DailyRotateWriter, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		cfg.Dir = "logs"
	}
	baseName := strings.TrimSpace(cfg.Filename)
	if baseName == "" {
		baseName = "lg-server"
	}
	baseName = strings.TrimSuffix(baseName, ".log")
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 7
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 7
	}

	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", cfg.Dir, err)
	}

	w := &DailyRotateWriter{
		dir:        cfg.Dir,
		baseName:   baseName,
		maxAgeDays: cfg.MaxAgeDays,
		maxBackups: cfg.MaxBackups,
		compress:   cfg.Compress,
	}

	if err := w.rotateIfNeeded(time.Now()); err != nil {
		return nil, err
	}

	var out io.Writer = w
	if cfg.Stdout {
		out = io.MultiWriter(os.Stdout, w)
	}

	var slogLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(cfg.Level)) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: slogLevel}
	var handler slog.Handler
	if strings.EqualFold(strings.TrimSpace(cfg.Format), "text") {
		handler = slog.NewTextHandler(out, opts)
	} else {
		handler = slog.NewJSONHandler(out, opts)
	}

	slogger := slog.New(handler)
	slog.SetDefault(slogger)
	log.SetOutput(out)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	return w, nil
}

func (w *DailyRotateWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	today := now.Format("2006-01-02")
	if today != w.currentDate || w.file == nil {
		if err := w.rotateLocked(now); err != nil {
			return len(p), nil
		}
	}
	return w.file.Write(p)
}

func (w *DailyRotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

func (w *DailyRotateWriter) activeLogPath() string {
	return filepath.Join(w.dir, w.baseName+".log")
}

func (w *DailyRotateWriter) datedLogPath(dateStr string) string {
	return filepath.Join(w.dir, fmt.Sprintf("%s-%s.log", w.baseName, dateStr))
}

func (w *DailyRotateWriter) rotateIfNeeded(now time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rotateLocked(now)
}

func (w *DailyRotateWriter) rotateLocked(now time.Time) error {
	today := now.Format("2006-01-02")
	activePath := w.activeLogPath()

	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}

	// If `lg-server.log` exists from a previous day, archive it to `lg-server-YYYY-MM-DD.log` (and optionally .gz)
	if info, err := os.Stat(activePath); err == nil && info.Size() > 0 {
		fileDate := info.ModTime().Format("2006-01-02")
		if w.currentDate != "" && w.currentDate != today {
			fileDate = w.currentDate
		}
		if fileDate != today {
			archivePath := w.datedLogPath(fileDate)
			if errRename := os.Rename(activePath, archivePath); errRename == nil && w.compress {
				_ = compressLogFile(archivePath)
			}
		}
	}

	f, err := os.OpenFile(activePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	w.file = f
	w.currentDate = today

	w.cleanupOldLogsLocked(now)
	return nil
}

func compressLogFile(srcPath string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	dstPath := srcPath + ".gz"
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		_ = in.Close()
		return err
	}
	gz := gzip.NewWriter(out)
	_, errCopy := io.Copy(gz, in)
	_ = gz.Close()
	_ = out.Close()
	_ = in.Close()
	if errCopy != nil {
		_ = os.Remove(dstPath)
		return errCopy
	}
	return os.Remove(srcPath)
}

type backupFile struct {
	path    string
	modTime time.Time
}

func (w *DailyRotateWriter) cleanupOldLogsLocked(now time.Time) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	cutoff := now.AddDate(0, 0, -w.maxAgeDays).Truncate(24 * time.Hour)
	prefixDash := w.baseName + "-"
	activeName := w.baseName + ".log"

	var backups []backupFile

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == activeName {
			continue
		}
		if !strings.HasPrefix(name, w.baseName) {
			continue
		}
		if !strings.HasSuffix(name, ".log") && !strings.HasSuffix(name, ".log.gz") {
			continue
		}

		fullPath := filepath.Join(w.dir, name)
		datePart := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".log")
		if strings.HasPrefix(datePart, prefixDash) {
			datePart = strings.TrimPrefix(datePart, prefixDash)
		} else {
			datePart = strings.TrimPrefix(datePart, w.baseName)
		}

		var fileTime time.Time
		if parsedDate, errParse := time.ParseInLocation("2006-01-02", datePart, now.Location()); errParse == nil {
			fileTime = parsedDate
		} else if info, errInfo := entry.Info(); errInfo == nil {
			fileTime = info.ModTime()
		}

		// 1. Delete if older than max_age_days
		if w.maxAgeDays > 0 && !fileTime.IsZero() && fileTime.Before(cutoff) {
			_ = os.Remove(fullPath)
			continue
		}

		backups = append(backups, backupFile{
			path:    fullPath,
			modTime: fileTime,
		})
	}

	// 2. Enforce max_backups (keep newest max_backups files, delete older excess backups)
	if w.maxBackups > 0 && len(backups) > w.maxBackups {
		sort.Slice(backups, func(i, j int) bool {
			return backups[i].modTime.After(backups[j].modTime)
		})
		for _, old := range backups[w.maxBackups:] {
			_ = os.Remove(old.path)
		}
	}
}
