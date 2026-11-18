package logger

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyRotateAndRetentionCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	now := time.Now()
	oldDate := now.AddDate(0, 0, -10).Format("2006-01-02")
	recentDate := now.AddDate(0, 0, -2).Format("2006-01-02")

	oldFile := filepath.Join(tmpDir, "lg-server-"+oldDate+".log.gz")
	recentFile := filepath.Join(tmpDir, "lg-server-"+recentDate+".log")
	_ = os.WriteFile(oldFile, []byte("old log"), 0644)
	_ = os.WriteFile(recentFile, []byte("recent log"), 0644)

	w, err := SetupLogger(LogConfig{
		Dir:        tmpDir,
		Filename:   "lg-server",
		MaxAgeDays: 7,
		MaxBackups: 7,
		Compress:   true,
		Level:      "info",
		Format:     "json",
		Stdout:     false,
		AccessLog:  true,
	})
	if err != nil {
		t.Fatalf("SetupLogger failed: %v", err)
	}
	defer w.Close()

	_, _ = w.Write([]byte("today log line\n"))

	activeFile := filepath.Join(tmpDir, "lg-server.log")
	if _, err := os.Stat(activeFile); err != nil {
		t.Fatalf("expected active log file %s to exist: %v", activeFile, err)
	}

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatalf("expected expired log file %s to be deleted!", oldFile)
	}

	if _, err := os.Stat(recentFile); err != nil {
		t.Fatalf("expected recent log file %s to be preserved: %v", recentFile, err)
	}
}
