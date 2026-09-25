package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	substitutionLogDirMode  = 0o750
	substitutionLogFileMode = 0o640
)

// substitutionLogConfig is the substitution_log mapping. Logging is off unless
// enabled is true. The file stores original values, so the default stays off.
// Rotation is not done here; deploy/logrotate installs a host logrotate rule.
type substitutionLogConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

func (c substitutionLogConfig) effectivePath() string {
	path := strings.TrimSpace(c.Path)
	if path == "" {
		return "logs/privacyfilter-substitutions.jsonl"
	}
	return path
}

// substitutionRecord is one redaction. Original is the matched plaintext.
type substitutionRecord struct {
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	RuleID      string    `json:"rule_id,omitempty"`
	Placeholder string    `json:"placeholder"`
	Original    string    `json:"original"`
}

// substitutionLogger appends one JSON line per substitution. Daily gzip and
// seven-day retention belong to logrotate, not this process.
type substitutionLogger struct {
	path string
	now  func() time.Time

	mu     sync.Mutex
	file   *os.File
	closed bool
}

func newSubstitutionLogger(path string) (*substitutionLogger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("substitution log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), substitutionLogDirMode); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, substitutionLogFileMode)
	if err != nil {
		return nil, err
	}
	return &substitutionLogger{path: path, now: time.Now, file: file}, nil
}

func (l *substitutionLogger) Record(kind, ruleID, placeholder, original string) {
	if l == nil {
		return
	}
	record := substitutionRecord{
		Time:        l.now().UTC(),
		Kind:        kind,
		RuleID:      ruleID,
		Placeholder: placeholder,
		Original:    original,
	}
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.file == nil {
		return
	}
	_, _ = l.file.Write(append(line, '\n'))
}

func (l *substitutionLogger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
