package main

import (
	"encoding/csv"
	"flag"
	"path/filepath"
	"strings"
)

type Config struct {
	ClamdSocket        string
	QuarantineDir      string
	WorkerCount        int
	Debug              bool
	StubClamd          bool
	WatchPath          string
	CacheSize          int
	TrustedPaths       string
	ParsedTrustedPaths []string
}

func LoadConfig() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.ClamdSocket, "clamd-socket", "/var/run/clamav/clamd.ctl", "Path to ClamAV Unix socket")
	flag.StringVar(&cfg.QuarantineDir, "quarantine-dir", "/var/spool/clamav-quarantine", "Directory to store quarantined threats")
	flag.IntVar(&cfg.WorkerCount, "workers", 16, "Number of worker goroutines (16-32 recommended)")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable verbose debug logging")
	flag.BoolVar(&cfg.StubClamd, "stub-clamav", false, "Stub ClamAV scanning and always assume success")
	flag.StringVar(&cfg.WatchPath, "watch-path", "/", "Interception path limit (defaults to root '/')")
	flag.IntVar(&cfg.CacheSize, "cache-size", 200000, "Maximum number of entries in the LRU cache")
	flag.StringVar(&cfg.TrustedPaths, "trusted-paths", "", "Comma-separated list of trusted paths to bypass scanning (e.g. '/my path,/usr,/mnt/')")
	flag.Parse()

	cfg.ParsedTrustedPaths = ParseTrustedPaths(cfg.TrustedPaths)
	return cfg
}

// ParseTrustedPaths parses a comma-separated string of trusted paths, accounting for spaces and quotes.
func ParseTrustedPaths(input string) []string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil
	}

	var rawList []string
	// Attempt CSV reader to support quotes and comma delimiters
	r := csv.NewReader(strings.NewReader(trimmed))
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err == nil && len(records) > 0 {
		for _, row := range records {
			for _, p := range row {
				pClean := strings.TrimSpace(p)
				if pClean != "" {
					rawList = append(rawList, pClean)
				}
			}
		}
	} else {
		// Fallback to simple comma split if CSV parsing fails
		for _, p := range strings.Split(trimmed, ",") {
			pClean := strings.TrimSpace(p)
			if pClean != "" {
				rawList = append(rawList, pClean)
			}
		}
	}

	var cleaned []string
	for _, p := range rawList {
		cleaned = append(cleaned, filepath.Clean(p))
	}
	return cleaned
}

// isTrustedPath checks if a resolved path is within any of the configured trusted paths.
func isTrustedPath(path string, trustedPaths []string) bool {
	if len(trustedPaths) == 0 {
		return false
	}
	cleanPath := filepath.Clean(path)
	for _, trusted := range trustedPaths {
		if trusted == "/" {
			return true
		}
		if cleanPath == trusted {
			return true
		}
		if strings.HasPrefix(cleanPath, trusted+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
