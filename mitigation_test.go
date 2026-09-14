package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineAndMitigate(t *testing.T) {
	tempDir := t.TempDir()
	quarantineDir := filepath.Join(tempDir, "quarantine")
	sourcePath := filepath.Join(tempDir, "malware.exe")

	payload := "DUMMY_VIRUS_PAYLOAD_1234567890"
	err := os.WriteFile(sourcePath, []byte(payload), 0644)
	if err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	f, err := os.OpenFile(sourcePath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open source file: %v", err)
	}
	defer f.Close()

	// Run mitigation
	err = QuarantineAndMitigate(int(f.Fd()), sourcePath, "EICAR-Test-Signature", quarantineDir)
	if err != nil {
		t.Fatalf("QuarantineAndMitigate failed: %v", err)
	}

	// 1. Verify original file is unlinked
	if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Fatalf("expected original file %s to be unlinked, but stat returned: %v", sourcePath, err)
	}

	// 2. Verify quarantine file exists
	expectedQuarantinePath := filepath.Join(quarantineDir, "malware.exe.quarantine")
	stat, err := os.Stat(expectedQuarantinePath)
	if err != nil {
		t.Fatalf("expected quarantine file at %s: %v", expectedQuarantinePath, err)
	}

	// 3. Verify stripped permissions (000)
	if stat.Mode().Perm() != 0000 {
		t.Fatalf("expected quarantine file permissions 0000, got: %o", stat.Mode().Perm())
	}

	// 4. Verify content by temporarily restoring read permissions
	_ = os.Chmod(expectedQuarantinePath, 0400)
	content, err := os.ReadFile(expectedQuarantinePath)
	if err != nil {
		t.Fatalf("failed to read quarantined file: %v", err)
	}

	if string(content) != payload {
		t.Fatalf("quarantined content mismatch: got %q, expected %q", string(content), payload)
	}
}
