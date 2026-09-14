package main

import (
	"errors"
	"net"
	"testing"
)

type dummyTimeoutError struct{}

func (e *dummyTimeoutError) Error() string   { return "i/o timeout" }
func (e *dummyTimeoutError) Timeout() bool   { return true }
func (e *dummyTimeoutError) Temporary() bool { return true }

func TestIsInWatchPath(t *testing.T) {
	tests := []struct {
		path      string
		watchPath string
		expected  bool
	}{
		{"/var/log/syslog", "/", true},
		{"/tmp/test/file.txt", "/tmp/test", true},
		{"/tmp/test/sub/file.txt", "/tmp/test", true},
		{"/tmp/test", "/tmp/test", true},
		{"/tmp/test2/file.txt", "/tmp/test", false},
		{"/var/tmp/file.txt", "/tmp", false},
		{"/home/user/document.pdf", "/home/user", true},
		{"/home/user_other/doc.pdf", "/home/user", false},
	}

	for _, tt := range tests {
		result := isInWatchPath(tt.path, tt.watchPath)
		if result != tt.expected {
			t.Errorf("isInWatchPath(%q, %q) = %v; expected %v", tt.path, tt.watchPath, result, tt.expected)
		}
	}
}

func TestErrorsIsTimeout(t *testing.T) {
	if errorsIsTimeout(nil) {
		t.Fatalf("expected nil to not be timeout")
	}

	deadlineErr := errors.New("context deadline exceeded")
	if !errorsIsTimeout(deadlineErr) {
		t.Fatalf("expected deadlineErr to be recognized as timeout")
	}

	var netErr net.Error = &dummyTimeoutError{}
	if !errorsIsTimeout(netErr) {
		t.Fatalf("expected net.Error timeout to be recognized as timeout")
	}

	randomErr := errors.New("connection refused")
	if errorsIsTimeout(randomErr) {
		t.Fatalf("expected randomErr to not be recognized as timeout")
	}
}

func TestParseTrustedPaths(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{
			input:    "/my path,/usr,/mnt/",
			expected: []string{"/my path", "/usr", "/mnt"},
		},
		{
			input:    " /my path , /usr/local/bin/ , /mnt/ ",
			expected: []string{"/my path", "/usr/local/bin", "/mnt"},
		},
		{
			input:    "\"/path with, comma\",/usr",
			expected: []string{"/path with, comma", "/usr"},
		},
		{
			input:    "",
			expected: nil,
		},
		{
			input:    "   ",
			expected: nil,
		},
	}

	for _, tt := range tests {
		result := ParseTrustedPaths(tt.input)
		if len(result) != len(tt.expected) {
			t.Fatalf("ParseTrustedPaths(%q) returned %d items (%v), expected %d (%v)",
				tt.input, len(result), result, len(tt.expected), tt.expected)
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("ParseTrustedPaths(%q)[%d] = %q; expected %q",
					tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

func TestIsTrustedPath(t *testing.T) {
	trusted := ParseTrustedPaths("/my path,/usr,/mnt/")

	tests := []struct {
		path     string
		expected bool
	}{
		{"/my path/sub/file.txt", true},
		{"/my path/file.txt", true},
		{"/my path", true},
		{"/my path_extra/file.txt", false},
		{"/usr/bin/python3", true},
		{"/usr/lib/x86_64/libc.so", true},
		{"/usr", true},
		{"/usr_backup/file.txt", false},
		{"/mnt/usb/data.csv", true},
		{"/mnt", true},
		{"/var/log/syslog", false},
		{"/home/user/document.pdf", false},
	}

	for _, tt := range tests {
		result := isTrustedPath(tt.path, trusted)
		if result != tt.expected {
			t.Errorf("isTrustedPath(%q, %v) = %v; expected %v", tt.path, trusted, result, tt.expected)
		}
	}
}
