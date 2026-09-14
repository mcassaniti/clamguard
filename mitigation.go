package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// rawFDReader wraps an integer file descriptor and implements io.Reader
type rawFDReader int

func (r rawFDReader) Read(p []byte) (n int, err error) {
	n, err = unix.Read(int(r), p)
	if err != nil {
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return 0, nil
		}
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// QuarantineAndMitigate performs chunk-by-chunk copying to quarantine, unlinks the threat,
// strips permissions on the quarantine copy, and triggers a desktop notification.
func QuarantineAndMitigate(eventFd int, resolvedPath string, virusName string, quarantineDir string) error {
	// 1. Ensure quarantine directory exists with restricted permissions
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	// 2. Perform chunk-by-chunk copy from the open event FD
	// This is container-safe and avoids triggering new open events on the system path.
	if _, err := unix.Seek(eventFd, 0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek event FD to start: %w", err)
	}

	fileName := filepath.Base(resolvedPath)
	if fileName == "" || fileName == "." || fileName == "/" {
		fileName = "quarantined-file"
	}
	// Append suffix to avoid collisions
	destPath := filepath.Join(quarantineDir, fmt.Sprintf("%s.quarantine", fileName))

	// Create with 000 permissions immediately
	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0000)
	if err != nil {
		return fmt.Errorf("failed to create quarantine file: %w", err)
	}
	defer destFile.Close()

	reader := rawFDReader(eventFd)
	_, copyErr := io.Copy(destFile, reader)
	if copyErr != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("failed to copy file to quarantine: %w", copyErr)
	}

	// 3. Explicitly strip permissions (chmod 000) on the quarantined copy
	if err := destFile.Chmod(0000); err != nil {
		return fmt.Errorf("failed to chmod 000 on quarantined file: %w", err)
	}

	// 4. Unlink (delete) the original threat file
	if err := os.Remove(resolvedPath); err != nil {
		return fmt.Errorf("failed to unlink original threat file %s: %w", resolvedPath, err)
	}

	// 5. Fire D-Bus desktop notification
	summary := "Threat Intercepted & Quarantined"
	body := fmt.Sprintf("File: %s\nDetected: %s\nQuarantined to: %s", resolvedPath, virusName, destPath)
	go func() {
		if notifyErr := SendDesktopNotification(summary, body); notifyErr != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] D-Bus notification failed: %v\n", notifyErr)
		}
	}()

	return nil
}

// SendDesktopNotification connects to the session bus (with fallback options) and sends a notification.
func SendDesktopNotification(summary, body string) error {
	addr, err := getSessionBusAddress()
	var conn *dbus.Conn
	if err == nil && addr != "" {
		conn, err = dbus.Dial(addr)
		if err == nil {
			if err = conn.Auth(nil); err != nil {
				conn.Close()
				conn = nil
			}
		}
	}

	if conn == nil {
		conn, err = dbus.SessionBus()
		if err != nil {
			conn, err = dbus.SystemBus()
			if err != nil {
				return fmt.Errorf("failed to connect to D-Bus: %w", err)
			}
		}
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	call := obj.Call("org.freedesktop.Notifications.Notify", 0,
		"Clamguard",               // App Name
		uint32(0),                 // Replaces ID
		"dialog-warning",          // App Icon
		summary,                   // Summary
		body,                      // Body
		[]string{},                // Actions
		map[string]dbus.Variant{}, // Hints
		int32(10000),              // Timeout (ms)
	)
	return call.Err
}

// getSessionBusAddress scans process environments in /proc to find a logged-in user's Session Bus address.
func getSessionBusAddress() (string, error) {
	if addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); addr != "" {
		return addr, nil
	}

	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		environPath := filepath.Join("/proc", strconv.Itoa(pid), "environ")
		data, err := os.ReadFile(environPath)
		if err != nil {
			continue
		}

		parts := bytes.Split(data, []byte{0})
		for _, part := range parts {
			if bytes.HasPrefix(part, []byte("DBUS_SESSION_BUS_ADDRESS=")) {
				addr := string(bytes.TrimPrefix(part, []byte("DBUS_SESSION_BUS_ADDRESS=")))
				if addr != "" {
					return addr, nil
				}
			}
		}
	}

	return "", fmt.Errorf("DBUS_SESSION_BUS_ADDRESS not found in process environments")
}
