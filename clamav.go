package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

// ScanFD connects to clamd via Unix socket and sends the FD for scanning.
// It returns (isClean, virusName, error).
func ScanFD(ctx context.Context, socketPath string, fd int) (bool, string, error) {
	// Connect to clamd Unix socket with a timeout
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return false, "", fmt.Errorf("failed to connect to clamd socket: %w", err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false, "", errors.New("connection is not a UnixConn")
	}

	// Reset the file offset to 0 so ClamAV reads from the beginning (critical for FAN_CLOSE_WRITE / append modes)
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil && err != unix.ESPIPE {
		// Non-pipe files should be seekable; log or continue if not
	}

	// In ClamAV protocol, send the zFILDES command first, then send the dummy byte with the FD as ancillary data (SCM_RIGHTS).
	_, err = unixConn.Write([]byte("zFILDES\x00"))
	if err != nil {
		return false, "", fmt.Errorf("failed to send zFILDES command: %w", err)
	}

	oob := unix.UnixRights(fd)
	_, _, err = unixConn.WriteMsgUnix([]byte{0}, oob, nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to send FD: %w", err)
	}

	// Set a deadline on the socket for reading response if context has a deadline
	if deadline, ok := ctx.Deadline(); ok {
		_ = unixConn.SetDeadline(deadline)
	}

	// Read the response from clamd
	buf := make([]byte, 4096)
	n, err := unixConn.Read(buf)
	if err != nil && err != io.EOF {
		return false, "", fmt.Errorf("failed to read clamd response: %w", err)
	}

	resp := string(buf[:n])
	// fmt.Printf("[DEBUG] clamd raw resp: %q\n", resp)
	// Response format is typically:
	// Clean: "stream: OK\n" or "fd[x]: OK\x00"
	// Infected: "stream: <VirusName> FOUND\n" or "fd[x]: <VirusName> FOUND\x00"
	// Error: "stream: <ErrorMsg> ERROR\n"
	if strings.Contains(resp, "FOUND") {
		parts := strings.Split(resp, ":")
		virusName := "Unknown Virus"
		if len(parts) >= 2 {
			virusAndFound := strings.Trim(strings.TrimSpace(parts[1]), "\x00\r\n ")
			if strings.HasSuffix(virusAndFound, " FOUND") {
				virusName = strings.TrimSuffix(virusAndFound, " FOUND")
			} else {
				virusName = virusAndFound
			}
		}
		return false, virusName, nil
	}

	if strings.Contains(resp, "OK") {
		return true, "", nil
	}

	if strings.Contains(resp, "ERROR") {
		return false, "", fmt.Errorf("clamd scan error: %s", strings.TrimSpace(resp))
	}

	return false, "", fmt.Errorf("unexpected clamd response: %s", strings.TrimSpace(resp))
}
