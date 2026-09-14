package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// startMockClamd creates a mock Unix socket server that implements the ClamAV FILDES protocol.
func startMockClamd(t *testing.T, handler func(conn *net.UnixConn, cmd string, passedFD int)) (string, func()) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "clamd.sock")

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := l.AcceptUnix()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c *net.UnixConn) {
				defer c.Close()

				buf := make([]byte, 1024)
				oob := make([]byte, 1024)

				var cmd string
				var passedFD int = -1

				for {
					n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
					if err != nil {
						break
					}
					if n > 0 && cmd == "" {
						cmd = string(buf[:n])
					}
					if oobn > 0 && passedFD == -1 {
						cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
						if err == nil {
							for _, cmsg := range cmsgs {
								fds, err := unix.ParseUnixRights(&cmsg)
								if err == nil && len(fds) > 0 {
									passedFD = fds[0]
									defer unix.Close(passedFD)
									break
								}
							}
						}
					}
					if cmd != "" && passedFD != -1 {
						break
					}
				}

				handler(c, cmd, passedFD)
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		l.Close()
	}

	return sockPath, cleanup
}

func TestScanFDClean(t *testing.T) {
	sockPath, cleanup := startMockClamd(t, func(conn *net.UnixConn, cmd string, passedFD int) {
		if !strings.Contains(cmd, "FILDES") {
			_, _ = conn.Write([]byte("stream: Bad command ERROR\n"))
			return
		}
		if passedFD < 0 {
			_, _ = conn.Write([]byte("stream: No FD passed ERROR\n"))
			return
		}

		// Read content from passed FD
		f := os.NewFile(uintptr(passedFD), "scanned-file")
		content, err := io.ReadAll(f)
		if err != nil {
			_, _ = conn.Write([]byte("stream: Read error ERROR\n"))
			return
		}

		if string(content) == "CLEAN_CONTENT" {
			_, _ = conn.Write([]byte("stream: OK\n"))
		} else {
			_, _ = conn.Write([]byte("stream: Mismatch ERROR\n"))
		}
	})
	defer cleanup()

	// Create a test file
	tmpFile, err := os.CreateTemp(t.TempDir(), "clean-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString("CLEAN_CONTENT"); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}

	// Deliberately leave offset at EOF to verify ScanFD seeks back to 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	isClean, virusName, err := ScanFD(ctx, sockPath, int(tmpFile.Fd()))
	if err != nil {
		t.Fatalf("ScanFD returned error: %v", err)
	}
	if !isClean {
		t.Fatalf("expected file to be clean, but got threat: %s", virusName)
	}
}

func TestScanFDThreatDetected(t *testing.T) {
	sockPath, cleanup := startMockClamd(t, func(conn *net.UnixConn, cmd string, passedFD int) {
		_, _ = conn.Write([]byte("stream: Win.Test.EICAR_HDB-1 FOUND\n"))
	})
	defer cleanup()

	tmpFile, err := os.CreateTemp(t.TempDir(), "eicar-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, _ = tmpFile.WriteString("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	isClean, virusName, err := ScanFD(ctx, sockPath, int(tmpFile.Fd()))
	if err != nil {
		t.Fatalf("ScanFD failed: %v", err)
	}
	if isClean {
		t.Fatalf("expected virus detection, but got clean verdict")
	}
	if virusName != "Win.Test.EICAR_HDB-1" {
		t.Fatalf("expected virus Win.Test.EICAR_HDB-1, got %q", virusName)
	}
}

func TestScanFDTimeout(t *testing.T) {
	sockPath, cleanup := startMockClamd(t, func(conn *net.UnixConn, cmd string, passedFD int) {
		// Simulate hanging scanner
		time.Sleep(500 * time.Millisecond)
		_, _ = conn.Write([]byte("stream: OK\n"))
	})
	defer cleanup()

	tmpFile, err := os.CreateTemp(t.TempDir(), "timeout-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Short timeout (50ms) to trigger timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err = ScanFD(ctx, sockPath, int(tmpFile.Fd()))
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if !errorsIsTimeout(err) {
		t.Fatalf("expected errorsIsTimeout to return true for err: %v", err)
	}
}
