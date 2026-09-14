package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// raiseFdLimit raises RLIMIT_NOFILE to 65536 to prevent EMFILE errors.
func raiseFdLimit() error {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return fmt.Errorf("failed to get rlimit: %w", err)
	}

	rLimit.Cur = 65536
	if rLimit.Max < 65536 {
		rLimit.Max = 65536
	}

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return fmt.Errorf("failed to set rlimit: %w", err)
	}
	return nil
}

func main() {
	fmt.Println("Starting Clamguard...")

	// 1. Raise FD Limit
	if err := raiseFdLimit(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Could not raise FD limit: %v\n", err)
	} else {
		fmt.Println("FD limit successfully raised to 65536.")
	}

	// 2. Load Configuration
	cfg := LoadConfig()
	if cfg.Debug {
		fmt.Printf("Config: %+v\n", cfg)
	}

	// 3. Ensure Quarantine Directory Exists
	if err := os.MkdirAll(cfg.QuarantineDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to initialize quarantine directory %s: %v\n", cfg.QuarantineDir, err)
		os.Exit(1)
	}
	_ = os.Chmod(cfg.QuarantineDir, 0700)
	if cfg.Debug {
		fmt.Printf("[DEBUG] Quarantine directory initialized: %s (mode 0700)\n", cfg.QuarantineDir)
	}

	// 4. Initialize Cache & Mount Tracker
	cache := NewBoundedFileCache(cfg.CacheSize)
	mountTracker := NewMountTracker()
	if err := mountTracker.UpdateFromMountinfo(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to parse mountinfo: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Mount tracker initialized.")

	// Start background cache stats reporter
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			hits, misses := cache.Stats()
			total := hits + misses
			var ratio float64
			if total > 0 {
				ratio = float64(hits) / float64(total) * 100
			}
			fmt.Printf("[INFO] Cache Stats - Hits: %d, Misses: %d, Total: %d, Hit Ratio: %.2f%%\n", hits, misses, total, ratio)
		}
	}()

	// 4. Initialize Fanotify FDs
	blockerFd, err := InitBlocker()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Blocker Fanotify FD initialized.")

	watchdogFd, err := InitWatchdog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Watchdog initialization failed: %v. Cache invalidation on detach will be disabled.\n", err)
		watchdogFd = -1
	} else {
		fmt.Println("Watchdog Fanotify FD initialized.")
	}

	// 5. Setup Concurrency
	eventChan := make(chan BlockerEvent, 5000)
	var responseLock sync.Mutex
	selfPid := int32(os.Getpid())

	// 6. Graceful Shutdown Signal Handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Printf("\nReceived signal %s, tearing down marks and exiting...\n", sig)
		if blockerFd != -1 {
			_ = unix.Close(blockerFd)
		}
		if watchdogFd != -1 {
			_ = unix.Close(watchdogFd)
		}
		os.Exit(0)
	}()

	// 7. Spawn Watchdog Reader (if watchdog is active)
	if watchdogFd != -1 {
		go ReadWatchdogEvents(watchdogFd, blockerFd, mountTracker, cache, cfg.WatchPath, cfg.Debug)
	}

	// 8. Spawn Blocker Reader
	go ReadEvents(blockerFd, eventChan, cfg.Debug)

	// 9. Spawn Worker Pool
	var wg sync.WaitGroup
	for i := 0; i < cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for event := range eventChan {
				processEvent(event, blockerFd, cache, cfg, &responseLock, selfPid)
			}
		}(i)
	}

	fmt.Printf("Clamguard fully operational with %d workers.\n", cfg.WorkerCount)
	wg.Wait()
}

func processEvent(event BlockerEvent, blockerFd int, cache *FileCache, cfg *Config, responseLock *sync.Mutex, selfPid int32) {
	// 1. FD Lifecycle: Immediately close the event FD upon exit to avoid leaks
	if event.Fd != unix.FAN_NOFD {
		defer unix.Close(int(event.Fd))
	}

	isPermEvent := (event.Mask & (unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM)) != 0

	// 2. Self Filter: Ignore operations initiated by the daemon itself to prevent infinite loops
	if event.Pid == selfPid {
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	// 3. File Type Filter: Only scan regular files
	var stat unix.Stat_t
	if err := unix.Fstat(int(event.Fd), &stat); err != nil {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Fstat failed on FD %d: %v\n", event.Fd, err)
		}
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	if (stat.Mode & unix.S_IFMT) != unix.S_IFREG {
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	// 4. Container-Safe Path Resolution via /proc/self/fd/{fd}
	resolvedPath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", event.Fd))
	if err != nil {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Path resolution failed for FD %d: %v\n", event.Fd, err)
		}
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	// Clean path suffixes if marked as deleted by kernel
	resolvedPath = strings.TrimSuffix(resolvedPath, " (deleted)")

	// 5. Watch Path Subtree Filter
	if !isInWatchPath(resolvedPath, cfg.WatchPath) {
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	// 6. Trusted Paths Filter
	if isTrustedPath(resolvedPath, cfg.ParsedTrustedPaths) {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Allowed trusted path: %s\n", resolvedPath)
		}
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	// 6. Write-Intent Invalidation
	// 6. Write-intent and FAN_CLOSE_WRITE handling
	if (event.Mask & unix.FAN_CLOSE_WRITE) != 0 {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Close-write detected on %s. Invalidating cache.\n", resolvedPath)
		}
		cache.Invalidate(stat.Dev, stat.Ino)
	} else if (event.Mask & unix.FAN_OPEN_PERM) != 0 {
		flags, err := unix.FcntlInt(uintptr(event.Fd), unix.F_GETFL, 0)
		if err == nil {
			accMode := flags & unix.O_ACCMODE
			if accMode == unix.O_WRONLY || accMode == unix.O_RDWR {
				if cfg.Debug {
					fmt.Printf("[DEBUG] Write-intent detected on %s. Invalidating cache.\n", resolvedPath)
				}
				cache.Invalidate(stat.Dev, stat.Ino)
				_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
				return
			}
		}
	}

	// 7. Caching State Check (bypass for FAN_CLOSE_WRITE)
	if (event.Mask&unix.FAN_CLOSE_WRITE) == 0 && cache.Get(stat.Dev, stat.Ino) {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Cache hit (CLEAN): %s\n", resolvedPath)
		}
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
		return
	}

	// 8. Scanner Slow-Path (ClamAV Scan)
	if cfg.Debug {
		fmt.Printf("[DEBUG] Cache miss. Scanning file: %s (PID: %d)\n", resolvedPath, event.Pid)
	}

	// Setup 2-second timeout context for ClamAV socket scan
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var isClean bool
	var virusName string
	var scanErr error

	if cfg.StubClamd {
		if cfg.Debug {
			fmt.Printf("[DEBUG] ClamAV stub active. Automatically allowing: %s\n", resolvedPath)
		}
		isClean = true
	} else {
		isClean, virusName, scanErr = ScanFD(ctx, cfg.ClamdSocket, int(event.Fd))
		if cfg.Debug {
			fmt.Printf("[DEBUG] ScanFD result for %s (PID %d, Mask 0x%x): isClean=%v, virusName=%q, err=%v\n", resolvedPath, event.Pid, event.Mask, isClean, virusName, scanErr)
		}
	}
	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Scan error on file %s: %v\n", resolvedPath, scanErr)

		// Check for timeout or other socket errors
		if errorsIsTimeout(scanErr) {
			// Fail-closed for scanner timeout
			if cfg.Debug {
				fmt.Printf("[DEBUG] Scan timeout reached for %s. Decision: DENY\n", resolvedPath)
			}
			if isPermEvent {
				_ = WriteResponse(blockerFd, event.Fd, unix.FAN_DENY, responseLock)
			}
			return
		}

		// For other connection errors (e.g. clamd offline), fail-closed to be safe
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_DENY, responseLock)
		}
		return
	}

	if isClean {
		if cfg.Debug {
			fmt.Printf("[DEBUG] Scan clean: %s\n", resolvedPath)
		}
		// Cache as clean
		cache.Add(stat.Dev, stat.Ino)

		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_ALLOW, responseLock)
		}
	} else {
		fmt.Printf("[ALERT] Threat detected! Virus: %s, File: %s\n", virusName, resolvedPath)

		// Invalidate cache
		cache.Invalidate(stat.Dev, stat.Ino)

		// Send deny response to kernel first if it's a permission event
		if isPermEvent {
			_ = WriteResponse(blockerFd, event.Fd, unix.FAN_DENY, responseLock)
		}

		// Trigger mitigation: quarantine copy, delete original, send D-Bus alert
		if mitErr := QuarantineAndMitigate(int(event.Fd), resolvedPath, virusName, cfg.QuarantineDir); mitErr != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Mitigation failed for file %s: %v\n", resolvedPath, mitErr)
		}
	}
}

// errorsIsTimeout checks if the error indicates a context timeout or temporary networking timeout.
func errorsIsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "i/o timeout") {
		return true
	}
	return false
}

func isInWatchPath(path, watchPath string) bool {
	if watchPath == "/" {
		return true
	}
	cleanWatch := filepath.Clean(watchPath)
	cleanPath := filepath.Clean(path)
	if cleanPath == cleanWatch {
		return true
	}
	return strings.HasPrefix(cleanPath, cleanWatch+string(filepath.Separator))
}
