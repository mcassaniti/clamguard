package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Define local copies of new constants in case x/sys/unix doesn't include them
const (
	optFAN_REPORT_MNT          = 0x00004000
	optFAN_MARK_MNTNS          = 0x00000110
	optFAN_MNT_ATTACH          = 0x01000000
	optFAN_MNT_DETACH          = 0x02000000
	optFAN_EVENT_INFO_TYPE_MNT = 0x07
)

type BlockerEvent struct {
	Fd   int32
	Pid  int32
	Mask uint64
}

type FanotifyEventInfoHeader struct {
	Info_type uint8
	Pad       uint8
	Len       uint16
}

var sizeofFanotifyEventMetadata = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

// InitBlocker initializes the primary blocking fanotify group and sets marks on the root filesystem.
func InitBlocker() (int, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLOEXEC|unix.FAN_CLASS_PRE_CONTENT|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS,
		unix.O_RDONLY,
	)
	if err != nil {
		return -1, fmt.Errorf("failed to init blocker fanotify: %w", err)
	}

	// Mark the root superblock (/) for events: FAN_OPEN_PERM, FAN_OPEN_EXEC_PERM, FAN_CLOSE_WRITE
	err = unix.FanotifyMark(
		fd,
		unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
		unix.FAN_OPEN_PERM|unix.FAN_OPEN_EXEC_PERM|unix.FAN_CLOSE_WRITE,
		unix.AT_FDCWD,
		"/",
	)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("failed to mark filesystem in blocker: %w", err)
	}

	return fd, nil
}

// InitWatchdog initializes the secondary mount tracker fanotify group.
func InitWatchdog() (int, error) {
	fd, err := unix.FanotifyInit(
		unix.FAN_CLOEXEC|unix.FAN_CLASS_NOTIF|optFAN_REPORT_MNT|unix.FAN_UNLIMITED_QUEUE,
		unix.O_RDONLY,
	)
	if err != nil {
		return -1, fmt.Errorf("failed to init watchdog fanotify: %w", err)
	}

	// Mark the mount namespace in host namespace (/proc/self/ns/mnt) for attach and detach events
	err = unix.FanotifyMark(
		fd,
		unix.FAN_MARK_ADD|optFAN_MARK_MNTNS,
		optFAN_MNT_ATTACH|optFAN_MNT_DETACH,
		unix.AT_FDCWD,
		"/proc/self/ns/mnt",
	)
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("failed to mark mount namespace in watchdog: %w", err)
	}

	return fd, nil
}

// ReadEvents reads from the blocker FD and pushes to the channel.
func ReadEvents(fanFd int, eventChan chan<- BlockerEvent, debug bool) {
	var buf [4096]byte
	for {
		n, err := unix.Read(fanFd, buf[:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EBADF {
				// FD was closed during graceful shutdown
				break
			}
			fmt.Fprintf(os.Stderr, "[ERROR] failed to read blocker fanotify events: %v\n", err)
			break
		}

		if n == 0 {
			break
		}

		var offset int
		for offset+sizeofFanotifyEventMetadata <= n {
			metadata := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			eventLen := int(metadata.Event_len)
			if eventLen == 0 {
				break
			}

			if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
				if debug {
					fmt.Printf("[DEBUG] version mismatch: got %d, expected %d\n", metadata.Vers, unix.FANOTIFY_METADATA_VERSION)
				}
				offset += eventLen
				continue
			}

			// Push to queue
			eventChan <- BlockerEvent{
				Fd:   metadata.Fd,
				Pid:  metadata.Pid,
				Mask: metadata.Mask,
			}

			offset += eventLen
		}
	}
}

// ReadWatchdogEvents reads from the watchdog FD and processes attach and detach events.
func ReadWatchdogEvents(fanFd int, blockerFd int, mt *MountTracker, cache *FileCache, watchPath string, debug bool) {
	var buf [4096]byte
	for {
		n, err := unix.Read(fanFd, buf[:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EBADF {
				// FD closed
				break
			}
			fmt.Fprintf(os.Stderr, "[ERROR] failed to read watchdog fanotify events: %v\n", err)
			break
		}

		if n == 0 {
			break
		}

		var offset int
		for offset+sizeofFanotifyEventMetadata <= n {
			metadata := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			eventLen := int(metadata.Event_len)
			if eventLen == 0 {
				break
			}

			if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
				offset += eventLen
				continue
			}

			// If it's a mount attach event, refresh mounts and mark new filesystems on blocker
			if (metadata.Mask & optFAN_MNT_ATTACH) != 0 {
				if debug {
					fmt.Println("[DEBUG] Watchdog detected mount attachment")
				}
				_ = mt.UpdateFromMountinfo()
				if blockerFd != -1 {
					for _, mp := range mt.GetMountPoints() {
						if isInWatchPath(mp, watchPath) || isInWatchPath(watchPath, mp) {
							_ = unix.FanotifyMark(
								blockerFd,
								unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM,
								unix.FAN_OPEN_PERM|unix.FAN_OPEN_EXEC_PERM|unix.FAN_CLOSE_WRITE,
								unix.AT_FDCWD,
								mp,
							)
						}
					}
				}
			}

			// If it's a mount detach event, extract the mount ID
			if (metadata.Mask & optFAN_MNT_DETACH) != 0 {
				// Parse info records to find mount ID
				infoOffset := offset + int(metadata.Metadata_len)
				infoEnd := offset + eventLen

				for infoOffset+4 <= infoEnd {
					header := (*FanotifyEventInfoHeader)(unsafe.Pointer(&buf[infoOffset]))
					recordLen := int(header.Len)
					if recordLen == 0 {
						break
					}

					if header.Info_type == optFAN_EVENT_INFO_TYPE_MNT {
						if recordLen >= 16 {
							mntID := *(*uint64)(unsafe.Pointer(&buf[infoOffset+8]))
							if debug {
								fmt.Printf("[DEBUG] Watchdog detected detachment of mount ID: %d\n", mntID)
							}
							dev, ok := mt.ResolveAndRemove(mntID)
							if ok {
								if debug {
									fmt.Printf("[DEBUG] Purging cache entries for device ID: %d\n", dev)
								}
								cache.PurgeMount(dev)
							} else {
								if debug {
									fmt.Printf("[DEBUG] Mount ID %d not found in MountTracker\n", mntID)
								}
							}
						}
					}
					infoOffset += recordLen
				}
			}

			offset += eventLen
		}
	}
}

// WriteResponse writes a response to the blocker FD in a thread-safe manner.
func WriteResponse(fanFd int, eventFd int32, response uint32, mu *sync.Mutex) error {
	mu.Lock()
	defer mu.Unlock()

	var buf [8]byte
	binary.NativeEndian.PutUint32(buf[0:4], uint32(eventFd))
	binary.NativeEndian.PutUint32(buf[4:8], response)

	n, err := unix.Write(fanFd, buf[:])
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("short write: wrote %d, expected %d", n, len(buf))
	}
	return nil
}
