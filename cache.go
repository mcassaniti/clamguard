package main

import (
	"bufio"
	"container/list"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const DefaultCacheCapacity = 200000

type cacheEntry struct {
	dev uint64
	ino uint64
}

// FileCache is a thread-safe, strictly bounded LRU cache keyed by (stat.Dev, stat.Ino).
type FileCache struct {
	mu       sync.Mutex
	capacity int
	items    map[uint64]map[uint64]*list.Element // dev -> ino -> list element
	lruList  *list.List
	hits     uint64
	misses   uint64
}

// NewFileCache creates a bounded FileCache with DefaultCacheCapacity.
func NewFileCache() *FileCache {
	return NewBoundedFileCache(DefaultCacheCapacity)
}

// NewBoundedFileCache creates a bounded FileCache with a specified capacity.
func NewBoundedFileCache(capacity int) *FileCache {
	if capacity <= 0 {
		capacity = DefaultCacheCapacity
	}
	return &FileCache{
		capacity: capacity,
		items:    make(map[uint64]map[uint64]*list.Element),
		lruList:  list.New(),
	}
}

// Get checks if the file (dev, ino) is in the clean cache, updating its LRU position.
func (c *FileCache) Get(dev, ino uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	innerMap, ok := c.items[dev]
	if ok {
		if elem, exists := innerMap[ino]; exists {
			c.lruList.MoveToFront(elem)
			c.hits++
			return true
		}
	}
	c.misses++
	return false
}

// Stats returns the total cache hits and misses.
func (c *FileCache) Stats() (uint64, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

// Len returns the current number of cached entries.
func (c *FileCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lruList.Len()
}

// Add adds or updates a file (dev, ino) as clean in the cache, evicting LRU entries if full.
func (c *FileCache) Add(dev, ino uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	innerMap, ok := c.items[dev]
	if !ok {
		innerMap = make(map[uint64]*list.Element)
		c.items[dev] = innerMap
	}

	if elem, exists := innerMap[ino]; exists {
		c.lruList.MoveToFront(elem)
		return
	}

	// Evict oldest entry if at capacity
	if c.lruList.Len() >= c.capacity {
		c.evictOldest()
	}

	elem := c.lruList.PushFront(cacheEntry{dev: dev, ino: ino})
	// Re-fetch innerMap in case it was deleted during evictOldest
	innerMap, ok = c.items[dev]
	if !ok {
		innerMap = make(map[uint64]*list.Element)
		c.items[dev] = innerMap
	}
	innerMap[ino] = elem
}

// evictOldest removes the least recently used element from the cache. Caller must hold c.mu.
func (c *FileCache) evictOldest() {
	backElem := c.lruList.Back()
	if backElem == nil {
		return
	}
	c.lruList.Remove(backElem)
	oldEntry := backElem.Value.(cacheEntry)

	if innerMap, ok := c.items[oldEntry.dev]; ok {
		delete(innerMap, oldEntry.ino)
		if len(innerMap) == 0 {
			delete(c.items, oldEntry.dev)
		}
	}
}

// Invalidate removes a specific file (dev, ino) from the cache.
func (c *FileCache) Invalidate(dev, ino uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	innerMap, ok := c.items[dev]
	if ok {
		if elem, exists := innerMap[ino]; exists {
			c.lruList.Remove(elem)
			delete(innerMap, ino)
			if len(innerMap) == 0 {
				delete(c.items, dev)
			}
		}
	}
}

// PurgeMount purges all cache entries belonging to a detached device ID.
func (c *FileCache) PurgeMount(dev uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	innerMap, ok := c.items[dev]
	if !ok {
		return
	}

	for _, elem := range innerMap {
		c.lruList.Remove(elem)
	}
	delete(c.items, dev)
}

const STATX_MNT_ID_UNIQUE = 0x00004000

// MountTracker tracks mount_id to dev_t mappings parsed from /proc/self/mountinfo.
type MountTracker struct {
	mu          sync.RWMutex
	mounts      map[uint64]uint64 // mount_id -> dev_t
	mountPoints map[uint64]string // mount_id -> mount_point
}

func NewMountTracker() *MountTracker {
	return &MountTracker{
		mounts:      make(map[uint64]uint64),
		mountPoints: make(map[uint64]string),
	}
}

func (mt *MountTracker) UpdateFromMountinfo() error {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		// 1st field: mount ID
		mountID, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			continue
		}
		// 3rd field: major:minor
		devStr := parts[2]
		devParts := strings.Split(devStr, ":")
		if len(devParts) != 2 {
			continue
		}
		major, err1 := strconv.ParseUint(devParts[0], 10, 32)
		minor, err2 := strconv.ParseUint(devParts[1], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		dev := unix.Mkdev(uint32(major), uint32(minor))
		mountPoint := parts[4]

		mt.mounts[mountID] = dev
		mt.mountPoints[mountID] = mountPoint

		// Also query statx for 64-bit unique mount ID if possible
		var statx unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, mountPoint, 0, STATX_MNT_ID_UNIQUE, &statx); err == nil && statx.Mnt_id != 0 {
			mt.mounts[statx.Mnt_id] = dev
		}
	}
	return scanner.Err()
}

func (mt *MountTracker) ResolveAndRemove(mountID uint64) (uint64, bool) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	dev, ok := mt.mounts[mountID]
	if ok {
		delete(mt.mounts, mountID)
		delete(mt.mountPoints, mountID)
	}
	return dev, ok
}

func (mt *MountTracker) GetMountPoints() []string {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	pts := make([]string, 0, len(mt.mountPoints))
	for _, p := range mt.mountPoints {
		pts = append(pts, p)
	}
	return pts
}
