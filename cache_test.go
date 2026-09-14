package main

import (
	"runtime"
	"sync"
	"testing"
)

func TestFileCacheBasic(t *testing.T) {
	c := NewBoundedFileCache(10)

	// Initially empty
	if c.Get(1, 100) {
		t.Fatalf("expected miss on empty cache")
	}

	// Add entry
	c.Add(1, 100)
	if !c.Get(1, 100) {
		t.Fatalf("expected hit for added entry")
	}

	// Invalidate entry
	c.Invalidate(1, 100)
	if c.Get(1, 100) {
		t.Fatalf("expected miss after invalidation")
	}

	hits, misses := c.Stats()
	if hits != 1 || misses != 2 {
		t.Fatalf("unexpected stats: hits=%d, misses=%d", hits, misses)
	}
}

func TestFileCacheLRUEviction(t *testing.T) {
	// Capacity = 3
	c := NewBoundedFileCache(3)

	c.Add(1, 10) // LRU oldest
	c.Add(1, 20)
	c.Add(1, 30)

	if c.Len() != 3 {
		t.Fatalf("expected len 3, got %d", c.Len())
	}

	// Access key (1, 10) to move it to MRU
	if !c.Get(1, 10) {
		t.Fatalf("expected hit for (1, 10)")
	}

	// Add 4th item (1, 40) -> should evict (1, 20)
	c.Add(1, 40)

	if c.Len() != 3 {
		t.Fatalf("expected len 3, got %d", c.Len())
	}

	if c.Get(1, 20) {
		t.Fatalf("expected (1, 20) to have been evicted")
	}

	if !c.Get(1, 10) || !c.Get(1, 30) || !c.Get(1, 40) {
		t.Fatalf("expected (1, 10), (1, 30), and (1, 40) to be present")
	}
}

func TestFileCachePurgeMount(t *testing.T) {
	c := NewBoundedFileCache(10)

	// Add items on device 1 and device 2
	c.Add(1, 10)
	c.Add(1, 20)
	c.Add(2, 30)
	c.Add(2, 40)

	if c.Len() != 4 {
		t.Fatalf("expected len 4, got %d", c.Len())
	}

	// Purge device 1
	c.PurgeMount(1)

	if c.Len() != 2 {
		t.Fatalf("expected len 2 after purge, got %d", c.Len())
	}

	if c.Get(1, 10) || c.Get(1, 20) {
		t.Fatalf("expected dev 1 items to be purged")
	}

	if !c.Get(2, 30) || !c.Get(2, 40) {
		t.Fatalf("expected dev 2 items to remain")
	}
}

func TestFileCacheConcurrency(t *testing.T) {
	c := NewBoundedFileCache(100)
	var wg sync.WaitGroup

	// Concurrently add and get items
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				dev := uint64(workerID % 3)
				ino := uint64(j)
				c.Add(dev, ino)
				_ = c.Get(dev, ino)
				if j%10 == 0 {
					c.Invalidate(dev, ino)
				}
				if j == 50 && workerID == 0 {
					c.PurgeMount(dev)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestMountTracker(t *testing.T) {
	mt := NewMountTracker()
	err := mt.UpdateFromMountinfo()
	if err != nil {
		t.Fatalf("UpdateFromMountinfo failed: %v", err)
	}

	mt.mu.RLock()
	count := len(mt.mounts)
	mt.mu.RUnlock()

	if count == 0 {
		t.Fatalf("expected mountinfo to have mounts, got 0")
	}

	// Test ResolveAndRemove
	var sampleMountID uint64
	mt.mu.RLock()
	for mntID := range mt.mounts {
		sampleMountID = mntID
		break
	}
	mt.mu.RUnlock()

	dev, ok := mt.ResolveAndRemove(sampleMountID)
	if !ok {
		t.Fatalf("expected ResolveAndRemove to succeed for mount %d", sampleMountID)
	}
	if dev == 0 {
		t.Logf("Note: mount %d resolved to dev %d", sampleMountID, dev)
	}

	// Second resolve should fail
	_, ok = mt.ResolveAndRemove(sampleMountID)
	if ok {
		t.Fatalf("expected second ResolveAndRemove to return false")
	}
}

func TestCacheMemoryFootprint(t *testing.T) {
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	const capacity = 200000
	c := NewBoundedFileCache(capacity)
	for i := uint64(0); i < capacity; i++ {
		c.Add(1, i)
	}

	runtime.ReadMemStats(&m2)
	allocBytes := m2.Alloc - m1.Alloc
	mb := float64(allocBytes) / (1024 * 1024)
	bytesPerEntry := float64(allocBytes) / capacity
	t.Logf("200,000 entries occupied: %.2f MB (%.1f bytes per entry)", mb, bytesPerEntry)
}
