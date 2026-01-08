package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Timestamp    uint64   `json:"timestamp"`
	ProviderId   [16]byte `json:"provider_id"`
	ProviderName string   `json:"provider_name"`
	EventId      uint16   `json:"event_id"`
	Data         []byte   `json:"data"` // Base64 in JSON by default
}

type StorageConfig struct {
	MaxRAMBytes   int64
	MaxAge        time.Duration
	CacheDir      string
	DiskChunkSize int
}

type Storage struct {
	mu        sync.RWMutex
	ramBuffer []Event
	ramUsage  int64
	config    StorageConfig

	// Start time of the buffer to efficiently prune
	// For ring buffer, we might just append and slice.
	// Since we need to keep 30m of data, a simple slice with `copy` on prune is easier than a fixed circular buffer
	// because complexity of variable sized payloads.
	// We will use a slice and compact it occasionally.
}

func NewStorage(config StorageConfig) *Storage {
	if config.CacheDir != "" {
		os.MkdirAll(config.CacheDir, 0755)
	}
	return &Storage{
		ramBuffer: make([]Event, 0, 10000),
		config:    config,
	}
}

func (s *Storage) Add(evt Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	evtSize := int64(len(evt.Data) + 30) // approx

	// Check RAM limit
	if s.ramUsage+evtSize > s.config.MaxRAMBytes {
		// Spill to disk or drop?
		// Requirement: "if that threshold is reached, the data should be cached locally... and pruned if not called for... 30 minutes"
		// This implies moving OLDEST data to disk or moving NEW data to disk?
		// Usually spillover means move oldest RAM to disk to make space for new RAM.
		// For simplicity, we will flush the ENTIRE current RAM buffer to a disk chunk if we hit the limit,
		// or at least a large chunk of it.
		s.flushToDisk()
	}

	s.ramBuffer = append(s.ramBuffer, evt)
	s.ramUsage += evtSize
}

func (s *Storage) flushToDisk() {
	// Simple implementation: Write current RAM buffer to a file named by timestamp
	if len(s.ramBuffer) == 0 {
		return
	}

	filename := fmt.Sprintf("chunk_%d.json", time.Now().UnixNano())
	path := filepath.Join(s.config.CacheDir, filename)

	file, err := os.Create(path)
	if err == nil {
		enc := json.NewEncoder(file)
		if err := enc.Encode(s.ramBuffer); err == nil {
			// Successfully saved
		} else {
			fmt.Printf("Error encoding chunk: %v\n", err)
		}
		file.Close()
	} else {
		fmt.Printf("Error creating chunk: %v\n", err)
	}

	// clear RAM
	s.ramBuffer = make([]Event, 0, 10000)
	s.ramUsage = 0
}

func (s *Storage) PruneLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.prune()
	}
}

func (s *Storage) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ETW timestamp is usually QPC or SystemTime (FileTime).
	// Assuming Producer sends SystemTime (FileTime).
	// FileTime is 100ns intervals since Jan 1 1601.
	// Go time.Now() -> FileTime conversion needed.
	// UnixNano is since 1970.
	// 1970 - 1601 = 369 years.
	// Magic offset: 116444736000000000 (100ns units).

	nowFileTime := uint64(time.Now().UnixNano()/100) + 116444736000000000
	cutoffFileTime := nowFileTime - uint64(s.config.MaxAge.Nanoseconds()/100)

	// Prune RAM
	// Since events are appended in order, we can find split index.
	// Actually, binary search is better, but linear scan is fine for "front" of slice.
	idx := 0
	for i, evt := range s.ramBuffer {
		if evt.Timestamp >= cutoffFileTime {
			idx = i
			break
		}
	}

	if idx > 0 {
		// Drop elements before idx
		// Calculate size dropped
		var droppedSize int64
		for i := 0; i < idx; i++ {
			droppedSize += int64(len(s.ramBuffer[i].Data) + 30)
		}

		copy(s.ramBuffer, s.ramBuffer[idx:])
		s.ramBuffer = s.ramBuffer[:len(s.ramBuffer)-idx]
		s.ramUsage -= droppedSize
	}

	// Prune Disk
	// Walk directory, parse filename timestamp or check file mod time
	files, err := os.ReadDir(s.config.CacheDir)
	if err == nil {
		for _, f := range files {
			info, err := f.Info()
			if err == nil {
				if time.Since(info.ModTime()) > s.config.MaxAge {
					os.Remove(filepath.Join(s.config.CacheDir, f.Name()))
				}
			}
		}
	}
}

func (s *Storage) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Clear RAM
	s.ramBuffer = make([]Event, 0, 10000)
	s.ramUsage = 0

	// 2. Clear Disk
	files, err := os.ReadDir(s.config.CacheDir)
	if err == nil {
		for _, f := range files {
			os.Remove(filepath.Join(s.config.CacheDir, f.Name()))
		}
	}
}

func (s *Storage) Search(query string, since uint64) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := []Event{}
	// Case-insensitive flexible match
	// We could parse specific fields (e.g. "provider:foo") but for now
	// we will do a simple "contains" on specific fields.

	for _, evt := range s.ramBuffer {
		if since > 0 && evt.Timestamp <= since {
			continue
		}

		if query == "" {
			results = append(results, evt)
			continue
		}

		// Check Provider Name
		if containsIgnoreCase(evt.ProviderName, query) {
			results = append(results, evt)
			continue
		}

		// Check EventID
		if fmt.Sprintf("%d", evt.EventId) == query {
			results = append(results, evt)
			continue
		}

		// Check Data (Payload) - assuming simple string search on raw bytes
		// This might be expensive for large buffers, but acceptable for RAM implementation.
		if containsIgnoreCase(string(evt.Data), query) {
			results = append(results, evt)
			continue
		}
	}
	return results
}

func containsIgnoreCase(s, substr string) bool {
	// Simple localized check or just use strings.Contains with ToLower
	// For efficiency we might want to avoid ToLower allocs in tight loop,
	// but for this MVP standard strings package is fine.
	// Note: We need to import "strings" package if not already imported.
	// Checking imports... "strings" is NOT imported in storage.go currently.
	// I will add the helper here but I also need to update imports.

	// actually, let's just do a naive implementation or rely on user adding import?
	// The tool requires the code to compile. I should check imports.
	// I'll make this function self-contained or use a helper that does byte comparison if I want to avoid allocating.
	// But `strings` is standard. I'll just rely on the tool to let me add imports or I will add it now.
	// Wait, `bytes.Contains` might be better for Data.

	// Let's use a simple helper here.
	sLen := len(s)
	subLen := len(substr)
	if subLen > sLen {
		return false
	}
	if subLen == 0 {
		return true
	}

	// Naive case insensitive search
	for i := 0; i <= sLen-subLen; i++ {
		match := true
		for j := 0; j < subLen; j++ {
			c1 := s[i+j]
			c2 := substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 'a' - 'A'
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 'a' - 'A'
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
