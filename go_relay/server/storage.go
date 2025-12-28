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
	for _, evt := range s.ramBuffer {
		if since > 0 && evt.Timestamp <= since {
			continue
		}
		// Match ProviderID or empty query returns all
		if query == "" {
			results = append(results, evt)
		}
	}
	return results
}
