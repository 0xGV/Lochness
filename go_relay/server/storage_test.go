package server

import (
	"testing"
	"time"
)

func TestStorage_Search(t *testing.T) {
	config := StorageConfig{
		MaxRAMBytes: 1024 * 1024,
		MaxAge:      10 * time.Minute,
		CacheDir:    "./test_cache",
	}
	s := NewStorage(config)

	// Add test events
	e1 := Event{
		Timestamp:    uint64(time.Now().UnixNano()),
		ProviderName: "Microsoft-Windows-Kernel",
		EventId:      100,
		Data:         []byte("Process Started"),
	}
	e2 := Event{
		Timestamp:    uint64(time.Now().UnixNano()),
		ProviderName: "Microsoft-Windows-Security",
		EventId:      4624,
		Data:         []byte("Logon Success User:Admin"),
	}
	e3 := Event{
		Timestamp:    uint64(time.Now().UnixNano()),
		ProviderName: "Microsoft-Windows-Kernel",
		EventId:      200,
		Data:         []byte("Process Terminated"),
	}

	s.Add(e1)
	s.Add(e2)
	s.Add(e3)

	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{"Empty Query", "", 3},
		{"Match Provider", "Security", 1},
		{"Match EventID", "100", 1},
		{"Match Data", "Terminated", 1},
		{"Case Insensitive", "logon", 1},
		{"No Match", "NonExistent", 0},
		{"Partial Provider", "Kernel", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, _ := s.Search(tt.query, 0, 1, 1000)
			if len(results) != tt.expected {
				t.Errorf("Search(%q) returned %d results, expected %d", tt.query, len(results), tt.expected)
			}
		})
	}
}
