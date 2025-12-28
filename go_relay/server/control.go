package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type ControlServer struct {
	Storage  *Storage
	Resolver *ProviderResolver
	// We need a way to send commands to C++.
	// "Implement Control Pipe Client (Sender)"
	// The C++ agent will listen on \\.\pipe\etw_control
	PipePath string
	mu       sync.Mutex
	Enabled  map[string]bool
}

func NewControlServer(storage *Storage, resolver *ProviderResolver, pipePath string) *ControlServer {
	return &ControlServer{
		Storage:  storage,
		Resolver: resolver,
		PipePath: pipePath,
		Enabled:  make(map[string]bool),
	}
}

type ProviderConfig struct {
	Action   string `json:"action"`   // "Enable" or "Disable"
	Provider string `json:"provider"` // GUID string
}

func (cs *ControlServer) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var config ProviderConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	// Send to C++ Agent
	// We open the pipe, write, close. (Or keep open).
	// Simple command mode: Open, Write, Close.

	f, err := os.OpenFile(cs.PipePath, os.O_RDWR, 0600) // This only works if C++ created it.
	// Go's os.OpenFile might not work for Named Pipes seamlessly without special flags on Windows?
	// Actually it works if the pipe exists.

	if err != nil {
		// If pipe not found, maybe C++ isn't running.
		// Try syscall if os.OpenFile fails? os.OpenFile usually works for \\.\pipe\.
		log.Printf("Failed to open control pipe: %v", err)
		http.Error(w, fmt.Sprintf("Agent unavailable: %v", err), 503)
		return
	}
	defer f.Close()

	// Write JSON command
	bytes, _ := json.Marshal(config)
	f.Write(bytes)

	// Read Response
	respBuf := make([]byte, 1024)
	n, err := f.Read(respBuf)
	if err != nil {
		log.Printf("Failed to read ack: %v", err)
		http.Error(w, "Command sent but no ack received", 502)
		return
	}

	if n > 0 { // Assume success if we got an ack
		cs.mu.Lock()
		if config.Action == "Enable" {
			cs.Enabled[config.Provider] = true
		} else {
			delete(cs.Enabled, config.Provider)
		}
		cs.mu.Unlock()
	}

	w.WriteHeader(200)
	w.Write(respBuf[:n])
}

func (cs *ControlServer) HandleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	sinceStr := r.URL.Query().Get("since")
	var since uint64
	if sinceStr != "" {
		fmt.Sscanf(sinceStr, "%d", &since)
	}

	events := cs.Storage.Search(query, since)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (cs *ControlServer) HandleListProviders(w http.ResponseWriter, r *http.Request) {
	providers := cs.Resolver.GetAll()
	// Update enabled status
	for i := range providers {
		providers[i].Enabled = cs.Enabled[strings.Trim(providers[i].GUID, "{}")]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(providers)
}
func (cs *ControlServer) HandleFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	cs.Storage.Flush()
	w.WriteHeader(200)
	w.Write([]byte("Cache flushed successfully"))
}
