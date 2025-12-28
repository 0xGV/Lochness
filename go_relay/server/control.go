package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
)

type ControlServer struct {
	Storage *Storage
	// We need a way to send commands to C++.
	// "Implement Control Pipe Client (Sender)"
	// The C++ agent will listen on \\.\pipe\etw_control
	PipePath string
	mu       sync.Mutex
	Enabled  map[string]bool
}

func NewControlServer(storage *Storage, pipePath string) *ControlServer {
	return &ControlServer{
		Storage:  storage,
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
	rawProviders := []map[string]string{
		{"name": "Microsoft-Windows-Kernel-Process", "guid": "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"},
		{"name": "Microsoft-Windows-Kernel-Network", "guid": "7DD42A49-5329-4832-8DFD-43D979153A88"},
		{"name": "Microsoft-Windows-DNS-Client", "guid": "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D"},
		{"name": "Microsoft-Windows-Security-Auditing", "guid": "54849625-5478-4994-A5BA-3E3B032834A0"},
		{"name": "Microsoft-Windows-LSA-Proxy", "guid": "70321793-C371-4FC1-A3C0-D770D63973E2"},
		{"name": "Microsoft-Windows-Winlogon", "guid": "DBE9B383-7CF3-4331-91CC-6393B8A3B097"},
		{"name": "Microsoft-Windows-Kernel-File", "guid": "EDD08927-9CC4-4E65-B970-C2560FB5C289"},
		{"name": "Microsoft-Windows-Kernel-Registry", "guid": "70EB4F03-C1DE-4F73-A051-33D13D5413BD"},
		{"name": "Microsoft-Windows-Threat-Intelligence", "guid": "F4E1897C-BB5D-5668-F1D8-040F4D8DD344"},
		{"name": "Microsoft-Windows-Kernel-EventTracing", "guid": "B675EC37-BDB6-4648-BC92-F3FDC74D3CA2"},
		{"name": "Microsoft-Antimalware-AMFilter", "guid": "CFEB0608-330E-4410-B00D-56D8DA9986E6"},
		{"name": "Microsoft-Antimalware-Engine", "guid": "0A002690-3839-4E3A-B3B6-96D8DF868D99"},
		{"name": "Microsoft-Antimalware-Engine-Instrumentation", "guid": "68621C25-DF8D-4A6B-AABC-19A22E296A7C"},
		{"name": "Microsoft-Antimalware-NIS", "guid": "102AAB0A-9D9C-4887-A860-55DE33B96595"},
		{"name": "Microsoft-Antimalware-Protection", "guid": "E4B70372-261F-4C54-8FA6-A5A7914D73DA"},
		{"name": "Microsoft-Antimalware-RTP", "guid": "8E92DEEF-5E17-413B-B927-59B2F06A3CFC"},
		{"name": "Microsoft-Antimalware-Scan-Interface", "guid": "2A576B87-09A7-520E-C21A-4942F0271D67"},
		{"name": "Microsoft-Antimalware-Service", "guid": "751EF305-6C6E-4FED-B847-02EF79D26AEF"},
		{"name": "Microsoft-Antimalware-UacScan", "guid": "D37E7910-79C8-57C4-DA77-52BB646364CD"},
		{"name": "Microsoft-Windows-PowerShell", "guid": "A0C1853B-5C40-4B15-8766-3CF1C58F985A"},
		{"name": "Microsoft-Windows-ProcessStateManager", "guid": "D49918CF-9489-4BF1-9D7B-014D864CF71F"},
		{"name": "Microsoft-Windows-RemoteApp and Desktop Connections", "guid": "1B8B402D-78DC-46FB-BF71-46E64AEDF165"},
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	type ProviderInfo struct {
		Name    string `json:"name"`
		Guid    string `json:"guid"`
		Enabled bool   `json:"enabled"`
	}

	providers := make([]ProviderInfo, len(rawProviders))
	for i, rp := range rawProviders {
		providers[i] = ProviderInfo{
			Name:    rp["name"],
			Guid:    rp["guid"],
			Enabled: cs.Enabled[rp["guid"]],
		}
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
