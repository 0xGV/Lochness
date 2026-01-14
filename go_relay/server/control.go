package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings" // Added for path splitting
	"sync"
	"time"
)

type ControlServer struct {
	Storage         *Storage
	Resolver        *ProviderResolver
	PipePath        string
	Groups          map[string][]string
	GroupConfigPath string
	mu              sync.Mutex
	Enabled         map[string]bool
	pipeMutex       sync.Mutex
}

func NewControlServer(storage *Storage, resolver *ProviderResolver, pipePath string, groupConfigPath string) *ControlServer {
	cs := &ControlServer{
		Storage:         storage,
		Resolver:        resolver,
		PipePath:        pipePath,
		Enabled:         make(map[string]bool),
		Groups:          make(map[string][]string),
		GroupConfigPath: groupConfigPath,
	}
	cs.LoadGroups()
	return cs
}

type ProviderConfig struct {
	Action   string `json:"action"`   // "Enable" or "Disable"
	Provider string `json:"provider"` // GUID string
}

// sendCommand handles opening the pipe, writing the request, and reading the response.
// responseDst can be a pointer to a struct/slice to unmarshal JSON into, or nil to just return raw string if needed,
// but for now we'll assume we return raw bytes so the caller can decide.
func (cs *ControlServer) sendCommand(req interface{}) ([]byte, error) {
	cs.pipeMutex.Lock()
	defer cs.pipeMutex.Unlock()

	f, err := os.OpenFile(cs.PipePath, os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open control pipe: %v", err)
	}
	defer f.Close()

	bytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	if _, err := f.Write(bytes); err != nil {
		return nil, fmt.Errorf("failed to write to pipe: %v", err)
	}

	// Read Response
	// We need to read enough. The C++ agent uses a 4KB buffer for reading commands,
	// but for writing metadata responses it could be large.
	// We should read until EOF or a reasonable limit.
	// Since it's a pipe, and C++ writes and then closes (or disconnects), we can readall.

	respBuf, err := io.ReadAll(f)
	if err != nil {
		// On Windows, a pipe disconnect (which C++ does) often returns "No process is on the other end of the pipe" (ERROR_BROKEN_PIPE).
		// If we got some data, we should consider it a success/EOF.
		if len(respBuf) > 0 {
			// Check for specific error message or type if we want to be pedantic,
			// but relying on "got data" + "error" is a reasonable heuristic for this pipe pattern.
			// Specifically, syscall.Errno 109 is ERROR_BROKEN_PIPE.
			return respBuf, nil
		}
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return respBuf, nil
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

	resp, err := cs.sendCommand(config)
	if err != nil {
		log.Printf("Control Error: %v", err)
		http.Error(w, err.Error(), 503)
		return
	}

	if len(resp) > 0 {
		cs.mu.Lock()
		if config.Action == "Enable" {
			cs.Enabled[config.Provider] = true
		} else {
			delete(cs.Enabled, config.Provider)
		}
		cs.mu.Unlock()
	}

	w.WriteHeader(200)
	w.Write(resp)
}

type SearchResponse struct {
	Events []Event `json:"events"`
	Total  int     `json:"total"`
	Page   int     `json:"page"`
	Size   int     `json:"size"`
}

func (cs *ControlServer) HandleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	sinceStr := r.URL.Query().Get("since")
	pageStr := r.URL.Query().Get("page")
	sizeStr := r.URL.Query().Get("size")
	filtersStr := r.URL.Query().Get("filters")

	var since uint64
	if sinceStr != "" {
		fmt.Sscanf(sinceStr, "%d", &since)
	}

	page := 1
	if pageStr != "" {
		fmt.Sscanf(pageStr, "%d", &page)
	}

	size := 500
	if sizeStr != "" {
		fmt.Sscanf(sizeStr, "%d", &size)
	}

	var filters []Filter
	if filtersStr != "" {
		json.Unmarshal([]byte(filtersStr), &filters)
	}

	events, total := cs.Storage.Search(query, filters, since, page, size)

	resp := SearchResponse{
		Events: events,
		Total:  total,
		Page:   page,
		Size:   size,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

// GET /api/providers/{guid}/events
func (cs *ControlServer) HandleGetEvents(w http.ResponseWriter, r *http.Request) {
	// Parse GUID from URL Path
	// Path expected: /api/providers/{guid}/events
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path", 400)
		return
	}
	guid := parts[3] // [ "", "api", "providers", "{guid}", "events"] ??
	// parts: ["", "api", "providers", "GUID", "events"] -> index 3 is GUID.

	name := r.URL.Query().Get("name")

	cmd := map[string]interface{}{
		"Action":   "GetMetadata",
		"Provider": guid,
		"Name":     name,
	}

	resp, err := cs.sendCommand(cmd)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

type FilterRequest struct {
	EventIds []int `json:"event_ids"`
}

// POST /api/providers/{guid}/filters
func (cs *ControlServer) HandleSetFilters(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid path", 400)
		return
	}
	guid := parts[3]

	var req FilterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}

	cmd := map[string]interface{}{
		"Action":   "SetFilter",
		"Provider": guid,
		"EventIds": req.EventIds,
	}

	resp, err := cs.sendCommand(cmd)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	w.WriteHeader(200)
	w.Write(resp)
}

func (cs *ControlServer) LoadGroups() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	data, err := os.ReadFile(cs.GroupConfigPath)
	if err != nil {
		return // Ignore error, file might not exist
	}
	json.Unmarshal(data, &cs.Groups)
}

func (cs *ControlServer) SaveGroups() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	data, err := json.MarshalIndent(cs.Groups, "", "  ")
	if err == nil {
		os.WriteFile(cs.GroupConfigPath, data, 0644)
	}
}

func (cs *ControlServer) HandleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		cs.mu.Lock()
		defer cs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cs.Groups)
		return
	}

	if r.Method == "POST" {
		var req struct {
			Name  string   `json:"name"`
			Guids []string `json:"guids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}
		if req.Name == "" {
			http.Error(w, "Name required", 400)
			return
		}

		cs.mu.Lock()
		cs.Groups[req.Name] = req.Guids
		cs.mu.Unlock() // Unlock save uses lock
		cs.SaveGroups()

		w.WriteHeader(200)
		return
	}

	if r.Method == "DELETE" {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "Name required", 400)
			return
		}
		cs.mu.Lock()
		delete(cs.Groups, name)
		cs.mu.Unlock()
		cs.SaveGroups()
		w.WriteHeader(200)
		return
	}

	http.Error(w, "Method not allowed", 405)
}

func (cs *ControlServer) HandleGroupToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Name   string `json:"name"`
		Enable bool   `json:"enable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}

	cs.mu.Lock()
	guids, ok := cs.Groups[req.Name]
	cs.mu.Unlock()

	if !ok {
		http.Error(w, "Group not found", 404)
		return
	}

	action := "Disable"
	if req.Enable {
		action = "Enable"
	}

	for _, guid := range guids {
		cleanGuid := strings.ToUpper(strings.Trim(guid, "{}"))
		// Ensure braces for provider logic if needed, but resolved usually expects braces?
		// My sendCommand usually takes just GUID string.
		// Existing toggle logic in index.html sends Clean GUID (no braces).
		// Existing HandleConfig takes Provider string.
		// However, C++ side might expect braces.
		// Let's look at `LoadProviders`. They are stored with braces in `ProviderInfo` but clean in map.
		// `HandleConfig` receives whatever.
		// `NewProviderResolver` stores clean GUIDs.
		// I will ensure braces are STRIPPED for consistency if backend expects clean, OR ADDED if C++ expects them.
		// `HandleConfig` calls `sendCommand`.
		// `sendCommand` sends JSON.
		// The C++ agent parses GUID.
		// Usually Windows GUID parsing handles braces or not.
		// I'll stick to what `toggleProv` did in JS: `cleanGuid`.

		if !strings.HasPrefix(cleanGuid, "{") {
			// actually `toggleProv` sends CLEAN guid.
			// so I will send clean guid.
		}

		cmd := map[string]interface{}{
			"Action":   action,
			"Provider": cleanGuid,
		}

		if _, err := cs.sendCommand(cmd); err == nil {
			cs.mu.Lock()
			if req.Enable {
				cs.Enabled[cleanGuid] = true
			} else {
				delete(cs.Enabled, cleanGuid)
			}
			cs.mu.Unlock()
		} else {
			log.Printf("Failed to %s provider %s: %v", action, guid, err)
		}
	}

	w.WriteHeader(200)
}

// POST /api/inspect
func (cs *ControlServer) HandleInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// Read raw body to pass through to C++
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}
	defer r.Body.Close()

	// Parse to validate/extract if needed, but for now just pass through the raw JSON object
	// The C++ agent expects {"Action":"...", "Pid":...}
	// Verify it's valid JSON at least
	var js map[string]interface{}
	if err := json.Unmarshal(body, &js); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	// Pass to sendCommand which marshals it again.
	// Optimize: sendCommand takes interface{}, so we pass the map.
	resp, err := cs.sendCommand(js)
	if err != nil {
		log.Printf("Inspect Error: %v", err)
		http.Error(w, err.Error(), 503)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// HydrateAllMetadata fetches metadata for all known providers from the C++ agent.
// This should be run in a background goroutine.
func (cs *ControlServer) HydrateAllMetadata() {
	log.Println("Starting background metadata hydration...")

	// 1. Wait for Control Pipe to be available (Agent started)
	// Timeout after 30 seconds
	ready := false
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(cs.PipePath); err == nil {
			ready = true
			break
		}
		// Also try opening just in case Stat behaves weird on pipes (it usually works for existence)
		// But simpler to just wait.
		time.Sleep(1 * time.Second)
	}

	if !ready {
		log.Printf("Hydration Aborted: Control pipe %s not found after waiting. Is the Agent running?", cs.PipePath)
		return
	}

	providers := cs.Resolver.GetAll()

	for _, p := range providers {
		// Construct GetMetadata command
		guid := p.GUID
		// Ensure braces if missing (though GetAll adds them)
		if !strings.HasPrefix(guid, "{") {
			guid = "{" + guid + "}"
		}

		cmd := map[string]interface{}{
			"Action":   "GetMetadata",
			"Provider": guid,
			"Name":     p.Name, // Send Name for better resolution
		}

		// Send Command
		// We might still fail if agent crashes or disconnects, so slight retry or just ignore error
		resp, err := cs.sendCommand(cmd)
		if err != nil {
			log.Printf("Failed to hydrate metadata for %s: %v", p.Name, err)
			continue
		}

		// Parse Response (JSON Array of Events)
		var metadata []interface{}
		if err := json.Unmarshal(resp, &metadata); err != nil {
			log.Printf("Failed to parse metadata for %s: %v", p.Name, err)
			continue
		}

		// Update Resolver
		cs.Resolver.UpdateMetadata(p.GUID, metadata)
		log.Printf("Hydrated %d events for %s", len(metadata), p.Name)

		// Small sleep to avoid choking the pipe?
		time.Sleep(50 * time.Millisecond)
	}
	log.Println("Metadata hydration completed.")
}
