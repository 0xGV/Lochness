package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"lochness/server"
)

func main() {
	log.Println("Starting Lochness Relay & Cache...")

	// 1. Initialize Storage
	config := server.StorageConfig{
		MaxRAMBytes: 100 * 1024 * 1024, // 100MB RAM limit for testing (1GB req)
		MaxAge:      30 * time.Minute,
		CacheDir:    "./cache",
	}
	store := server.NewStorage(config)
	go store.PruneLoop()

	// 2. Initialize Provider Resolver
	resolver := server.NewProviderResolver("providers.json")

	// 3. Start Pipe Ingestor Server
	// This listens for the C++ Producer to connect and send data.
	pipePath := `\\.\pipe\etw_stream`
	ingestor := server.NewPipeServer(pipePath, store, resolver)
	ingestor.Start()
	log.Printf("Listening on Named Pipe: %s", pipePath)

	// 3. Initialize Control Server
	// This talks to C++ Control Listener
	controlPipePath := `\\.\pipe\etw_control`
	control := server.NewControlServer(store, resolver, controlPipePath, "groups.json")

	// Start metadata hydration in background
	// Give C++ agent a moment to connect if we just started
	go func() {
		time.Sleep(2 * time.Second)
		control.HydrateAllMetadata()
	}()

	// 4. Setup HTTP API
	http.HandleFunc("/events/search", control.HandleSearch)
	http.HandleFunc("/config/providers", control.HandleConfig)
	http.HandleFunc("/api/providers", control.HandleListProviders)
	http.HandleFunc("/api/groups", control.HandleGroups)
	http.HandleFunc("/api/groups/toggle", control.HandleGroupToggle)
	http.HandleFunc("/api/inspect", control.HandleInspect)

	// Dynamic Handler for /api/providers/{guid}/...
	http.HandleFunc("/api/providers/", func(w http.ResponseWriter, r *http.Request) {
		// Precise path matching logic
		if r.URL.Path == "/api/providers" || r.URL.Path == "/api/providers/" {
			control.HandleListProviders(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/events") {
			control.HandleGetEvents(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/filters") {
			control.HandleSetFilters(w, r)
			return
		}
		http.NotFound(w, r)
	})

	http.HandleFunc("/events/flush", control.HandleFlush)

	// 5. Serve Static UI
	// Try to find the ui directory in common locations
	uiDir := "./ui"
	if _, err := os.Stat(uiDir); os.IsNotExist(err) {
		uiDir = "./go_relay/ui"
	}

	fs := http.FileServer(http.Dir(uiDir))
	http.Handle("/ui/", http.StripPrefix("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		}
		fs.ServeHTTP(w, r)
	})))

	log.Println("Starting HTTP API on :8087")
	log.Fatal(http.ListenAndServe(":8087", nil))
}
