package main

import (
	"log"
	"net/http"
	"os"
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
	control := server.NewControlServer(store, resolver, controlPipePath)

	// 4. Setup HTTP API
	http.HandleFunc("/events/search", control.HandleSearch)
	http.HandleFunc("/config/providers", control.HandleConfig)
	http.HandleFunc("/api/providers", control.HandleListProviders)
	http.HandleFunc("/events/flush", control.HandleFlush)

	// 5. Serve Static UI
	// Try to find the ui directory in common locations
	uiDir := "./ui"
	if _, err := os.Stat(uiDir); os.IsNotExist(err) {
		uiDir = "./go_relay/ui"
	}

	fs := http.FileServer(http.Dir(uiDir))
	http.Handle("/ui/", http.StripPrefix("/ui/", fs))

	log.Println("Starting HTTP API on :8087")
	log.Fatal(http.ListenAndServe(":8087", nil))
}
