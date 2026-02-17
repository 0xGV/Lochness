package server

import (
	"encoding/json"
	"fmt"
	"log" // Added log for errors
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type ProviderInfo struct {
	Name     string      `json:"name"`
	GUID     string      `json:"guid"`
	Enabled  bool        `json:"enabled"`
	Metadata interface{} `json:"metadata,omitempty"`
}

type ProviderResolver struct {
	mu            sync.RWMutex
	providers     map[string]string      // GUID -> Name
	metadataCache map[string]interface{} // GUID -> Metadata (New)
}

func NewProviderResolver(configFilename string) *ProviderResolver {
	pr := &ProviderResolver{
		providers:     make(map[string]string),
		metadataCache: make(map[string]interface{}),
	}
	// ... (rest of NewProviderResolver logic is same but need to preserve it. Wait, replace_file_content replaces chunks. I should replace struct def and NewProviderResolver init lines)

	// Search paths:
	// 1. Current directory
	// 2. ./go_relay/ (if running from root)
	// 3. ../go_relay/ (if running from bin?)
	paths := []string{
		configFilename,
		filepath.Join(".", "go_relay", configFilename),
		filepath.Join("..", "go_relay", configFilename),
	}

	var content []byte
	var loadedPath string
	var err error

	for _, p := range paths {
		content, err = os.ReadFile(p)
		if err == nil {
			loadedPath = p
			break
		}
	}

	if loadedPath == "" {
		log.Printf("Error: Could not find %s in any of the search paths: %v", configFilename, paths)
		return pr
	}

	log.Printf("Loading providers configuration from: %s", loadedPath)

	var list []ProviderInfo
	if err := json.Unmarshal(content, &list); err != nil {
		log.Printf("Error: Failed to parse %s: %v", loadedPath, err)
		return pr
	}

	for _, p := range list {
		guid := strings.ToUpper(strings.Trim(p.GUID, "{}"))
		pr.providers[guid] = p.Name
		log.Printf("Loaded Provider: %s (%s)", p.Name, guid)
	}
	log.Printf("Total Providers Loaded: %d", len(pr.providers))

	return pr
}

func (pr *ProviderResolver) UpdateMetadata(guid string, metadata interface{}) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	cleanGUID := strings.ToUpper(strings.Trim(guid, "{}"))
	pr.metadataCache[cleanGUID] = metadata
}

func (pr *ProviderResolver) GetName(guid string) string {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	// Normalize GUID for lookup
	cleanGUID := strings.ToUpper(strings.Trim(guid, "{} "))
	if name, ok := pr.providers[cleanGUID]; ok {
		return name
	}
	return ""
}

func (pr *ProviderResolver) GetAll() []ProviderInfo {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	list := make([]ProviderInfo, 0, len(pr.providers))
	for guid, name := range pr.providers {
		info := ProviderInfo{
			Name: name,
			GUID: "{" + guid + "}",
		}
		if meta, ok := pr.metadataCache[guid]; ok {
			info.Metadata = meta
		}
		list = append(list, info)
	}

	// Sort by Name for stable UI ordering
	sort.Slice(list, func(i, j int) bool {
		return list[i].Name < list[j].Name
	})

	return list
}

func GUIDFromBytes(b [16]byte) string {
	// GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
	// First 3 parts are Little Endian in the byte array, last 2 are Big Endian (as stored in bytes, usually).
	// Actually, standard GUID byte representation in Windows:
	// Data1 (4 bytes), Data2 (2 bytes), Data3 (2 bytes) are little-endian.
	// Data4 (8 bytes) is big-endian / array of bytes.
	// We need to format them carefully.
	return fmt.Sprintf("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}
