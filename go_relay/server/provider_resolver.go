package server

import (
	"encoding/json"
	"fmt"
	"log" // Added log for errors
	"os"
	"strings"
	"sync"
)

type ProviderInfo struct {
	Name    string `json:"name"`
	GUID    string `json:"guid"`
	Enabled bool   `json:"enabled"`
}

type ProviderResolver struct {
	mu        sync.RWMutex
	providers map[string]string // GUID -> Name
}

func NewProviderResolver(configPath string) *ProviderResolver {
	pr := &ProviderResolver{
		providers: make(map[string]string),
	}

	// Load from JSON
	content, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: Failed to read %s: %v", configPath, err)
		return pr
	}

	var list []ProviderInfo
	if err := json.Unmarshal(content, &list); err != nil {
		log.Printf("Warning: Failed to parse %s: %v", configPath, err)
		return pr
	}

	for _, p := range list {
		guid := strings.ToUpper(strings.Trim(p.GUID, "{}"))
		pr.providers[guid] = p.Name
	}

	return pr
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
		list = append(list, ProviderInfo{
			Name: name,
			GUID: "{" + guid + "}",
		})
	}
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
