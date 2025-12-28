package server

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
	"sync"
)

type ProviderInfo struct {
	Name string `json:"name"`
	GUID string `json:"guid"`
}

type ProviderResolver struct {
	mu        sync.RWMutex
	providers map[string]string // GUID -> Name
}

func NewProviderResolver() *ProviderResolver {
	pr := &ProviderResolver{
		providers: make(map[string]string),
	}
	pr.Refresh()
	return pr
}

func (pr *ProviderResolver) Refresh() error {
	cmd := exec.Command("logman", "query", "providers")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return err
	}

	newProviders := make(map[string]string)
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()

		// Expected format: "Name {GUID}"
		// Find last { and last }
		start := strings.LastIndex(line, "{")
		end := strings.LastIndex(line, "}")

		if start != -1 && end != -1 && end > start {
			guid := strings.ToUpper(line[start+1 : end])
			name := strings.TrimSpace(line[:start])
			if name != "" {
				newProviders[guid] = name
			}
		}
	}

	pr.mu.Lock()
	pr.providers = newProviders
	pr.mu.Unlock()
	return nil
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
