package server

import (
	"fmt"
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

var KnownProviders = []map[string]string{
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

func NewProviderResolver() *ProviderResolver {
	pr := &ProviderResolver{
		providers: make(map[string]string),
	}
	// Load static list
	for _, p := range KnownProviders {
		guid := strings.ToUpper(strings.Trim(p["guid"], "{}"))
		pr.providers[guid] = p["name"]
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
