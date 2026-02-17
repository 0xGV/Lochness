package server

import (
	"strings"
)

var NormalizationMap = map[string]string{
	// Process ID
	"PID":       "ProcessId",
	"processid": "ProcessId",
	"ProcessID": "ProcessId",
	"pid":       "ProcessId",

	// Parent Process ID
	"ParentPID":  "ParentProcessId",
	"parentpid":  "ParentProcessId",
	"ParentId":   "ParentProcessId",
	"parent pid": "ParentProcessId",
	"parent_pid": "ParentProcessId", // Also catch snake_case

	// User
	"user":     "User",
	"username": "User",
	"UserName": "User",

	// Process Name (Keeping separate from ImageName as requested)
	"process name": "ProcessName",
	"processname":  "ProcessName",

	// Image Name
	"Image":     "ImageName",
	"image":     "ImageName",
	"ImageName": "ImageName",

	// Parent Process Name
	"parent process name": "ParentProcessName",
}

func NormalizePayload(data map[string]interface{}) bool {
	changed := false

	// Create a list of modifications to apply to avoid modifying map while iterating
	type modification struct {
		oldKey string
		newKey string
		val    interface{}
	}
	var mods []modification

	for k, v := range data {
		// 1. Exact Match Alias
		if newKey, ok := NormalizationMap[k]; ok {
			if k != newKey {
				mods = append(mods, modification{oldKey: k, newKey: newKey, val: v})
			}
		} else {
			// 2. Case Insensitive Check (Slow fallback?)
			// Let's stick to explicit map for now to avoid accidental collisions
			// but we can check if the lower case version exists in map
			if newKey, ok := NormalizationMap[strings.ToLower(k)]; ok {
				if k != newKey {
					mods = append(mods, modification{oldKey: k, newKey: newKey, val: v})
				}
			}
		}
	}

	for _, mod := range mods {
		// Only apply if new key doesn't already exist (prioritize existing canonical keys or explicit data)
		if _, exists := data[mod.newKey]; !exists {
			data[mod.newKey] = mod.val
			delete(data, mod.oldKey)
			changed = true
		} else {
			// If both exist, we might want to check if they are the same.
			// If they are different, we perform a "soft merge" or just skip.
			// Here we skip overwrite to be safe.
		}
	}

	return changed
}
