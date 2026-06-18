package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type StandardHashEntry struct {
	FilePath    string        `json:"file_path"`
	FileName    string        `json:"file_name"`
	Algorithm   HashAlgorithm `json:"algorithm"`
	HashValue   string        `json:"hash_value"`
	Description string        `json:"description,omitempty"`
	CreatedAt   string        `json:"created_at"`
	UpdatedAt   string        `json:"updated_at"`
}

type HashConfig struct {
	Version   string                       `json:"version"`
	UpdatedAt string                       `json:"updated_at"`
	Files     map[string]StandardHashEntry `json:"files"`
}

var (
	configMutex    sync.RWMutex
	configFilePath = "hash_config.json"
	hashConfig     *HashConfig
)

func initConfigPath() {
	if envPath := os.Getenv("HASH_CONFIG_PATH"); envPath != "" {
		configFilePath = envPath
	}
}

func LoadHashConfig() error {
	initConfigPath()

	configMutex.Lock()
	defer configMutex.Unlock()

	absPath, err := filepath.Abs(configFilePath)
	if err == nil {
		configFilePath = absPath
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			hashConfig = &HashConfig{
				Version:   "1.0",
				UpdatedAt: time.Now().UTC().Format(time.RFC3339),
				Files:     make(map[string]StandardHashEntry),
			}
			return SaveHashConfigLocked()
		}
		return fmt.Errorf("failed to read config: %w", err)
	}

	hashConfig = &HashConfig{}
	if err := json.Unmarshal(data, hashConfig); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	if hashConfig.Files == nil {
		hashConfig.Files = make(map[string]StandardHashEntry)
	}

	return nil
}

func SaveHashConfigLocked() error {
	if hashConfig == nil {
		return fmt.Errorf("config not initialized")
	}

	hashConfig.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	data, err := json.MarshalIndent(hashConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func SaveHashConfig() error {
	configMutex.Lock()
	defer configMutex.Unlock()
	return SaveHashConfigLocked()
}

func GetConfigKey(filePath string, algorithm HashAlgorithm) string {
	return fmt.Sprintf("%s|%s", filePath, string(algorithm))
}

func GetStandardHash(filePath string, algorithm HashAlgorithm) (*StandardHashEntry, bool) {
	configMutex.RLock()
	defer configMutex.RUnlock()

	if hashConfig == nil {
		return nil, false
	}

	key := GetConfigKey(filePath, algorithm)
	entry, exists := hashConfig.Files[key]
	if !exists {
		return nil, false
	}
	return &entry, true
}

func AddStandardHash(filePath string, algorithm HashAlgorithm, hashValue string, description string) (*StandardHashEntry, error) {
	configMutex.Lock()
	defer configMutex.Unlock()

	if hashConfig == nil {
		return nil, fmt.Errorf("config not initialized")
	}

	absPath, err := filepath.Abs(filePath)
	if err == nil {
		filePath = absPath
	}

	now := time.Now().UTC().Format(time.RFC3339)
	entry := StandardHashEntry{
		FilePath:    filePath,
		FileName:    filepath.Base(filePath),
		Algorithm:   algorithm,
		HashValue:   hashValue,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	key := GetConfigKey(filePath, algorithm)
	if existing, exists := hashConfig.Files[key]; exists {
		entry.CreatedAt = existing.CreatedAt
	}
	hashConfig.Files[key] = entry

	if err := SaveHashConfigLocked(); err != nil {
		return nil, err
	}

	return &entry, nil
}

func DeleteStandardHash(filePath string, algorithm HashAlgorithm) bool {
	configMutex.Lock()
	defer configMutex.Unlock()

	if hashConfig == nil {
		return false
	}

	key := GetConfigKey(filePath, algorithm)
	if _, exists := hashConfig.Files[key]; !exists {
		return false
	}

	delete(hashConfig.Files, key)
	SaveHashConfigLocked()
	return true
}

func ListAllStandardHashes() []StandardHashEntry {
	configMutex.RLock()
	defer configMutex.RUnlock()

	result := make([]StandardHashEntry, 0, len(hashConfig.Files))
	for _, entry := range hashConfig.Files {
		result = append(result, entry)
	}
	return result
}

func GetAllStandardHashesForFile(filePath string) []StandardHashEntry {
	configMutex.RLock()
	defer configMutex.RUnlock()

	result := make([]StandardHashEntry, 0)
	if hashConfig == nil {
		return result
	}

	for _, entry := range hashConfig.Files {
		if entry.FilePath == filePath {
			result = append(result, entry)
		}
	}
	return result
}

func ComputeAndAddStandardHash(filePath string, algorithm HashAlgorithm, description string) (*StandardHashEntry, error) {
	hashValue, err := ComputeFileHash(filePath, algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}
	return AddStandardHash(filePath, algorithm, hashValue, description)
}
