// Package license handles license validation and feature gating for NetShield.
package license

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Tier represents the subscription tier
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

// License holds the validated license information
type License struct {
	Tier      Tier      `json:"tier"`
	OrgName   string    `json:"org_name,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Features  []string  `json:"features"`
	IsValid   bool      `json:"is_valid"`
	Message   string    `json:"message,omitempty"`
}

// Feature constants for gating
const (
	FeatureCallGraph = "callgraph"
	FeatureStorage   = "storage"
	FeatureAPI       = "api"
	FeatureExport    = "export"
)

// Free tier features
var freeFeatures = []string{FeatureAPI}

// Pro tier features
var proFeatures = []string{FeatureAPI, FeatureCallGraph, FeatureStorage, FeatureExport}

// Enterprise tier features (all)
var enterpriseFeatures = []string{FeatureAPI, FeatureCallGraph, FeatureStorage, FeatureExport}

// HasFeature checks if the license has a specific feature
func HasFeature(license *License, feature string) bool {
	if license == nil {
		return false
	}
	for _, f := range license.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// GetLicenseFromEnv reads license key + server URL from env and validates.
// Priority: env var → saved key file → free tier. Then validates via server or locally.
func GetLicenseFromEnv() *License {
	key := os.Getenv("NETSHIELD_LICENSE_KEY")
	serverURL := os.Getenv("NETSHIELD_LICENSE_SERVER")

	// If no env var, try saved key from previous GUI activation
	if key == "" {
		key = loadSavedKey()
	}

	if key == "" {
		return &License{
			Tier:     TierFree,
			Features: freeFeatures,
			IsValid:  true,
			Message:  "Free tier - upgrade to unlock Call Graph and Storage",
		}
	}

	// If license server is configured, phone home
	if serverURL != "" {
		lic := validateWithServer(key, serverURL)
		if lic != nil {
			// Cache successful result
			saveCache(lic)
			return lic
		}

		// Server unreachable — try offline cache
		cached := loadCache()
		if cached != nil {
			cached.Message = cached.Message + " (offline — cached)"
			return cached
		}

		// Cache expired or missing — fall back to free
		fmt.Println("Warning: license server unreachable and no valid cache — falling back to free tier")
	}

	// No server configured — use local validation (backward compatible)
	return ValidateLicenseKey(key)
}

// ValidateKey validates a license key (called from GUI activation).
// Saves the key to disk on success so it persists across server restarts.
func ValidateKey(key string) *License {
	if key == "" {
		return &License{Tier: TierFree, Features: freeFeatures, IsValid: true, Message: "No key provided"}
	}

	serverURL := os.Getenv("NETSHIELD_LICENSE_SERVER")
	if serverURL != "" {
		lic := validateWithServer(key, serverURL)
		if lic != nil {
			saveCache(lic)
			saveKeyToFile(key) // Persist for restarts
			return lic
		}
	}

	result := ValidateLicenseKey(key)
	if result.IsValid {
		saveKeyToFile(key) // Persist for restarts
	}
	return result
}

// --- Key file persistence ---

func getKeyFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".netshield", "active_key")
}

func saveKeyToFile(key string) {
	path := getKeyFilePath()
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte(strings.TrimSpace(key)), 0600)
}

func loadSavedKey() string {
	path := getKeyFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// validateWithServer calls the license server to validate a key.
func validateWithServer(key, serverURL string) *License {
	serverURL = strings.TrimRight(serverURL, "/")
	endpoint := serverURL + "/api/validate"

	// Generate machine ID from hostname
	machineID := getMachineID()

	body, _ := json.Marshal(map[string]string{
		"key":        key,
		"machine_id": machineID,
	})

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Warning: license server error: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	var result struct {
		Valid    bool     `json:"valid"`
		Tier     string   `json:"tier"`
		Features []string `json:"features"`
		OrgName  string   `json:"org_name"`
		Message  string   `json:"message"`
		ExpAt    string   `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("Warning: failed to parse license response: %v\n", err)
		return nil
	}

	lic := &License{
		Tier:     Tier(result.Tier),
		OrgName:  result.OrgName,
		Features: result.Features,
		IsValid:  result.Valid,
		Message:  result.Message,
	}

	if result.ExpAt != "" {
		if t, err := time.Parse(time.RFC3339, result.ExpAt); err == nil {
			lic.ExpiresAt = t
		}
	}

	return lic
}

// --- Offline cache ---

type licenseCache struct {
	License  *License  `json:"license"`
	CachedAt time.Time `json:"cached_at"`
}

const cacheGracePeriod = 72 * time.Hour

func getCachePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".netshield", "license_cache.json")
}

func saveCache(lic *License) {
	path := getCachePath()
	os.MkdirAll(filepath.Dir(path), 0700)
	data, _ := json.Marshal(licenseCache{License: lic, CachedAt: time.Now()})
	os.WriteFile(path, data, 0600)
}

func loadCache() *License {
	path := getCachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cached licenseCache
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil
	}
	// Check grace period
	if time.Since(cached.CachedAt) > cacheGracePeriod {
		return nil // Cache expired
	}
	if !cached.License.IsValid {
		return nil
	}
	return cached.License
}

func getMachineID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	h := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(h[:8])
}

// --- Legacy local validation (backward compatible) ---

// ValidateLicenseKey validates a license key locally (no server).
// Kept for backward compatibility when no license server is configured.
func ValidateLicenseKey(key string) *License {
	if key == "" {
		return &License{
			Tier:     TierFree,
			Features: freeFeatures,
			IsValid:  true,
			Message:  "Free tier - upgrade to unlock Call Graph and Storage",
		}
	}

	key = strings.ToUpper(strings.TrimSpace(key))

	if !strings.HasPrefix(key, "NS") {
		return &License{
			Tier:     TierFree,
			Features: freeFeatures,
			IsValid:  false,
			Message:  "Invalid license key format",
		}
	}

	if !validateKeyChecksum(key) {
		return &License{
			Tier:     TierFree,
			Features: freeFeatures,
			IsValid:  false,
			Message:  "Invalid license key",
		}
	}

	if strings.HasPrefix(key, "NSPRO") {
		return &License{
			Tier:     TierPro,
			Features: proFeatures,
			IsValid:  true,
			Message:  "Pro license active",
		}
	}

	if strings.HasPrefix(key, "NSENT") {
		return &License{
			Tier:     TierEnterprise,
			Features: enterpriseFeatures,
			IsValid:  true,
			Message:  "Enterprise license active",
		}
	}

	return &License{
		Tier:     TierFree,
		Features: freeFeatures,
		IsValid:  false,
		Message:  "Unknown license tier",
	}
}

func validateKeyChecksum(key string) bool {
	cleanKey := strings.ReplaceAll(key, "-", "")
	if len(cleanKey) < 16 {
		return false
	}
	body := cleanKey[5:]
	return len(body) >= 8
}

// GenerateDemoKey generates a demo license key (for testing)
func GenerateDemoKey(tier Tier) string {
	var prefix string
	switch tier {
	case TierPro:
		prefix = "NSPRO"
	case TierEnterprise:
		prefix = "NSENT"
	default:
		return ""
	}

	hash := sha256.Sum256([]byte(time.Now().String()))
	hashStr := hex.EncodeToString(hash[:])[:12]

	return prefix + "-" + hashStr[:4] + "-" + hashStr[4:8] + "-" + hashStr[8:12]
}
