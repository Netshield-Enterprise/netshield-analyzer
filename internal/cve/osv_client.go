package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// OSVClient interacts with the Open Source Vulnerabilities (OSV) API
type OSVClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewOSVClient creates a new OSV API client
func NewOSVClient() *OSVClient {
	return &OSVClient{
		baseURL: "https://api.osv.dev/v1",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// OSVQuery represents a query to the OSV API
type OSVQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

// OSVPackage represents a package in OSV format
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVResponse represents the response from OSV API
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents a vulnerability from OSV
type OSVVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []OSVSeverity `json:"severity,omitempty"`
	Affected []OSVAffected `json:"affected"`
}

// OSVSeverity represents severity information
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected represents affected package information
type OSVAffected struct {
	Package           OSVPackage             `json:"package"`
	Ranges            []OSVRange             `json:"ranges"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
}

// OSVRange represents a version range
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent represents a version event
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// GetVulnerabilities queries OSV for vulnerabilities in a package
func (c *OSVClient) GetVulnerabilities(groupID, artifactID, version string) ([]*models.Vulnerability, error) {
	// Construct Maven package name
	packageName := fmt.Sprintf("%s:%s", groupID, artifactID)

	query := OSVQuery{
		Package: OSVPackage{
			Name:      packageName,
			Ecosystem: "Maven",
		},
		Version: version,
	}

	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Make request to OSV API
	url := fmt.Sprintf("%s/query", c.baseURL)
	resp, err := c.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	// Convert to our vulnerability model
	vulns := make([]*models.Vulnerability, 0)
	for _, osv := range osvResp.Vulns {
		vuln := c.convertOSVToVulnerability(osv, packageName)
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// convertOSVToVulnerability converts OSV format to our internal model
func (c *OSVClient) convertOSVToVulnerability(osv OSVVulnerability, packageName string) *models.Vulnerability {
	vuln := &models.Vulnerability{
		ID:              osv.ID,
		AffectedPackage: packageName,
		Description:     osv.Summary,
	}

	if vuln.Description == "" {
		vuln.Description = osv.Details
	}

	// Extract severity
	if len(osv.Severity) > 0 {
		vuln.Severity = c.extractSeverity(osv.Severity)
		vuln.CVSS = c.extractCVSS(osv.Severity)
	} else {
		vuln.Severity = "UNKNOWN"
	}

	// Extract fixed version
	for _, affected := range osv.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					vuln.FixedVersion = event.Fixed
					break
				}
			}
			if vuln.FixedVersion != "" {
				break
			}
		}
		if vuln.FixedVersion != "" {
			break
		}
	}

	// Try to extract affected methods from database_specific or ecosystem_specific
	vuln.AffectedMethods = c.extractAffectedMethods(osv)

	return vuln
}

// extractSeverity extracts severity level from OSV severity data
func (c *OSVClient) extractSeverity(severities []OSVSeverity) string {
	for _, sev := range severities {
		if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V2" {
			// Parse CVSS score to determine severity
			score := c.extractCVSS(severities)
			if score >= 9.0 {
				return "CRITICAL"
			} else if score >= 7.0 {
				return "HIGH"
			} else if score >= 4.0 {
				return "MEDIUM"
			} else if score > 0 {
				return "LOW"
			}
		}
	}
	return "UNKNOWN"
}

// extractCVSS extracts CVSS score from severity data
func (c *OSVClient) extractCVSS(severities []OSVSeverity) float64 {
	for _, sev := range severities {
		if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V2" {
			// Parse CVSS vector string to extract base score
			// Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
			parts := strings.Split(sev.Score, "/")
			for _, part := range parts {
				if strings.HasPrefix(part, "CVSS:") {
					// This is a simplified extraction; in production, use a proper CVSS parser
					// For now, we'll estimate based on the vector
					if strings.Contains(sev.Score, "C:H") && strings.Contains(sev.Score, "I:H") {
						return 9.0 // High impact
					} else if strings.Contains(sev.Score, "C:H") || strings.Contains(sev.Score, "I:H") {
						return 7.0 // Medium-high impact
					}
					return 5.0 // Default medium
				}
			}
		}
	}
	return 0.0
}

// extractAffectedMethods tries to extract affected methods from vulnerability data
func (c *OSVClient) extractAffectedMethods(osv OSVVulnerability) []string {
	methods := make([]string, 0)

	// Check if details mention specific classes or methods
	// This is heuristic-based; OSV doesn't always provide this information
	details := strings.ToLower(osv.Details + " " + osv.Summary)

	// Look for common patterns like "in the X method" or "X.class"
	if strings.Contains(details, "jndi") {
		methods = append(methods, "lookup")
	}
	if strings.Contains(details, "deserialize") {
		methods = append(methods, "readObject")
	}

	// Check database_specific fields
	for _, affected := range osv.Affected {
		if affected.DatabaseSpecific != nil {
			if classes, ok := affected.DatabaseSpecific["affected_classes"].([]interface{}); ok {
				for _, class := range classes {
					if classStr, ok := class.(string); ok {
						methods = append(methods, classStr)
					}
				}
			}
		}
	}

	return methods
}

// GetVulnerabilitiesForDependencies gets vulnerabilities for all dependencies
func (c *OSVClient) GetVulnerabilitiesForDependencies(dependencies []*models.Dependency) (map[string][]*models.Vulnerability, error) {
	result := make(map[string][]*models.Vulnerability)

	for _, dep := range dependencies {
		key := fmt.Sprintf("%s:%s:%s", dep.GroupID, dep.ArtifactID, dep.Version)

		vulns, err := c.GetVulnerabilities(dep.GroupID, dep.ArtifactID, dep.Version)
		if err != nil {
			fmt.Printf("Warning: failed to get vulnerabilities for %s: %v\n", key, err)
			continue
		}

		if len(vulns) > 0 {
			result[key] = vulns
		}
	}

	return result, nil
}
