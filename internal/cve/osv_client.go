package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// OSVClient interacts with the Open Source Vulnerabilities (OSV) API
type OSVClient struct {
	baseURL    string
	httpClient *http.Client
	Quiet      bool // suppress per-dependency progress logging
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

// extractAffectedMethods tries to extract affected methods from vulnerability data.
// This is heuristic-based since OSV doesn't always provide structured method-level data.
// The approach:
//  1. Check CVE description keywords → map to known vulnerable method names
//  2. Check the affected package name itself → map well-known libraries to their methods
//  3. Check database_specific fields for structured data
func (c *OSVClient) extractAffectedMethods(osv OSVVulnerability) []string {
	methods := make([]string, 0)
	seen := make(map[string]bool)

	add := func(m string) {
		if !seen[m] {
			seen[m] = true
			methods = append(methods, m)
		}
	}

	details := strings.ToLower(osv.Details + " " + osv.Summary)

	// --- Keyword-based heuristics from CVE description ---

	// JNDI injection
	if strings.Contains(details, "jndi") {
		add("lookup")
	}

	// Deserialization (Java native, Jackson, SnakeYAML, etc.)
	if strings.Contains(details, "deserializ") {
		add("readObject")
		add("readResolve")
		add("readExternal")
		add("load")
		add("readValue")
		add("fromXML")
		add("unmarshal")
	}

	// XStream / XML unmarshalling patterns
	if strings.Contains(details, "unmarshal") || strings.Contains(details, "xstream") {
		add("fromXML")
		add("unmarshal")
	}

	// XML parsing / XXE patterns
	if strings.Contains(details, "xml") && (strings.Contains(details, "injection") ||
		strings.Contains(details, "external entit") || strings.Contains(details, "xxe") ||
		strings.Contains(details, "code execution") || strings.Contains(details, "arbitrary")) {
		add("fromXML")
		add("unmarshal")
		add("parse")
		add("newSAXParser")
		add("newDocumentBuilder")
		add("createXMLStreamReader")
	}

	// Arbitrary code / remote code execution
	if strings.Contains(details, "arbitrary code") || strings.Contains(details, "remote code execution") ||
		strings.Contains(details, "code execution") || strings.Contains(details, "rce") {
		add("readObject")
		add("fromXML")
		add("unmarshal")
		add("load")
		add("readValue")
		add("evaluate")
		add("invoke")
	}

	// SSRF patterns
	if strings.Contains(details, "server-side") && strings.Contains(details, "request") {
		add("fromXML")
		add("unmarshal")
		add("openConnection")
		add("openStream")
	}

	// Denial of Service via input processing
	if strings.Contains(details, "denial of service") && strings.Contains(details, "input") {
		add("fromXML")
		add("unmarshal")
		add("parse")
		add("load")
		add("readValue")
	}

	// YAML processing
	if strings.Contains(details, "yaml") {
		add("load")
		add("loadAll")
		add("loadAs")
	}

	// Expression language / template injection
	if strings.Contains(details, "expression") || strings.Contains(details, "template") ||
		strings.Contains(details, "spel") || strings.Contains(details, "ognl") {
		add("evaluate")
		add("parseExpression")
		add("getValue")
	}

	// SQL injection
	if strings.Contains(details, "sql injection") || strings.Contains(details, "sql inject") {
		add("executeQuery")
		add("executeUpdate")
		add("execute")
		add("prepareStatement")
	}

	// --- Package-name-based heuristics (fallback) ---
	// Well-known libraries have well-known vulnerable entry points.
	// If the CVE is for this package, these methods are the likely attack surface.
	for _, affected := range osv.Affected {
		pkg := strings.ToLower(affected.Package.Name)

		switch {
		case strings.Contains(pkg, "xstream"):
			add("fromXML")
			add("unmarshal")
		case strings.Contains(pkg, "snakeyaml"):
			add("load")
			add("loadAll")
			add("loadAs")
		case strings.Contains(pkg, "jackson-databind"):
			add("readValue")
			add("readTree")
			add("enableDefaultTyping")
		case strings.Contains(pkg, "commons-collections"):
			add("readObject")
			add("transform")
		case strings.Contains(pkg, "log4j"):
			add("lookup")
			add("log")
			add("error")
			add("info")
		case strings.Contains(pkg, "spring-expression") || strings.Contains(pkg, "spring-core"):
			add("parseExpression")
			add("getValue")
		case strings.Contains(pkg, "commons-text"):
			add("replace")
			add("lookup")
		}

		// Check database_specific fields for structured affected class data
		if affected.DatabaseSpecific != nil {
			if classes, ok := affected.DatabaseSpecific["affected_classes"].([]interface{}); ok {
				for _, class := range classes {
					if classStr, ok := class.(string); ok {
						add(classStr)
					}
				}
			}
		}
	}

	return methods
}

// GetVulnerabilitiesForDependencies gets vulnerabilities for all dependencies concurrently
func (c *OSVClient) GetVulnerabilitiesForDependencies(dependencies []*models.Dependency) (map[string][]*models.Vulnerability, error) {
	result := make(map[string][]*models.Vulnerability)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore to limit concurrent HTTP requests (avoid overwhelming the API)
	const maxConcurrent = 10
	sem := make(chan struct{}, maxConcurrent)

	total := len(dependencies)
	var completed int64

	if !c.Quiet {
		fmt.Fprintf(os.Stderr, "  Querying CVE database for %d dependencies...\n", total)
	}

	for _, dep := range dependencies {
		wg.Add(1)
		go func(dep *models.Dependency) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			key := fmt.Sprintf("%s:%s:%s", dep.GroupID, dep.ArtifactID, dep.Version)

			vulns, err := c.GetVulnerabilities(dep.GroupID, dep.ArtifactID, dep.Version)
			done := atomic.AddInt64(&completed, 1)
			if err != nil {
				if !c.Quiet {
					fmt.Fprintf(os.Stderr, "  [%d/%d] Warning: %s: %v\n", done, total, key, err)
				}
				return
			}

			if len(vulns) > 0 {
				mu.Lock()
				result[key] = vulns
				mu.Unlock()
				if !c.Quiet {
					fmt.Fprintf(os.Stderr, "  [%d/%d] %s — %d CVEs found\n", done, total, key, len(vulns))
				}
			} else {
				if !c.Quiet {
					fmt.Fprintf(os.Stderr, "  [%d/%d] %s — clean\n", done, total, key)
				}
			}
		}(dep)
	}

	wg.Wait()
	return result, nil
}
