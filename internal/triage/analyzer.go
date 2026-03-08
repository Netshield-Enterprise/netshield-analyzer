package triage

import (
	"fmt"
	"strings"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// Analyzer performs reachability analysis on vulnerabilities
type Analyzer struct {
	callGraph        *models.CallGraph
	reachableMethods map[string]bool
	vulnerabilities  map[string][]*models.Vulnerability

	// Pre-built indexes for fast lookups
	// reachableByClass maps className → []methodName for all reachable methods
	reachableByClass map[string][]string
	// reachableClasses is the deduplicated set of class names with reachable methods
	reachableClasses []string
}

// NewAnalyzer creates a new triage analyzer with pre-built indexes
func NewAnalyzer(cg *models.CallGraph, reachable map[string]bool, vulns map[string][]*models.Vulnerability) *Analyzer {
	// Build the class→methods index from reachable methods
	byClass := make(map[string][]string)
	for methodID, isReachable := range reachable {
		if !isReachable {
			continue
		}
		if node, exists := cg.Nodes[methodID]; exists {
			byClass[node.ClassName] = append(byClass[node.ClassName], node.MethodName)
		}
	}

	classes := make([]string, 0, len(byClass))
	for cn := range byClass {
		classes = append(classes, cn)
	}

	return &Analyzer{
		callGraph:        cg,
		reachableMethods: reachable,
		vulnerabilities:  vulns,
		reachableByClass: byClass,
		reachableClasses: classes,
	}
}

// AnalyzeReachability performs reachability analysis on all vulnerabilities
func (a *Analyzer) AnalyzeReachability() []*models.TriageResult {
	results := make([]*models.TriageResult, 0)

	for depKey, vulns := range a.vulnerabilities {
		for _, vuln := range vulns {
			result := a.analyzeVulnerability(depKey, vuln)
			results = append(results, result)
		}
	}

	return results
}

// analyzeVulnerability analyzes a single vulnerability
func (a *Analyzer) analyzeVulnerability(depKey string, vuln *models.Vulnerability) *models.TriageResult {
	result := &models.TriageResult{
		Vulnerability: vuln,
		Status:        models.StatusUnknown,
	}

	// Extract package name from dependency key (format: groupId:artifactId:version)
	parts := strings.Split(depKey, ":")
	if len(parts) < 2 {
		result.Reason = "Unable to parse dependency key"
		result.Recommendation = "Manual review required"
		return result
	}

	// Generate candidate package prefixes to match against call graph nodes.
	// Maven groupId:artifactId doesn't always map cleanly to Java package names.
	// Examples of mismatches:
	//   com.thoughtworks.xstream:xstream → classes in com/thoughtworks/xstream/ (not com/thoughtworks/xstream/xstream/)
	//   com.fasterxml.jackson.core:jackson-databind → classes in com/fasterxml/jackson/databind/
	//   org.apache.commons:commons-lang3 → classes in org/apache/commons/lang3/
	packageCandidates := buildPackageCandidates(parts[0], parts[1])

	// Check if we have specific affected methods
	if len(vuln.AffectedMethods) > 0 {
		isReachable := false
		for _, pkg := range packageCandidates {
			if a.checkMethodsReachability(pkg, vuln.AffectedMethods) {
				isReachable = true
				break
			}
		}
		if isReachable {
			result.Status = models.StatusReachable
			result.Reason = fmt.Sprintf("Vulnerable methods %v are reachable from application code", vuln.AffectedMethods)
			result.Recommendation = fmt.Sprintf("URGENT: Upgrade to version %s or apply mitigation", vuln.FixedVersion)
		} else {
			result.Status = models.StatusUnreachable
			result.Reason = fmt.Sprintf("Vulnerable methods %v exist but are not called by application", vuln.AffectedMethods)
			result.Recommendation = "Low priority: Consider upgrading during next maintenance cycle"
		}
	} else {
		// No specific methods identified, check if any method from the package is reachable
		isReachable := false
		for _, pkg := range packageCandidates {
			if a.checkPackageReachability(pkg) {
				isReachable = true
				break
			}
		}
		if isReachable {
			result.Status = models.StatusUnknown
			result.Reason = "Package is used by application, but specific vulnerable methods not identified"
			result.Recommendation = fmt.Sprintf("Review vulnerability details and consider upgrading to %s", vuln.FixedVersion)
		} else {
			result.Status = models.StatusUnreachable
			result.Reason = "No methods from vulnerable package are called by application"
			result.Recommendation = "Low priority: Package is included but not used"
		}
	}

	return result
}

// buildPackageCandidates generates multiple possible Java package prefixes from Maven coordinates.
// Maven groupId:artifactId often doesn't directly map to Java package paths.
func buildPackageCandidates(groupID, artifactID string) []string {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	candidates := make([]string, 0, 4)
	seen := make(map[string]bool)

	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			candidates = append(candidates, c)
		}
	}

	// Pattern 1: groupId/artifactId (e.g., org/yaml/snakeyaml)
	add(groupPath + "/" + artifactID)

	// Pattern 2: groupId only (e.g., com/thoughtworks/xstream)
	// Handles cases where artifactId duplicates the last segment of groupId
	add(groupPath)

	// Pattern 3: Strip common artifact prefixes and append to groupId parent
	// e.g., com.fasterxml.jackson.core:jackson-databind → com/fasterxml/jackson/databind
	cleanArtifact := artifactID
	for _, prefix := range []string{"jackson-", "spring-", "commons-", "jakarta.", "javax."} {
		if strings.HasPrefix(artifactID, prefix) {
			cleanArtifact = strings.TrimPrefix(artifactID, prefix)
			break
		}
	}
	if cleanArtifact != artifactID {
		// Try replacing the last groupId segment with the clean artifact name
		lastSlash := strings.LastIndex(groupPath, "/")
		if lastSlash > 0 {
			parentPath := groupPath[:lastSlash]
			add(parentPath + "/" + cleanArtifact)
		}
	}

	// Pattern 4: artifactId with hyphens removed  (e.g., commons-lang3 → lang3 appended to group)
	if strings.Contains(artifactID, "-") {
		parts := strings.Split(artifactID, "-")
		lastPart := parts[len(parts)-1]
		add(groupPath + "/" + lastPart)
	}

	return candidates
}

// checkMethodsReachability checks if specific methods are reachable using the pre-built index
func (a *Analyzer) checkMethodsReachability(packageName string, methods []string) bool {
	for _, className := range a.reachableClasses {
		if !strings.Contains(className, packageName) {
			continue
		}
		// This class belongs to the vulnerable package — check its methods
		for _, reachableMethod := range a.reachableByClass[className] {
			for _, affectedMethod := range methods {
				if strings.Contains(reachableMethod, affectedMethod) {
					return true
				}
			}
		}
	}
	return false
}

// checkPackageReachability checks if any method from a package is reachable using the pre-built index
func (a *Analyzer) checkPackageReachability(packageName string) bool {
	for _, className := range a.reachableClasses {
		if strings.Contains(className, packageName) {
			return true
		}
	}
	return false
}

// GetSummary generates a summary of the triage results
func (a *Analyzer) GetSummary(results []*models.TriageResult) *TriageSummary {
	summary := &TriageSummary{
		Total:       len(results),
		Reachable:   0,
		Unreachable: 0,
		Unknown:     0,
		BySeverity:  make(map[string]int),
	}

	for _, result := range results {
		switch result.Status {
		case models.StatusReachable:
			summary.Reachable++
		case models.StatusUnreachable:
			summary.Unreachable++
		case models.StatusUnknown:
			summary.Unknown++
		}

		severity := result.Vulnerability.Severity
		summary.BySeverity[severity]++
	}

	return summary
}

// TriageSummary provides a summary of triage results
type TriageSummary struct {
	Total       int            `json:"total"`
	Reachable   int            `json:"reachable"`
	Unreachable int            `json:"unreachable"`
	Unknown     int            `json:"unknown"`
	BySeverity  map[string]int `json:"by_severity"`
}
