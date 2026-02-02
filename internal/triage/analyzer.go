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
}

// NewAnalyzer creates a new triage analyzer
func NewAnalyzer(cg *models.CallGraph, reachable map[string]bool, vulns map[string][]*models.Vulnerability) *Analyzer {
	return &Analyzer{
		callGraph:        cg,
		reachableMethods: reachable,
		vulnerabilities:  vulns,
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

	packageName := strings.ReplaceAll(parts[0], ".", "/") + "/" + parts[1]

	// Check if we have specific affected methods
	if len(vuln.AffectedMethods) > 0 {
		isReachable := a.checkMethodsReachability(packageName, vuln.AffectedMethods)
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
		isReachable := a.checkPackageReachability(packageName)
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

// checkMethodsReachability checks if specific methods are reachable
func (a *Analyzer) checkMethodsReachability(packageName string, methods []string) bool {
	for methodID, isReachable := range a.reachableMethods {
		if !isReachable {
			continue
		}

		// Check if this method belongs to the vulnerable package
		if node, exists := a.callGraph.Nodes[methodID]; exists {
			if strings.Contains(node.ClassName, packageName) {
				// Check if method name matches any affected method
				for _, affectedMethod := range methods {
					if strings.Contains(node.MethodName, affectedMethod) ||
						strings.Contains(methodID, affectedMethod) {
						return true
					}
				}
			}
		}
	}
	return false
}

// checkPackageReachability checks if any method from a package is reachable
func (a *Analyzer) checkPackageReachability(packageName string) bool {
	for methodID, isReachable := range a.reachableMethods {
		if !isReachable {
			continue
		}

		if node, exists := a.callGraph.Nodes[methodID]; exists {
			if strings.Contains(node.ClassName, packageName) {
				return true
			}
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
	Total       int
	Reachable   int
	Unreachable int
	Unknown     int
	BySeverity  map[string]int
}
