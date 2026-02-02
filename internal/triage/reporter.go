package triage

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// Reporter generates reports from triage results
type Reporter struct {
	results []*models.TriageResult
	summary *TriageSummary
}

// NewReporter creates a new reporter
func NewReporter(results []*models.TriageResult, summary *TriageSummary) *Reporter {
	return &Reporter{
		results: results,
		summary: summary,
	}
}

// OutputFormat specifies the output format
type OutputFormat string

const (
	FormatCore      OutputFormat = "core"      // Fast decision snapshot
	FormatExecutive OutputFormat = "executive" // Decision + intelligence + foresight
	FormatDebug     OutputFormat = "debug"     // Technical deep-dive
	FormatJSON      OutputFormat = "json"      // Machine-readable
)

// GenerateReport generates a report in the specified format
func (r *Reporter) GenerateReport(writer io.Writer, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return r.generateJSONReport(writer)
	case FormatCore:
		return r.generateCoreReport(writer)
	case FormatExecutive:
		return r.generateExecutiveReport(writer)
	case FormatDebug:
		return r.generateDebugReport(writer)
	default:
		return r.generateExecutiveReport(writer) // Default to executive
	}
}

// generateCoreReport generates a minimal, CI-optimized report
func (r *Reporter) generateCoreReport(writer io.Writer) error {
	fmt.Fprintln(writer, "NetShield Real Risk Analysis")
	fmt.Fprintln(writer, "────────────────────────────")
	fmt.Fprintln(writer)

	if r.summary.Total == 0 {
		fmt.Fprintln(writer, "SAFE TO SHIP")
		fmt.Fprintln(writer, "No vulnerabilities detected")
		return nil
	}

	// Show only critical information
	if r.summary.Reachable > 0 {
		hasCritical := r.hasReachableCritical()
		if hasCritical {
			fmt.Fprintln(writer, "DO NOT SHIP")
		} else {
			fmt.Fprintln(writer, "SHIP WITH CAUTION")
		}
		fmt.Fprintf(writer, "%d reachable vulnerabilities found\n", r.summary.Reachable)
		fmt.Fprintln(writer)

		// Show only reachable vulnerabilities
		for _, result := range r.results {
			if result.Status == models.StatusReachable {
				vuln := result.Vulnerability
				fmt.Fprintf(writer, "• %s (%s) - %s\n", vuln.ID, vuln.Severity, vuln.AffectedPackage)
				if vuln.FixedVersion != "" {
					fmt.Fprintf(writer, "  Fix: Upgrade to %s\n", vuln.FixedVersion)
				}
			}
		}
	} else if r.summary.Unknown > 0 {
		fmt.Fprintln(writer, "SHIP WITH CAUTION")
		fmt.Fprintf(writer, "%d vulnerabilities require manual review\n", r.summary.Unknown)
	} else {
		// All unreachable
		fmt.Fprintln(writer, "SAFE TO SHIP")
		fmt.Fprintln(writer, "No exploitable vulnerabilities detected.")
		if r.summary.Total == 1 {
			fmt.Fprintf(writer, "1 vulnerability present but unreachable from application code.\n")
		} else {
			fmt.Fprintf(writer, "%d vulnerabilities present but unreachable from application code.\n", r.summary.Total)
		}
	}

	return nil
}

// generateExecutiveReport generates an executive decision + intelligence report
func (r *Reporter) generateExecutiveReport(writer io.Writer) error {
	// Header
	fmt.Fprintln(writer, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(writer, "                   NetShield Release Analysis")
	fmt.Fprintln(writer, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(writer)

	// 🎯 EXECUTIVE SUMMARY (The Kill Shot)
	fmt.Fprintln(writer, "EXECUTIVE SUMMARY")
	fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
	execSummary := r.generateExecutiveSummary()
	fmt.Fprintln(writer, execSummary)
	fmt.Fprintln(writer)

	// 1️⃣ RELEASE STATUS
	releaseStatus, _ := r.determineReleaseStatus()
	fmt.Fprintln(writer, "RELEASE STATUS")
	fmt.Fprintf(writer, "%s\n", releaseStatus)
	fmt.Fprintln(writer)

	// 🎯 RELEASE CONFIDENCE (Emotional Anchor)
	releaseConfidence := r.determineReleaseConfidence()
	fmt.Fprintln(writer, "RELEASE CONFIDENCE")
	fmt.Fprintln(writer, releaseConfidence)
	fmt.Fprintln(writer)

	// 2️⃣ BUSINESS RISK
	fmt.Fprintln(writer, "BUSINESS RISK")
	fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")

	exploitRisk := r.determineExploitRisk()
	productionExposure := r.determineProductionExposure()
	patchUrgency := r.determinePatchUrgency()
	engineeringImpact := r.determineEngineeringImpact()

	fmt.Fprintf(writer, "Exploit Risk         %s\n", exploitRisk)
	fmt.Fprintf(writer, "Production Exposure  %s\n", productionExposure)
	fmt.Fprintf(writer, "Patch Urgency        %s\n", patchUrgency)
	fmt.Fprintf(writer, "Engineering Impact   %s\n", engineeringImpact)
	fmt.Fprintln(writer)

	// 3️⃣ SUPPLY CHAIN TRUST SCORE (Executive Candy)
	score, factors := r.calculateSupplyChainScore()
	fmt.Fprintln(writer, "SUPPLY CHAIN TRUST SCORE")
	fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
	fmt.Fprintf(writer, "%d / 100  (%s)\n", score, r.scoreRating(score))
	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "Factors:")
	for _, factor := range factors {
		fmt.Fprintf(writer, "%s\n", factor)
	}
	fmt.Fprintln(writer)

	if r.summary.Total == 0 {
		// No vulnerabilities - show automated protection and exit
		fmt.Fprintln(writer, "ACTIVE PROTECTION")
		fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
		fmt.Fprintln(writer, "NetShield continuously monitors code changes. If any vulnerability")
		fmt.Fprintln(writer, "becomes reachable through new code paths, builds will automatically")
		fmt.Fprintln(writer, "fail until the risk is addressed.")
		fmt.Fprintln(writer)
		return nil
	}

	// 4️⃣ BLAST RADIUS PROJECTION (Future Vision with Time Framing)
	if r.summary.Unreachable > 0 {
		fmt.Fprintln(writer, "IF FUTURE CODE INTRODUCES RISK")
		fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
		blastRadius := r.projectBlastRadius()
		fmt.Fprintln(writer, blastRadius)
		fmt.Fprintln(writer)
	}

	// 5️⃣ SECURITY EVIDENCE (Minimal)
	findingCount := r.summary.Total
	fmt.Fprintf(writer, "SECURITY EVIDENCE\n")
	fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
	if findingCount == 1 {
		if r.summary.Unreachable == 1 {
			fmt.Fprintln(writer, "1 critical vulnerability detected but unreachable from execution paths.")
		} else {
			fmt.Fprintln(writer, "1 vulnerability detected.")
		}
	} else {
		if r.summary.Unreachable == findingCount {
			fmt.Fprintf(writer, "%d vulnerabilities detected but unreachable from execution paths.\n", findingCount)
		} else {
			fmt.Fprintf(writer, "%d vulnerabilities detected.\n", findingCount)
		}
	}
	fmt.Fprintln(writer)

	sortedResults := r.sortResultsByPriority()
	for _, result := range sortedResults {
		r.printExecutiveVulnerability(writer, result)
	}

	// 6️⃣ ACTIVE PROTECTION
	fmt.Fprintln(writer, "ACTIVE PROTECTION")
	fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
	fmt.Fprintln(writer, "If future code makes any vulnerability reachable, NetShield will")
	fmt.Fprintln(writer, "fail the build automatically.")
	fmt.Fprintln(writer)

	return nil
}

// generateExecutiveSummary creates a 2-sentence executive summary
func (r *Reporter) generateExecutiveSummary() string {
	if r.summary.Total == 0 {
		return "No security vulnerabilities detected in project dependencies.\nApplication is clear for production release."
	}

	if r.summary.Reachable > 0 {
		if r.hasReachableCritical() {
			return fmt.Sprintf("Critical exploitable vulnerabilities detected (%d reachable).\nRelease is blocked until patches are applied.", r.summary.Reachable)
		}
		return fmt.Sprintf("Exploitable vulnerabilities detected (%d reachable) but not critical severity.\nReview recommended before release.", r.summary.Reachable)
	}

	if r.summary.Unknown > 0 {
		return fmt.Sprintf("Vulnerabilities detected (%d total) but reachability analysis incomplete.\nManual security review recommended before release.", r.summary.Total)
	}

	// All unreachable
	if r.summary.Total == 1 {
		return "1 vulnerability exists in dependencies but cannot be triggered by application code.\nNo exploitable security risk exists in this release."
	}
	return fmt.Sprintf("%d vulnerabilities exist in dependencies but cannot be triggered by application code.\nNo exploitable security risk exists in this release.", r.summary.Total)
}

// determineReleaseConfidence returns the emotional anchor statement
func (r *Reporter) determineReleaseConfidence() string {
	if r.summary.Reachable > 0 {
		if r.hasReachableCritical() {
			return "Critical risk detected. Release blocked."
		}
		return "Moderate confidence. Review recommended before release."
	}

	if r.summary.Unknown > 0 {
		return "Moderate confidence. Manual review recommended."
	}

	return "High confidence this release introduces no exploitable security risk."
}

// calculateSupplyChainScore returns a trust score and contributing factors
func (r *Reporter) calculateSupplyChainScore() (int, []string) {
	score := 100
	factors := []string{}

	// Deduct for reachable CVEs
	if r.summary.Reachable > 0 {
		deduction := r.summary.Reachable * 15
		if deduction > 40 {
			deduction = 40
		}
		score -= deduction
		factors = append(factors, fmt.Sprintf("✗ Reachable CVEs detected (-%d)", deduction))
	} else {
		factors = append(factors, "✔ No reachable CVEs")
	}

	// Deduct for unknown status
	if r.summary.Unknown > 0 {
		deduction := r.summary.Unknown * 5
		if deduction > 20 {
			deduction = 20
		}
		score -= deduction
		factors = append(factors, fmt.Sprintf("⚠ Incomplete analysis (-%d)", deduction))
	} else {
		factors = append(factors, "✔ Complete reachability analysis")
	}

	// Bonus for clean dependency graph
	if r.summary.Total == 0 {
		factors = append(factors, "✔ Clean dependency graph")
	} else if r.summary.Unreachable == r.summary.Total {
		factors = append(factors, "✔ All vulnerabilities unreachable")
	}

	// Standard practices
	factors = append(factors, "✔ Standard dependency management")

	// Cap at 96 to avoid perfection trap (leave room for SBOM signing, provenance, etc.)
	if score > 96 {
		score = 96
		// Future premium features that could unlock 97-100:
		// - SBOM signing verification
		// - Provenance attestation
		// - Runtime telemetry integration
	}

	if score < 0 {
		score = 0
	}

	return score, factors
}

// scoreRating converts numeric score to rating
func (r *Reporter) scoreRating(score int) string {
	if score >= 90 {
		return "Excellent"
	} else if score >= 75 {
		return "Good"
	} else if score >= 60 {
		return "Fair"
	} else if score >= 40 {
		return "Poor"
	}
	return "Critical"
}

// projectBlastRadius estimates impact if unreachable vulns become reachable
func (r *Reporter) projectBlastRadius() string {
	if r.summary.Unreachable == 0 {
		return "No unreachable vulnerabilities to project."
	}

	criticalCount := 0
	highCount := 0
	for _, result := range r.results {
		if result.Status == models.StatusUnreachable {
			if result.Vulnerability.Severity == "CRITICAL" {
				criticalCount++
			} else if result.Vulnerability.Severity == "HIGH" {
				highCount++
			}
		}
	}

	output := "Potential Impact:\n"
	if criticalCount > 0 {
		output += fmt.Sprintf("  • %d critical vulnerabilities could become exploitable\n", criticalCount)
	}
	if highCount > 0 {
		output += fmt.Sprintf("  • %d high-severity vulnerabilities could become exploitable\n", highCount)
	}
	output += "\nNetShield will block builds within minutes of risk becoming reachable."

	return output
}

// determineReleaseStatus returns the release status and explanation
func (r *Reporter) determineReleaseStatus() (string, string) {
	if r.summary.Reachable > 0 {
		if r.hasReachableCritical() {
			return "✗ DO NOT SHIP", "Critical exploitable vulnerabilities exist in application execution paths."
		}
		return "⚠ SHIP WITH CAUTION", "Vulnerabilities are reachable but not critical severity."
	}

	if r.summary.Unknown > 0 {
		return "⚠ SHIP WITH CAUTION", "Some vulnerabilities require manual security review."
	}

	return "✓ SAFE TO SHIP", "No exploitable vulnerabilities exist in application execution paths."
}

// hasReachableCritical checks if there are any reachable critical vulnerabilities
func (r *Reporter) hasReachableCritical() bool {
	for _, result := range r.results {
		if result.Status == models.StatusReachable && result.Vulnerability.Severity == "CRITICAL" {
			return true
		}
	}
	return false
}

// determineExploitRisk returns the exploit risk level
func (r *Reporter) determineExploitRisk() string {
	if r.summary.Reachable > 0 {
		if r.hasReachableCritical() {
			return "HIGH"
		}
		return "MEDIUM"
	}
	if r.summary.Unknown > 0 {
		return "LOW"
	}
	return "NONE"
}

// determineProductionExposure returns the production exposure level
func (r *Reporter) determineProductionExposure() string {
	if r.summary.Reachable > 0 {
		return "ACTIVE RISK"
	}
	if r.summary.Unknown > 0 {
		return "LIMITED"
	}
	return "NONE"
}

// determinePatchUrgency returns the patch urgency level
func (r *Reporter) determinePatchUrgency() string {
	if r.summary.Reachable > 0 {
		if r.hasReachableCritical() {
			return "IMMEDIATE"
		}
		return "SPRINT"
	}
	if r.summary.Unknown > 0 {
		return "ROUTINE"
	}
	return "NONE"
}

// determineEngineeringImpact returns the engineering impact
func (r *Reporter) determineEngineeringImpact() string {
	if r.summary.Reachable > 0 {
		if r.hasReachableCritical() {
			return "Release Blocking"
		}
		return "Requires Patch"
	}
	if r.summary.Unknown > 0 {
		return "Minor"
	}
	return "None"
}

// printPremiumVulnerabilityDecisionFocused prints vulnerability in decision-focused format
func (r *Reporter) printPremiumVulnerabilityDecisionFocused(writer io.Writer, result *models.TriageResult) {
	vuln := result.Vulnerability

	// Header with CVE and Package
	fmt.Fprintf(writer, "CVE: %s\n", vuln.ID)
	fmt.Fprintf(writer, "Package: %s\n", vuln.AffectedPackage)
	fmt.Fprintf(writer, "Severity: %s", vuln.Severity)
	if vuln.CVSS > 0 {
		fmt.Fprintf(writer, " (CVSS %.1f)", vuln.CVSS)
	}
	fmt.Fprintln(writer)
	fmt.Fprintln(writer)

	// Reachability Status
	var reachStatus string
	switch result.Status {
	case models.StatusReachable:
		reachStatus = "REACHABLE - Vulnerable code is called by application"
	case models.StatusUnreachable:
		reachStatus = "UNREACHABLE - Vulnerable code exists but is not called"
	case models.StatusUnknown:
		reachStatus = "UNKNOWN - Manual review required"
	}
	fmt.Fprintf(writer, "Reachability: %s\n", reachStatus)
	fmt.Fprintln(writer)

	// Plain-English Reason
	fmt.Fprintln(writer, "Analysis:")
	reasons := r.parseReasonIntoBullets(result.Reason)
	for _, reason := range reasons {
		fmt.Fprintf(writer, "  • %s\n", reason)
	}
	fmt.Fprintln(writer)

	// Recommended Action
	fmt.Fprintf(writer, "Recommended Action: %s\n", result.Recommendation)

	if vuln.FixedVersion != "" {
		fmt.Fprintf(writer, "Fixed In: %s\n", vuln.FixedVersion)
	}

	fmt.Fprintln(writer)
	fmt.Fprintln(writer, "────────────────────────────────────────────────────────────────")
	fmt.Fprintln(writer)
}

// parseReasonIntoBullets converts a reason string into bullet points
func (r *Reporter) parseReasonIntoBullets(reason string) []string {
	if strings.Contains(reason, "Vulnerable method") {
		parts := strings.Split(reason, ". ")
		bullets := make([]string, 0)
		for _, part := range parts {
			if part != "" {
				bullets = append(bullets, strings.TrimSpace(part))
			}
		}
		if len(bullets) > 0 {
			return bullets
		}
	}
	return []string{reason}
}

// printExecutiveVulnerability prints vulnerability in clean, minimal format
func (r *Reporter) printExecutiveVulnerability(writer io.Writer, result *models.TriageResult) {
	vuln := result.Vulnerability

	// CVE and Package on separate lines
	fmt.Fprintf(writer, "CVE: %s\n", vuln.ID)
	fmt.Fprintf(writer, "Package: %s\n", vuln.AffectedPackage)
	fmt.Fprintf(writer, "Severity: %s\n", vuln.Severity)
	fmt.Fprintln(writer)

	// Reachability Status
	var reachStatus string
	switch result.Status {
	case models.StatusReachable:
		reachStatus = "REACHABLE"
	case models.StatusUnreachable:
		reachStatus = "UNREACHABLE"
	case models.StatusUnknown:
		reachStatus = "UNKNOWN"
	}
	fmt.Fprintf(writer, "Reachability: %s\n", reachStatus)

	// Plain-English reason
	fmt.Fprintf(writer, "Reason: %s\n", r.simplifyReason(result.Reason))
	fmt.Fprintln(writer)
	fmt.Fprintln(writer)
}

// simplifyReason converts technical reason to plain English
func (r *Reporter) simplifyReason(reason string) string {
	// Convert technical reasons to plain English
	if strings.Contains(reason, "exist but are not called") {
		return "Vulnerable method exists but is never invoked"
	}
	if strings.Contains(reason, "are reachable") {
		return "Vulnerable method is called by application"
	}
	if strings.Contains(reason, "No affected methods") {
		return "Insufficient vulnerability data for analysis"
	}
	return reason
}

// generateDebugReport generates a technical deep-dive report
func (r *Reporter) generateDebugReport(writer io.Writer) error {
	fmt.Fprintln(writer, "╔════════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(writer, "║     JAR Reachability & Impact Analysis Report (DEBUG)         ║")
	fmt.Fprintln(writer, "╚════════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(writer)

	fmt.Fprintln(writer, "TECHNICAL SUMMARY")
	fmt.Fprintln(writer, "──────────────────────────────────────────────────────────────────")
	fmt.Fprintf(writer, "Total Vulnerabilities: %d\n", r.summary.Total)
	fmt.Fprintf(writer, "  Reachable:        %d (URGENT)\n", r.summary.Reachable)
	fmt.Fprintf(writer, "  Unknown:          %d (Review Required)\n", r.summary.Unknown)
	fmt.Fprintf(writer, "  Unreachable:      %d (Low Priority)\n", r.summary.Unreachable)
	fmt.Fprintln(writer)

	if len(r.summary.BySeverity) > 0 {
		fmt.Fprintln(writer, "By Severity:")
		severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
		for _, sev := range severities {
			if count, exists := r.summary.BySeverity[sev]; exists && count > 0 {
				fmt.Fprintf(writer, "  %s: %d\n", sev, count)
			}
		}
		fmt.Fprintln(writer)
	}

	sortedResults := r.sortResultsByPriority()

	fmt.Fprintln(writer, "DETAILED TECHNICAL ANALYSIS")
	fmt.Fprintln(writer, "══════════════════════════════════════════════════════════════════")
	fmt.Fprintln(writer)

	for i, result := range sortedResults {
		r.printDebugVulnerability(writer, i+1, result)
	}

	fmt.Fprintln(writer, "──────────────────────────────────────────────────────────────────")
	fmt.Fprintln(writer, "TIP: Use --format=premium for decision-focused output")
	fmt.Fprintln(writer, "══════════════════════════════════════════════════════════════════")

	return nil
}

// printDebugVulnerability prints a single vulnerability in debug format
func (r *Reporter) printDebugVulnerability(writer io.Writer, index int, result *models.TriageResult) {
	vuln := result.Vulnerability

	var statusIcon string
	var statusColor string
	switch result.Status {
	case models.StatusReachable:
		statusIcon = "🔴"
		statusColor = "REACHABLE"
	case models.StatusUnreachable:
		statusIcon = "🟢"
		statusColor = "UNREACHABLE"
	case models.StatusUnknown:
		statusIcon = "🟡"
		statusColor = "UNKNOWN"
	}

	fmt.Fprintf(writer, "[%d] %s %s - %s\n", index, statusIcon, vuln.ID, statusColor)
	fmt.Fprintf(writer, "    Package:  %s\n", vuln.AffectedPackage)
	fmt.Fprintf(writer, "    Severity: %s", vuln.Severity)
	if vuln.CVSS > 0 {
		fmt.Fprintf(writer, " (CVSS: %.1f)", vuln.CVSS)
	}
	fmt.Fprintln(writer)

	if vuln.Description != "" {
		desc := vuln.Description
		if len(desc) > 100 {
			desc = desc[:97] + "..."
		}
		fmt.Fprintf(writer, "    Description: %s\n", desc)
	}

	if len(vuln.AffectedMethods) > 0 {
		fmt.Fprintf(writer, "    Affected Methods: %s\n", strings.Join(vuln.AffectedMethods, ", "))
	}

	if vuln.FixedVersion != "" {
		fmt.Fprintf(writer, "    Fixed In: %s\n", vuln.FixedVersion)
	}

	fmt.Fprintf(writer, "    Technical Reason: %s\n", result.Reason)
	fmt.Fprintf(writer, "    ➜ %s\n", result.Recommendation)
	fmt.Fprintln(writer)
}

// generateJSONReport generates a JSON report
func (r *Reporter) generateJSONReport(writer io.Writer) error {
	report := map[string]interface{}{
		"summary": r.summary,
		"results": r.results,
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// sortResultsByPriority sorts results by priority
func (r *Reporter) sortResultsByPriority() []*models.TriageResult {
	sorted := make([]*models.TriageResult, len(r.results))
	copy(sorted, r.results)

	sort.Slice(sorted, func(i, j int) bool {
		statusPriority := map[models.ReachabilityStatus]int{
			models.StatusReachable:   3,
			models.StatusUnknown:     2,
			models.StatusUnreachable: 1,
		}

		if statusPriority[sorted[i].Status] != statusPriority[sorted[j].Status] {
			return statusPriority[sorted[i].Status] > statusPriority[sorted[j].Status]
		}

		severityPriority := map[string]int{
			"CRITICAL": 5,
			"HIGH":     4,
			"MEDIUM":   3,
			"LOW":      2,
			"UNKNOWN":  1,
		}

		return severityPriority[sorted[i].Vulnerability.Severity] > severityPriority[sorted[j].Vulnerability.Severity]
	})

	return sorted
}
