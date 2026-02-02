package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Netshield-Enterprise/netshield-analyzer/internal/callgraph"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/cve"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/parser"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/triage"
	"github.com/spf13/cobra"
)

var (
	projectPath   string
	outputFormat  string
	appPackages   []string
	skipCVELookup bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netshield",
		Short: "NetShield Real Risk Analysis",
		Long: `NetShield analyzes Java projects to determine real exploitability of CVEs.
Stop wasting time on vulnerabilities that don't matter.`,
		RunE: runAnalysis,
	}

	rootCmd.Flags().StringVarP(&projectPath, "project", "p", ".", "Path to the Java project")
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "executive", "Output format: core, executive, debug, json")
	rootCmd.Flags().StringSliceVarP(&appPackages, "packages", "a", []string{}, "Application package prefixes (comma-separated)")
	rootCmd.Flags().BoolVar(&skipCVELookup, "skip-cve", false, "Skip CVE lookup (only build call graph)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	// Step 1: Parse dependencies (quiet)
	mavenParser := parser.NewMavenParser(projectPath)
	depTree, err := mavenParser.ParseDependencies()
	if err != nil {
		return fmt.Errorf("failed to parse dependencies: %w", err)
	}

	// Step 2: Build call graph (quiet)
	builder := callgraph.NewBuilder(projectPath)

	// Set application packages if provided
	if len(appPackages) > 0 {
		builder.SetApplicationPackages(appPackages)
	}

	cg, err := builder.BuildCallGraph(depTree.Dependencies)
	if err != nil {
		return fmt.Errorf("failed to build call graph: %w", err)
	}

	// Step 3: Find reachable methods (quiet)
	reachable := builder.FindReachableMethods(cg, nil)

	if skipCVELookup {
		fmt.Println("Skipping CVE lookup (--skip-cve flag set)")
		return nil
	}

	// Step 4: Query CVE database (quiet)
	osvClient := cve.NewOSVClient()
	vulns, err := osvClient.GetVulnerabilitiesForDependencies(depTree.Dependencies)
	if err != nil {
		return fmt.Errorf("failed to query CVE database: %w", err)
	}

	totalVulns := 0
	for _, v := range vulns {
		totalVulns += len(v)
	}

	// Step 5: Perform triage analysis (quiet)
	analyzer := triage.NewAnalyzer(cg, reachable, vulns)
	results := analyzer.AnalyzeReachability()
	summary := analyzer.GetSummary(results)

	// Generate report
	reporter := triage.NewReporter(results, summary)

	var format triage.OutputFormat
	switch strings.ToLower(outputFormat) {
	case "json":
		format = triage.FormatJSON
	case "core":
		format = triage.FormatCore
	case "debug":
		format = triage.FormatDebug
	default:
		format = triage.FormatExecutive
	}

	if err := reporter.GenerateReport(os.Stdout, format); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}
