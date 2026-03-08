package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netshield-Enterprise/netshield-analyzer/internal/api"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/callgraph"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/cve"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/config"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/parser"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/telemetry"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/triage"
	"github.com/spf13/cobra"
)

var (
	projectPath   string
	outputFormat  string
	appPackages   []string
	entryPoints   []string
	skipCVELookup bool
	keyStdin      bool
	quiet         bool
	noProgress    bool
	summaryOnly   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netshield [flags]",
		Short: "NetShield Real Risk Analysis",
		Long: `NetShield analyzes Java projects to determine real exploitability of CVEs.
Stop wasting time on vulnerabilities that don't matter.

NetShield performs static reachability analysis on your Java project's
dependency graph to determine which CVEs are actually exploitable
through your application's code paths.

Examples:
  # Basic scan with application package filter
  netshield --packages com.yourcompany.app

  # Scan a specific project path
  netshield --project /path/to/project --packages com.yourcompany

  # Quiet mode for CI/CD (no progress output)
  netshield --packages com.yourcompany --quiet

  # Summary only (no individual CVE listing)
  netshield --packages com.yourcompany --summary-only

  # Minimal CI output (no progress, no CVE details)
  netshield --packages com.yourcompany --quiet --summary-only

  # Show progress steps but suppress per-dependency log
  netshield --packages com.yourcompany --no-progress

  # JSON output for programmatic consumption
  netshield --packages com.yourcompany --format json --quiet

  # Start the web dashboard
  netshield --serve --port 9090`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return config.InitResolver(keyStdin)
		},
		RunE: runAnalysis,
	}

	rootCmd.PersistentFlags().StringVarP(&projectPath, "project", "p", ".", "Path to the Java project")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "executive", "Output format: core, executive, debug, json")
	rootCmd.PersistentFlags().StringSliceVarP(&appPackages, "packages", "a", []string{}, "Application package prefixes (comma-separated)")
	rootCmd.PersistentFlags().StringSliceVarP(&entryPoints, "entry-points", "e", []string{}, "Custom entry points in format Package.Class.method(Signature)")
	rootCmd.PersistentFlags().BoolVar(&skipCVELookup, "skip-cve", false, "Skip CVE lookup (only build call graph)")
	rootCmd.PersistentFlags().BoolVar(&keyStdin, "key-stdin", false, "Read API key securely from stdin to avoid /proc snooping")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress all progress output (stderr)")
	rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Suppress per-dependency CVE query log (keep step headers)")
	rootCmd.PersistentFlags().BoolVar(&summaryOnly, "summary-only", false, "Show executive summary only, omit individual CVE details")

	// Web UI flags
	rootCmd.Flags().Bool("serve", false, "Start web UI server instead of CLI analysis")
	rootCmd.Flags().Int("port", 8080, "Web UI server port (use with --serve)")

	// Monitor command
	monitorCmd := &cobra.Command{
		Use:   "monitor",
		Short: "Scan and upload results to NetShield dashboard",
		RunE:  runMonitor,
	}
	rootCmd.AddCommand(monitorCmd)

	// Config command
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configure NetShield settings",
		RunE:  runConfig,
	}
	configCmd.Flags().String("server", "", "Dashboard server URL")
	rootCmd.AddCommand(configCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runAnalysis(cmd *cobra.Command, args []string) error {
	// Check if we should start the web UI server
	serveMode, _ := cmd.Flags().GetBool("serve")
	if serveMode {
		port, _ := cmd.Flags().GetInt("port")
		return runWebServer(port)
	}

	// Step 1: Parse dependencies
	if !quiet {
		fmt.Fprintf(os.Stderr, "[1/5] Parsing dependencies...\n")
	}
	mavenParser := parser.NewMavenParser(projectPath)
	depTree, err := mavenParser.ParseDependencies()
	if err != nil {
		return fmt.Errorf("failed to parse dependencies: %w", err)
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "  Found %d dependencies\n", len(depTree.Dependencies))
	}

	// Step 2: Build call graph
	if !quiet {
		fmt.Fprintf(os.Stderr, "[2/5] Building call graph (%d dependencies)...\n", len(depTree.Dependencies))
	}
	builder := callgraph.NewBuilder(projectPath)

	// Set application packages if provided
	if len(appPackages) > 0 {
		builder.SetApplicationPackages(appPackages)
	}

	cg, err := builder.BuildCallGraph(depTree.Dependencies)
	if err != nil {
		return fmt.Errorf("failed to build call graph: %w", err)
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "  Call graph: %d nodes, %d edges\n", len(cg.Nodes), len(cg.Edges))
	}

	// Step 3: Find reachable methods
	if !quiet {
		fmt.Fprintf(os.Stderr, "[3/5] Finding reachable methods...\n")
	}
	reachable := builder.FindReachableMethods(cg, entryPoints)
	if !quiet {
		fmt.Fprintf(os.Stderr, "  %d reachable methods identified\n", len(reachable))
	}

	if skipCVELookup {
		fmt.Println("Skipping CVE lookup (--skip-cve flag set)")
		return nil
	}

	// Step 4: Query CVE database
	if !quiet {
		fmt.Fprintf(os.Stderr, "[4/5] Querying CVE database (%d dependencies)...\n", len(depTree.Dependencies))
	}
	osvClient := cve.NewOSVClient()
	osvClient.Quiet = quiet || noProgress
	vulns, err := osvClient.GetVulnerabilitiesForDependencies(depTree.Dependencies)
	if err != nil {
		return fmt.Errorf("failed to query CVE database: %w", err)
	}

	totalVulns := 0
	for _, v := range vulns {
		totalVulns += len(v)
	}

	// Step 5: Perform triage analysis
	if !quiet {
		fmt.Fprintf(os.Stderr, "[5/5] Analyzing reachability...\n")
	}
	analyzer := triage.NewAnalyzer(cg, reachable, vulns)
	results := analyzer.AnalyzeReachability()
	summary := analyzer.GetSummary(results)

	// Generate report
	reporter := triage.NewReporter(results, summary, summaryOnly)

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

	// Fire async telemetry to platform API
	decision := "SAFE_TO_SHIP"
	if summary.Reachable > 0 {
		decision = "BLOCK"
	}
	repoName := filepath.Base(projectPath)
	if repoName == "." {
		if dir, err := os.Getwd(); err == nil {
			repoName = filepath.Base(dir)
		}
	}
	tlmWg := telemetry.Send(telemetry.Payload{
		ToolName:      "analyzer",
		Repo:          repoName,
		Decision:      decision,
		FindingCount:  totalVulns,
		BlockingCount: summary.Reachable,
		Metadata: map[string]interface{}{
			"unreachable": summary.Unreachable,
			"unknown":     summary.Unknown,
		},
	})
	defer telemetry.WaitWithTimeout(tlmWg, telemetry.DefaultTimeout)

	// Exit codes for CI/CD integration:
	// 0 = Safe to ship (no reachable vulnerabilities)
	// 1 = Reachable vulnerability detected (block deployment)
	// 2 = Analysis failure (handled by cobra error handling above)

	if summary.Reachable > 0 {
		// Reachable vulnerabilities found - fail the build
		os.Exit(1)
	}

	// Safe to ship
	return nil
}

// runWebServer starts the web UI server
func runWebServer(port int) error {
	fmt.Printf("🚀 NetShield Web UI starting on http://localhost:%d\n", port)
	fmt.Printf("📁 Project: %s\n", projectPath)
	if len(appPackages) > 0 {
		fmt.Printf("📦 Packages: %s\n", strings.Join(appPackages, ", "))
	}
	fmt.Println("\n💡 Tip: Open your browser and navigate to the URL above")
	fmt.Println("   API endpoints:")
	fmt.Println("   - POST /api/analyze       - Run analysis")
	fmt.Println("   - GET  /api/summary       - Get summary")
	fmt.Println("   - GET  /api/vulnerabilities - Get vulnerabilities")
	fmt.Println("   - GET  /api/callgraph     - Get call graph")
	fmt.Println("")

	server := api.NewServer(projectPath, appPackages)
	addr := fmt.Sprintf(":%d", port)
	return http.ListenAndServe(addr, server.Router())
}

// --- Monitor Command ---

func runMonitor(cmd *cobra.Command, args []string) error {
	// 1. Load config (server URL)
	cfg := loadConfig()
	serverURL := cfg.ServerURL
	if serverURL == "" {
		serverURL = os.Getenv("NETSHIELD_SERVER")
	}
	if serverURL == "" {
		return fmt.Errorf("dashboard server URL not configured. Run 'netshield config --server <url>' first")
	}

	// Security warning for HTTP
	if strings.HasPrefix(serverURL, "http://") && !strings.Contains(serverURL, "localhost") && !strings.Contains(serverURL, "127.0.0.1") {
		fmt.Println("⚠️  WARNING: You are connecting to a remote server over HTTP. Your license key (auth token) will be sent in plaintext.")
		fmt.Println("   Please use HTTPS for production deployments to prevent credential theft.")
		fmt.Println("")
	}

	fmt.Printf("🔍 Scanning %s...\n", projectPath)

	// 2. Run analysis pipeline
	mavenParser := parser.NewMavenParser(projectPath)
	depTree, err := mavenParser.ParseDependencies()
	if err != nil {
		return fmt.Errorf("parse dependencies failed: %w", err)
	}

	builder := callgraph.NewBuilder(projectPath)
	if len(appPackages) > 0 {
		builder.SetApplicationPackages(appPackages)
	}
	cg, err := builder.BuildCallGraph(depTree.Dependencies)
	if err != nil {
		return fmt.Errorf("build call graph failed: %w", err)
	}

	reachable := builder.FindReachableMethods(cg, entryPoints)

	osvClient := cve.NewOSVClient()
	vulns, err := osvClient.GetVulnerabilitiesForDependencies(depTree.Dependencies)
	if err != nil {
		return fmt.Errorf("cve lookup failed: %w", err)
	}

	analyzer := triage.NewAnalyzer(cg, reachable, vulns)
	results := analyzer.AnalyzeReachability()
	summary := analyzer.GetSummary(results)

	// 3. Prepare payload
	payload := map[string]interface{}{
		"project_path":    projectPath, // In real usage, this might be a git remote URL or project name
		"summary":         summary,
		"vulnerabilities": results,
	}

	// 4. Upload
	return uploadScan(serverURL, payload)
}

func uploadScan(serverURL string, payload interface{}) error {
	// Get license key (auth token)
	// We use list.GetLicenseFromEnv() but we need the raw key string for the header.
	// GetLicenseFromEnv follows the priority: env -> file -> free.
	// If it falls back to free (empty key), upload will fail (authentication required).

	key := os.Getenv("NETSHIELD_LICENSE_KEY")
	if key == "" {
		// Try reading from file directly
		home, _ := os.UserHomeDir()
		data, _ := os.ReadFile(filepath.Join(home, ".netshield", "active_key"))
		key = strings.TrimSpace(string(data))
	}

	if key == "" {
		return fmt.Errorf("no license key found. Activate license via 'netshield --serve' first or set NETSHIELD_LICENSE_KEY")
	}

	jsonData, _ := json.Marshal(payload)
	endpoint := strings.TrimRight(serverURL, "/") + "/api/upload"

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", key)

	fmt.Printf("☁️  Uploading to %s...\n", versionSafeURL(endpoint))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %s: %s", resp.Status, string(body))
	}

	var res struct {
		ScanID  string `json:"scan_id"`
		Org     string `json:"org"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("✅ Upload successful! (Scan ID: %s)\n", res.ScanID)
	fmt.Printf("🏢 Organization: %s\n", res.Org)
	fmt.Printf("📊 View report: %s/evidence?scan=%s\n", strings.TrimRight(serverURL, "/"), res.ScanID)
	return nil
}

func versionSafeURL(u string) string {
	// Simple helper to mask auth if it was in URL (not used here but good practice)
	return u
}

// --- Config Command ---

type Config struct {
	ServerURL string `json:"server_url"`
}

func runConfig(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	if server == "" {
		return fmt.Errorf("server URL is required (use --server)")
	}

	cfg := Config{ServerURL: server}
	data, _ := json.MarshalIndent(cfg, "", "  ")

	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".netshield")
	os.MkdirAll(configDir, 0755)
	configPath := filepath.Join(configDir, "config.json")

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("✅ Config saved to %s\n", configPath)
	return nil
}

func loadConfig() Config {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".netshield", "config.json")
	var cfg Config
	if data, err := os.ReadFile(configPath); err == nil {
		json.Unmarshal(data, &cfg)
	}
	return cfg
}
