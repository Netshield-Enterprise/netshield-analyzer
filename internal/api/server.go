package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/Netshield-Enterprise/netshield-analyzer/internal/callgraph"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/cve"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/database"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/license"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/parser"
	"github.com/Netshield-Enterprise/netshield-analyzer/internal/triage"
	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// Server represents the HTTP API server
type Server struct {
	projectPath string
	appPackages []string
	license     *license.License
	db          *database.DB

	// Cache for analysis results
	cacheMu       sync.RWMutex
	cachedCG      *models.CallGraph
	cachedResults []*models.TriageResult
	cachedSummary *triage.TriageSummary
}

// NewServer creates a new API server
func NewServer(projectPath string, appPackages []string) *Server {
	// Open database (ignore errors, storage is optional)
	db, _ := database.Open(projectPath)

	return &Server{
		projectPath: projectPath,
		appPackages: appPackages,
		license:     license.GetLicenseFromEnv(),
		db:          db,
	}
}

// Router returns the HTTP router with all endpoints configured
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/analyze", s.handleAnalyze)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/vulnerabilities", s.handleVulnerabilities)
	mux.HandleFunc("/api/callgraph", s.handleCallGraph)
	mux.HandleFunc("/api/license", s.handleLicense)
	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/trends", s.handleTrends)
	mux.HandleFunc("/api/diff", s.handleDiff)
	mux.HandleFunc("/api/export", s.handleExport)
	mux.HandleFunc("/api/upload", s.handleUpload) // Remote monitor upload
	mux.HandleFunc("/api/health", s.handleHealth)

	// Serve static files (React build) - will be added later
	// mux.Handle("/", http.FileServer(http.Dir("./web/dist")))

	return corsMiddleware(mux)
}

// handleAnalyze runs full analysis and caches results
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse dependencies
	mavenParser := parser.NewMavenParser(s.projectPath)
	depTree, err := mavenParser.ParseDependencies()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to parse dependencies: %v", err),
		})
		return
	}

	// Build call graph
	builder := callgraph.NewBuilder(s.projectPath)
	if len(s.appPackages) > 0 {
		builder.SetApplicationPackages(s.appPackages)
	}

	cg, err := builder.BuildCallGraph(depTree.Dependencies)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to build call graph: %v", err),
		})
		return
	}

	// Find reachable methods
	reachable := builder.FindReachableMethods(cg, nil)

	// Query CVE database
	osvClient := cve.NewOSVClient()
	vulns, err := osvClient.GetVulnerabilitiesForDependencies(depTree.Dependencies)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to query CVE database: %v", err),
		})
		return
	}

	// Perform triage analysis
	analyzer := triage.NewAnalyzer(cg, reachable, vulns)
	results := analyzer.AnalyzeReachability()
	summary := analyzer.GetSummary(results)

	// Cache results
	s.cacheMu.Lock()
	s.cachedCG = cg
	s.cachedResults = results
	s.cachedSummary = summary
	s.cacheMu.Unlock()

	// Save to database if storage feature is available
	if s.db != nil && license.HasFeature(s.license, license.FeatureStorage) {
		scanID := database.GenerateScanID()
		absPath, _ := filepath.Abs(filepath.Clean(s.projectPath))
		scan := &database.Scan{
			ID:          scanID,
			ProjectPath: absPath,
			TotalVulns:  summary.Total,
			Reachable:   summary.Reachable,
			Unreachable: summary.Unreachable,
			SummaryJSON: database.MarshalSummary(summary),
		}
		if err := s.db.SaveScan(scan); err != nil {
			fmt.Printf("Warning: failed to save scan: %v\n", err)
		}

		// Save vulnerabilities
		for _, r := range results {
			s.db.SaveVulnerability(scanID, r.Vulnerability.ID, r.Vulnerability.AffectedPackage, string(r.Status), r.Vulnerability.Severity)
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"summary": summary,
	})
}

// handleSummary returns the cached summary
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	s.cacheMu.RLock()
	summary := s.cachedSummary
	s.cacheMu.RUnlock()

	if summary == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "No analysis results available. Run /api/analyze first.",
		})
		return
	}

	respondJSON(w, http.StatusOK, summary)
}

// handleVulnerabilities returns all vulnerability results
func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	s.cacheMu.RLock()
	results := s.cachedResults
	s.cacheMu.RUnlock()

	if results == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "No analysis results available. Run /api/analyze first.",
		})
		return
	}

	respondJSON(w, http.StatusOK, results)
}

// handleCallGraph returns the call graph (PREMIUM FEATURE)
func (s *Server) handleCallGraph(w http.ResponseWriter, r *http.Request) {
	// Check license for callgraph feature
	if !license.HasFeature(s.license, license.FeatureCallGraph) {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error":   "Call Graph is a premium feature",
			"tier":    string(s.license.Tier),
			"upgrade": "Set NETSHIELD_LICENSE_KEY environment variable with a Pro or Enterprise key",
		})
		return
	}

	s.cacheMu.RLock()
	cg := s.cachedCG
	s.cacheMu.RUnlock()

	if cg == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "No call graph available. Run /api/analyze first.",
		})
		return
	}

	respondJSON(w, http.StatusOK, cg)
}

// handleLicense returns current license (GET) or activates a new key (POST)
func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "license key is required"})
			return
		}

		// Validate the key — use license server if configured, otherwise local check
		newLic := license.ValidateKey(req.Key)
		if !newLic.IsValid {
			respondJSON(w, http.StatusOK, map[string]interface{}{
				"activated": false,
				"license":   newLic,
			})
			return
		}

		// Update in-memory license
		s.license = newLic
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"activated": true,
			"license":   newLic,
		})
		return
	}

	respondJSON(w, http.StatusOK, s.license)
}

// handleScans returns scan history (PREMIUM: requires storage feature)
func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if !license.HasFeature(s.license, license.FeatureStorage) {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error":   "Scan history is a premium feature",
			"tier":    string(s.license.Tier),
			"upgrade": "Set NETSHIELD_LICENSE_KEY with a Pro or Enterprise key",
		})
		return
	}

	if s.db == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Database not available",
		})
		return
	}

	absPath, _ := filepath.Abs(filepath.Clean(s.projectPath))
	orgID := s.getOrgID(r)
	scans, err := s.db.ListScans(orgID, absPath, 50)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to list scans: %v", err),
		})
		return
	}

	respondJSON(w, http.StatusOK, scans)
}

// handleTrends returns vulnerability trends (PREMIUM: requires storage feature)
func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	if !license.HasFeature(s.license, license.FeatureStorage) {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error":   "Trends analysis is a premium feature",
			"tier":    string(s.license.Tier),
			"upgrade": "Set NETSHIELD_LICENSE_KEY with a Pro or Enterprise key",
		})
		return
	}

	if s.db == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Database not available",
		})
		return
	}

	absPath, _ := filepath.Abs(filepath.Clean(s.projectPath))
	orgID := s.getOrgID(r)
	trends, err := s.db.GetTrends(orgID, absPath, 30)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to get trends: %v", err),
		})
		return
	}

	respondJSON(w, http.StatusOK, trends)
}

// handleDiff returns build-to-build vulnerability comparison (PREMIUM: requires storage feature)
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	if !license.HasFeature(s.license, license.FeatureStorage) {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error":   "Build comparison is a premium feature",
			"tier":    string(s.license.Tier),
			"upgrade": "Set NETSHIELD_LICENSE_KEY with a Pro or Enterprise key",
		})
		return
	}

	if s.db == nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "Database not available",
		})
		return
	}

	absPath, _ := filepath.Abs(filepath.Clean(s.projectPath))
	orgID := s.getOrgID(r)
	diff, err := s.db.DiffScans(orgID, absPath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to compute diff: %v", err),
		})
		return
	}

	if diff == nil {
		respondJSON(w, http.StatusOK, map[string]string{
			"message": "Not enough scan history for comparison. Run analysis at least twice.",
		})
		return
	}

	respondJSON(w, http.StatusOK, diff)
}

// handleExport exports analysis results as JSON (PREMIUM: requires export feature)
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !license.HasFeature(s.license, license.FeatureExport) {
		respondJSON(w, http.StatusForbidden, map[string]string{
			"error":   "JSON export is a premium feature",
			"tier":    string(s.license.Tier),
			"upgrade": "Set NETSHIELD_LICENSE_KEY with a Pro or Enterprise key",
		})
		return
	}

	s.cacheMu.RLock()
	results := s.cachedResults
	summary := s.cachedSummary
	s.cacheMu.RUnlock()

	if results == nil {
		respondJSON(w, http.StatusNotFound, map[string]string{
			"error": "No analysis results available. Run /api/analyze first.",
		})
		return
	}

	// Set download headers
	w.Header().Set("Content-Disposition", "attachment; filename=netshield-report.json")

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"summary":         summary,
		"vulnerabilities": results,
		"exported_at":     fmt.Sprintf("%v", time.Now().Format(time.RFC3339)),
	})
}

// handleUpload receives scan results from the CLI monitor command
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	// 1. Validate License Key (Auth)
	key := r.Header.Get("X-License-Key")
	if key == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing X-License-Key header"})
		return
	}

	lic := license.ValidateKey(key)
	if !lic.IsValid {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid license key"})
		return
	}

	// 2. Parse payload
	var req struct {
		ProjectPath     string      `json:"project_path"`
		Summary         interface{} `json:"summary"`
		Vulnerabilities []struct {
			CveID         string `json:"cve_id"`
			Package       string `json:"package"`
			Status        string `json:"status"`
			Vulnerability struct {
				Severity string `json:"severity"`
			} `json:"vulnerability"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	// 3. Save to DB
	scanID := database.GenerateScanID()
	scan := &database.Scan{
		ID:          scanID,
		OrgID:       lic.OrgName, // Strict identity from license!
		ProjectPath: req.ProjectPath,
		Timestamp:   time.Now(),
		SummaryJSON: database.MarshalSummary(req.Summary),
	}

	// Try to populate stats from summary object
	if sumMap, ok := req.Summary.(map[string]interface{}); ok {
		if val, k := sumMap["total_vulnerabilities"].(float64); k {
			scan.TotalVulns = int(val)
		}
		if val, k := sumMap["reachable_vulnerabilities"].(float64); k {
			scan.Reachable = int(val)
		}
		if val, k := sumMap["unreachable_vulnerabilities"].(float64); k {
			scan.Unreachable = int(val)
		}
	} else {
		// Fallback: calc from vulns array
		scan.TotalVulns = len(req.Vulnerabilities)
		for _, v := range req.Vulnerabilities {
			if v.Status == "REACHABLE" {
				scan.Reachable++
			} else if v.Status == "UNREACHABLE" {
				scan.Unreachable++
			}
		}
	}

	if err := s.db.SaveScan(scan); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "DB error saving scan"})
		return
	}

	for _, v := range req.Vulnerabilities {
		s.db.SaveVulnerability(scanID, v.CveID, v.Package, v.Status, v.Vulnerability.Severity)
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"scan_id": scanID,
		"org":     lic.OrgName,
		"message": "Scan uploaded successfully",
	})
}

// getOrgID determines the Tenant ID for the request.
func (s *Server) getOrgID(r *http.Request) string {
	// 1. Check header (CLI / monitor usage)
	key := r.Header.Get("X-License-Key")
	if key != "" {
		lic := license.ValidateKey(key)
		if lic.IsValid {
			return lic.OrgName
		}
	}

	// 2. Fallback to local active key (Browser usage)
	if s.license != nil && s.license.IsValid {
		return s.license.OrgName
	}

	// 3. No authed user/org -> return empty (local mode default)
	return ""
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"project": s.projectPath,
	})
}

// respondJSON writes JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// corsMiddleware adds CORS headers
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
