// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

// Package database provides SQLite storage for scan history and vulnerability trends.
package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite database connection
type DB struct {
	conn *sql.DB
	path string
}

// Scan represents a stored analysis scan
type Scan struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"` // Tenant isolation
	ProjectPath string    `json:"project_path"`
	Timestamp   time.Time `json:"timestamp"`
	TotalVulns  int       `json:"total_vulns"`
	Reachable   int       `json:"reachable"`
	Unreachable int       `json:"unreachable"`
	SummaryJSON string    `json:"summary_json,omitempty"`
}

// TrendPoint represents a single data point for vulnerability trends
type TrendPoint struct {
	Date        string `json:"date"`
	TotalVulns  int    `json:"total_vulns"`
	Reachable   int    `json:"reachable"`
	Unreachable int    `json:"unreachable"`
}

// Open opens or creates the SQLite database in the project directory
func Open(projectPath string) (*DB, error) {
	// Sanitize path to prevent directory traversal
	cleanPath := filepath.Clean(projectPath)
	dbPath := filepath.Join(cleanPath, ".netshield", "data.db")

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{conn: conn, path: dbPath}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

// migrate creates the database schema
func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		org_id TEXT DEFAULT '',
		project_path TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		total_vulns INTEGER DEFAULT 0,
		reachable INTEGER DEFAULT 0,
		unreachable INTEGER DEFAULT 0,
		summary_json TEXT
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		cve_id TEXT,
		package TEXT,
		status TEXT,
		severity TEXT,
		FOREIGN KEY (scan_id) REFERENCES scans(id)
	);

	CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_path);
	CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
	CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
	`

	if _, err := db.conn.Exec(schema); err != nil {
		return err
	}

	// Migration: ensure org_id column exists (safe to run multiple times)
	// Ignore error (it fails if column already exists)
	_, _ = db.conn.Exec(`ALTER TABLE scans ADD COLUMN org_id TEXT DEFAULT ''`)

	return nil
}

// SaveScan saves a scan result to the database
func (db *DB) SaveScan(scan *Scan) error {
	query := `
	INSERT INTO scans (id, org_id, project_path, timestamp, total_vulns, reachable, unreachable, summary_json)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := db.conn.Exec(query,
		scan.ID,
		scan.OrgID,
		scan.ProjectPath,
		scan.Timestamp,
		scan.TotalVulns,
		scan.Reachable,
		scan.Unreachable,
		scan.SummaryJSON,
	)
	return err
}

// GetScan retrieves a scan by ID
func (db *DB) GetScan(id string) (*Scan, error) {
	query := `SELECT id, project_path, timestamp, total_vulns, reachable, unreachable, summary_json FROM scans WHERE id = ?`

	scan := &Scan{}
	err := db.conn.QueryRow(query, id).Scan(
		&scan.ID,
		&scan.ProjectPath,
		&scan.Timestamp,
		&scan.TotalVulns,
		&scan.Reachable,
		&scan.Unreachable,
		&scan.SummaryJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return scan, err
}

// ListScans returns all scans for a project, filtered by org and ordered by timestamp desc
func (db *DB) ListScans(orgID, projectPath string, limit int) ([]*Scan, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, org_id, project_path, timestamp, total_vulns, reachable, unreachable FROM scans WHERE project_path = ? AND org_id = ? ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.conn.Query(query, projectPath, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*Scan
	for rows.Next() {
		scan := &Scan{}
		if err := rows.Scan(&scan.ID, &scan.OrgID, &scan.ProjectPath, &scan.Timestamp, &scan.TotalVulns, &scan.Reachable, &scan.Unreachable); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, rows.Err()
}

// GetTrends returns vulnerability trends for the last N days, filtered by org
func (db *DB) GetTrends(orgID, projectPath string, days int) ([]*TrendPoint, error) {
	if days <= 0 {
		days = 30
	}

	query := `
	SELECT DATE(timestamp) as date, 
		   MAX(total_vulns) as total, 
		   MAX(reachable) as reachable, 
		   MAX(unreachable) as unreachable
	FROM scans 
	WHERE project_path = ? AND org_id = ? AND timestamp >= datetime('now', ?)
	GROUP BY DATE(timestamp)
	ORDER BY date ASC
	`

	daysAgo := fmt.Sprintf("-%d days", days)
	rows, err := db.conn.Query(query, projectPath, orgID, daysAgo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []*TrendPoint
	for rows.Next() {
		point := &TrendPoint{}
		if err := rows.Scan(&point.Date, &point.TotalVulns, &point.Reachable, &point.Unreachable); err != nil {
			return nil, err
		}
		trends = append(trends, point)
	}
	return trends, rows.Err()
}

// SaveVulnerability saves a vulnerability for a scan
func (db *DB) SaveVulnerability(scanID, cveID, pkg, status, severity string) error {
	query := `INSERT INTO vulnerabilities (scan_id, cve_id, package, status, severity) VALUES (?, ?, ?, ?, ?)`
	_, err := db.conn.Exec(query, scanID, cveID, pkg, status, severity)
	return err
}

// GenerateScanID creates a unique scan ID
func GenerateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}

// MarshalSummary converts a summary to JSON string
func MarshalSummary(summary interface{}) string {
	b, _ := json.Marshal(summary)
	return string(b)
}

// ScanVuln represents a vulnerability record from a scan
type ScanVuln struct {
	CveID    string `json:"cve_id"`
	Package  string `json:"package"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
}

// ScanDiff represents the difference between two scans
type ScanDiff struct {
	CurrentScanID  string      `json:"current_scan_id"`
	PreviousScanID string      `json:"previous_scan_id"`
	NewVulns       []*ScanVuln `json:"new"`
	FixedVulns     []*ScanVuln `json:"fixed"`
	CurrentTotal   int         `json:"current_total"`
	PreviousTotal  int         `json:"previous_total"`
	RiskDelta      string      `json:"risk_delta"`
}

// GetVulnerabilitiesForScan returns all vulnerabilities for a given scan
func (db *DB) GetVulnerabilitiesForScan(scanID string) ([]*ScanVuln, error) {
	query := `SELECT cve_id, package, status, severity FROM vulnerabilities WHERE scan_id = ?`
	rows, err := db.conn.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []*ScanVuln
	for rows.Next() {
		v := &ScanVuln{}
		if err := rows.Scan(&v.CveID, &v.Package, &v.Status, &v.Severity); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, rows.Err()
}

// DiffScans compares the two most recent scans for a project, filtered by org
func (db *DB) DiffScans(orgID, projectPath string) (*ScanDiff, error) {
	scans, err := db.ListScans(orgID, projectPath, 2)
	if err != nil {
		return nil, err
	}
	if len(scans) < 2 {
		return nil, nil // Not enough scans to diff
	}

	current := scans[0]
	previous := scans[1]

	currentVulns, err := db.GetVulnerabilitiesForScan(current.ID)
	if err != nil {
		return nil, err
	}
	previousVulns, err := db.GetVulnerabilitiesForScan(previous.ID)
	if err != nil {
		return nil, err
	}

	// Build lookup maps by cve_id
	prevMap := make(map[string]*ScanVuln)
	for _, v := range previousVulns {
		prevMap[v.CveID] = v
	}
	currMap := make(map[string]*ScanVuln)
	for _, v := range currentVulns {
		currMap[v.CveID] = v
	}

	// New = in current but not in previous
	var newVulns []*ScanVuln
	for _, v := range currentVulns {
		if _, found := prevMap[v.CveID]; !found {
			newVulns = append(newVulns, v)
		}
	}

	// Fixed = in previous but not in current
	var fixedVulns []*ScanVuln
	for _, v := range previousVulns {
		if _, found := currMap[v.CveID]; !found {
			fixedVulns = append(fixedVulns, v)
		}
	}

	delta := "stable"
	if current.Reachable > previous.Reachable {
		delta = "increasing"
	} else if current.Reachable < previous.Reachable {
		delta = "decreasing"
	}

	return &ScanDiff{
		CurrentScanID:  current.ID,
		PreviousScanID: previous.ID,
		NewVulns:       newVulns,
		FixedVulns:     fixedVulns,
		CurrentTotal:   current.TotalVulns,
		PreviousTotal:  previous.TotalVulns,
		RiskDelta:      delta,
	}, nil
}
