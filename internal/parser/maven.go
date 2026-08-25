// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

package parser

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// Parent represents a Maven Parent POM reference
type Parent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Properties represents arbitrary XML property mappings
type Properties map[string]string

// UnmarshalXML implements custom unmarshaling for properties to handle arbitrary XML tags
func (p *Properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*p = make(map[string]string)
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch el := token.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &el); err != nil {
				return err
			}
			(*p)[el.Name.Local] = value
		case xml.EndElement:
			if el.Name == start.Name {
				return nil
			}
		}
	}
}

// MavenParser handles parsing of Maven projects
type MavenParser struct {
	projectPath   string
	localRepoPath string
	Debug         bool
}

// NewMavenParser creates a new Maven parser
func NewMavenParser(projectPath string) *MavenParser {
	return &MavenParser{
		projectPath:   projectPath,
		localRepoPath: getLocalRepositoryPath(),
	}
}

// debugLog prints debug information when Debug mode is enabled
func (mp *MavenParser) debugLog(format string, args ...interface{}) {
	if mp.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

// DependencyManagementEntry represents a managed dependency version
type DependencyManagementEntry struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// POM represents a simplified Maven POM structure
type POM struct {
	XMLName              xml.Name                 `xml:"project"`
	Parent               Parent                   `xml:"parent"`
	GroupID              string                   `xml:"groupId"`
	ArtifactID           string                   `xml:"artifactId"`
	Version              string                   `xml:"version"`
	Dependencies         []Dependency             `xml:"dependencies>dependency"`
	Properties           Properties               `xml:"properties"`
	DependencyManagement []DependencyManagementEntry `xml:"dependencyManagement>dependencies>dependency"`
}

// GetEffectiveGroupID returns GroupID or falls back to Parent GroupID
func (p *POM) GetEffectiveGroupID() string {
	if p.GroupID != "" {
		return p.GroupID
	}
	return p.Parent.GroupID
}

// GetEffectiveVersion returns Version or falls back to Parent Version
func (p *POM) GetEffectiveVersion() string {
	if p.Version != "" {
		return p.Version
	}
	return p.Parent.Version
}

// Dependency represents a Maven dependency in POM
type Dependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Classifier string `xml:"classifier"`
}

// ParseDependencies extracts the dependency tree from a Maven project
func (mp *MavenParser) ParseDependencies() (*models.DependencyTree, error) {
	pomPath := filepath.Join(mp.projectPath, "pom.xml")
	
	// Check if pom.xml exists
	if _, err := os.Stat(pomPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("pom.xml not found at %s", pomPath)
	}

	// Parse POM file
	pom, err := mp.parsePOM(pomPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	// Get dependency tree using mvn command
	deps, err := mp.getDependencyTreeFromMaven()
	if err != nil {
		// Fallback to POM-only parsing if mvn command fails
		fmt.Fprintf(os.Stderr, "Warning: mvn dependency:tree failed, using POM-only parsing: %v\n", err)
		return mp.parseDependenciesFromPOM(pom)
	}

	// Resolve missing JARs by running mvn dependency:resolve
	// This downloads any JARs that aren't in the local cache yet
	mp.resolveMissingJARs(deps)

	return deps, nil
}

// resolveMissingJARs runs mvn dependency:resolve to download JARs that aren't cached locally
func (mp *MavenParser) resolveMissingJARs(deps *models.DependencyTree) {
	// Count how many JARs are missing
	missing := 0
	for _, dep := range deps.Dependencies {
		if dep.JARPath == "" {
			missing++
		}
	}
	if missing == 0 {
		return
	}

	mp.debugLog("%d JARs missing from local cache, running mvn dependency:resolve...", missing)

	mavenBin, err := mp.findMavenBinary()
	if err != nil {
		mp.debugLog("Cannot resolve missing JARs: %v", err)
		return
	}

	// Run mvn dependency:resolve to download all JARs
	cmd := exec.Command(mavenBin, "dependency:resolve", "-DincludeScope=compile,runtime")
	cmd.Dir = filepath.Clean(mp.projectPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		mp.debugLog("mvn dependency:resolve failed: %v", err)
		mp.debugLog("Output: %s", truncate(string(output), 1000))
		return
	}

	mp.debugLog("mvn dependency:resolve completed, re-resolving JAR paths...")

	// Re-resolve JAR paths for dependencies that were missing
	for _, dep := range deps.Dependencies {
		if dep.JARPath == "" {
			dep.JARPath = mp.findJARInLocalRepo(dep)
			if dep.JARPath != "" {
				mp.debugLog("Resolved JAR for %s:%s:%s -> %s", dep.GroupID, dep.ArtifactID, dep.Version, dep.JARPath)
			}
		}
	}
}

// parsePOM parses the pom.xml file
func (mp *MavenParser) parsePOM(pomPath string) (*POM, error) {
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, err
	}

	var pom POM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, err
	}

	return &pom, nil
}

// findMavenBinary locates the Maven executable, preferring mvnw if available.
// Returns the command name and any error if neither mvnw nor mvn is found.
func (mp *MavenParser) findMavenBinary() (string, error) {
	// Check for Maven wrapper in project directory (cross-platform)
	for _, wrapper := range []string{"mvnw", "mvnw.cmd"} {
		wrapperPath := filepath.Join(mp.projectPath, wrapper)
		if info, err := os.Stat(wrapperPath); err == nil && !info.IsDir() {
			// On Unix, ensure mvnw is executable
			if wrapper == "mvnw" {
				if err := os.Chmod(wrapperPath, info.Mode()|0111); err != nil {
					mp.debugLog("Could not chmod +x %s: %v", wrapperPath, err)
				}
			}
			// Return absolute path so exec.Command can find it
			absPath, err := filepath.Abs(wrapperPath)
			if err != nil {
				absPath = wrapperPath
			}
			mp.debugLog("Using Maven wrapper: %s", absPath)
			return absPath, nil
		}
	}

	// Fall back to system mvn
	if _, err := exec.LookPath("mvn"); err == nil {
		mp.debugLog("Using system Maven: mvn")
		return "mvn", nil
	}

	return "", fmt.Errorf("no Maven found: neither mvnw wrapper in %s nor mvn on PATH", mp.projectPath)
}

// getDependencyTreeFromMaven uses mvn dependency:tree to get full dependency graph
func (mp *MavenParser) getDependencyTreeFromMaven() (*models.DependencyTree, error) {
	mavenBin, err := mp.findMavenBinary()
	if err != nil {
		return nil, err
	}

	mp.debugLog("Running dependency tree with: %s", mavenBin)

	// Securely execute the Maven command without a shell
	// mp.projectPath is used as Dir, which is safe, and arguments are passed cleanly
	cmd := exec.Command(mavenBin, "dependency:tree", "-DoutputType=text")
	cmd.Dir = filepath.Clean(mp.projectPath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		mp.debugLog("Maven command failed: %v", err)
		mp.debugLog("Maven output (last 2000 chars): %s", truncate(string(output), 2000))
		return nil, fmt.Errorf("mvn command failed: %w, output: %s", err, truncate(string(output), 500))
	}

	mp.debugLog("Maven dependency tree output (%d bytes)", len(output))
	return mp.parseMavenTreeOutput(string(output))
}

// truncate shortens a string to maxLen characters, appending "..." if truncated
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[len(s)-maxLen:] + "..."
}

// parseMavenTreeOutput parses the output of mvn dependency:tree
func (mp *MavenParser) parseMavenTreeOutput(output string) (*models.DependencyTree, error) {
	tree := &models.DependencyTree{
		Dependencies: make([]*models.Dependency, 0),
	}

	// Regex to match dependency lines from mvn dependency:tree output.
	// Handles formats like:
	//   [INFO] +- org.springframework.boot:spring-boot-starter-web:jar:2.5.0:compile
	//   [INFO] |  \- com.querydsl:querydsl-jpa:jar:jakarta:5.0.0:compile
	//   [INFO] +- org.apache.commons:commons-lang3:3.14.0 (no classifier, no type)
	//   [INFO] +- com.thoughtworks.xstream:xstream:1.4.5
	//
	// The pattern handles optional type and classifier fields which Maven may or may not include.
	depRegex := regexp.MustCompile(`[\+\-\\\|]\s+([^:\s]+):([^:\s]+):([^:\s]+)(?::([^:\s]+))?(?::([^:\s]+))?(?::([^\s]+))?`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		matches := depRegex.FindStringSubmatch(line)
		if len(matches) < 4 {
			mp.debugLog("Line %d: no match: %s", lineNum, line)
			continue
		}

		dep := &models.Dependency{
			GroupID:    matches[1],
			ArtifactID: matches[2],
		}

		// Maven tree output formats:
		//   group:artifact:type:version:scope                    (standard)
		//   group:artifact:type:classifier:version:scope         (with classifier)
		//   group:artifact:version                                (minimal)
		// FindStringSubmatch always returns all capture groups (empty if unmatched).
		// Determine format by checking which groups are non-empty.
		switch {
		case matches[6] != "":
			// group:artifact:type:classifier:version:scope
			dep.Classifier = matches[4]
			dep.Version = matches[5]
			dep.Scope = matches[6]
		case matches[5] != "":
			// group:artifact:type:version:scope (standard Maven format)
			dep.Version = matches[4]
			dep.Scope = matches[5]
		case matches[4] != "":
			// group:artifact:type:version (no scope)
			dep.Version = matches[4]
			dep.Scope = "compile"
		default:
			// group:artifact:version (minimal)
			dep.Version = matches[3]
			dep.Scope = "compile"
		}

		// Skip dependencies with empty version (likely a BOM/pom import)
		if dep.Version == "" {
			mp.debugLog("Line %d: skipping dep with empty version: %s:%s", lineNum, dep.GroupID, dep.ArtifactID)
			continue
		}

		// Try to locate the JAR file in local Maven repository
		dep.JARPath = mp.findJARInLocalRepo(dep)

		if dep.JARPath == "" {
			mp.debugLog("Line %d: JAR not found for %s:%s:%s", lineNum, dep.GroupID, dep.ArtifactID, dep.Version)
		} else {
			mp.debugLog("Line %d: JAR resolved for %s:%s:%s -> %s", lineNum, dep.GroupID, dep.ArtifactID, dep.Version, dep.JARPath)
		}

		tree.Dependencies = append(tree.Dependencies, dep)
	}

	mp.debugLog("Parsed %d dependencies from Maven tree output", len(tree.Dependencies))
	return tree, nil
}

// parseDependenciesFromPOM fallback method to parse dependencies from POM only
func (mp *MavenParser) parseDependenciesFromPOM(pom *POM) (*models.DependencyTree, error) {
	tree := &models.DependencyTree{
		Dependencies: make([]*models.Dependency, 0),
	}

	// Build a lookup map from dependencyManagement for version resolution
	managedVersions := make(map[string]string)
	for _, managed := range pom.DependencyManagement {
		key := managed.GroupID + ":" + managed.ArtifactID
		managedVersions[key] = managed.Version
	}
	mp.debugLog("Parsed %d dependencyManagement entries", len(managedVersions))

	for _, dep := range pom.Dependencies {
		modelDep := &models.Dependency{
			GroupID:    resolveValue(dep.GroupID, pom),
			ArtifactID: resolveValue(dep.ArtifactID, pom),
			Version:    resolveValue(dep.Version, pom),
			Scope:      resolveValue(dep.Scope, pom),
			Classifier: resolveValue(dep.Classifier, pom),
		}

		// If version is empty, try to resolve from dependencyManagement
		if modelDep.Version == "" {
			depKey := modelDep.GroupID + ":" + modelDep.ArtifactID
			if managedVer, ok := managedVersions[depKey]; ok {
				modelDep.Version = resolveValue(managedVer, pom)
				mp.debugLog("Resolved version for %s from dependencyManagement: %s", depKey, modelDep.Version)
			}
		}

		// If version is still empty but parent has a version, some Maven conventions
		// allow inheriting the parent version — but only for BOM-like patterns.
		// We don't blindly apply parent version to avoid false JAR lookups.

		// Skip dependencies with no version (can't resolve JAR)
		if modelDep.Version == "" {
			mp.debugLog("Skipping %s:%s (no version resolved)", modelDep.GroupID, modelDep.ArtifactID)
			continue
		}

		modelDep.JARPath = mp.findJARInLocalRepo(modelDep)
		tree.Dependencies = append(tree.Dependencies, modelDep)
	}

	mp.debugLog("POM fallback parsed %d dependencies", len(tree.Dependencies))
	return tree, nil
}

// findJARInLocalRepo attempts to locate the JAR file in the local Maven repository
func (mp *MavenParser) findJARInLocalRepo(dep *models.Dependency) string {
	if mp.localRepoPath == "" {
		mp.debugLog("findJAR: localRepoPath is empty, cannot resolve %s:%s", dep.GroupID, dep.ArtifactID)
		return ""
	}

	// Convert groupId to path (e.g., org.springframework -> org/springframework)
	groupPath := strings.ReplaceAll(dep.GroupID, ".", string(filepath.Separator))
	
	jarFileName := dep.ArtifactID + "-" + dep.Version
	if dep.Classifier != "" {
		jarFileName += "-" + dep.Classifier
	}
	jarFileName += ".jar"

	jarPath := filepath.Join(
		mp.localRepoPath,
		groupPath,
		dep.ArtifactID,
		dep.Version,
		jarFileName,
	)

	mp.debugLog("findJAR: looking for %s", jarPath)

	// Check if file exists
	if _, err := os.Stat(jarPath); err == nil {
		return jarPath
	} else {
		mp.debugLog("findJAR: stat failed for %s: %v", jarPath, err)
	}

	return ""
}

// getLocalRepositoryPath retrieves the Maven local repository path, respecting custom configurations.
func getLocalRepositoryPath() string {
	// 1. Check environment variable override
	if envPath := os.Getenv("MAVEN_REPO_LOCAL"); envPath != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG] Local repo from env MAVEN_REPO_LOCAL: %s\n", filepath.Clean(envPath))
		return filepath.Clean(envPath)
	}

	// 2. Check ~/.m2/settings.xml for custom localRepository path
	homeDir, err := os.UserHomeDir()
	if err == nil {
		settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")
		if _, err := os.Stat(settingsPath); err == nil {
			if data, err := os.ReadFile(settingsPath); err == nil {
				var settings struct {
					LocalRepository string `xml:"localRepository"`
				}
				if err := xml.Unmarshal(data, &settings); err == nil && settings.LocalRepository != "" {
					repoPath := settings.LocalRepository
					// Expand ~ or ${user.home} if present
					if strings.HasPrefix(repoPath, "~") {
						repoPath = filepath.Join(homeDir, repoPath[1:])
					}
					if strings.Contains(repoPath, "${user.home}") {
						repoPath = strings.ReplaceAll(repoPath, "${user.home}", homeDir)
					}
					cleaned := filepath.Clean(repoPath)
					fmt.Fprintf(os.Stderr, "[DEBUG] Local repo from settings.xml: %s\n", cleaned)
					return cleaned
				}
			}
		}
	}

	// Default fallback
	if homeDir != "" {
		defaultPath := filepath.Join(homeDir, ".m2", "repository")
		fmt.Fprintf(os.Stderr, "[DEBUG] Local repo (default): %s\n", defaultPath)
		return defaultPath
	}
	return ""
}

var propRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// resolveValue resolves placeholders like ${jackson.version} using the POM properties.
func resolveValue(val string, pom *POM) string {
	// Limit recursion/iterations to avoid infinite loops
	for i := 0; i < 5; i++ {
		matches := propRegex.FindAllStringSubmatch(val, -1)
		if len(matches) == 0 {
			break
		}
		
		replacedAny := false
		for _, match := range matches {
			placeholder := match[0]
			propName := match[1]
			
			var replacement string
			found := false
			
			switch propName {
			case "project.version", "version":
				replacement = pom.GetEffectiveVersion()
				found = true
			case "project.groupId", "groupId":
				replacement = pom.GetEffectiveGroupID()
				found = true
			case "project.artifactId", "artifactId":
				replacement = pom.ArtifactID
				found = true
			default:
				if propVal, ok := pom.Properties[propName]; ok {
					replacement = propVal
					found = true
				}
			}
			
			if found {
				val = strings.ReplaceAll(val, placeholder, replacement)
				replacedAny = true
			}
		}
		if !replacedAny {
			break
		}
	}
	return val
}
