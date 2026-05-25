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
}

// NewMavenParser creates a new Maven parser
func NewMavenParser(projectPath string) *MavenParser {
	return &MavenParser{
		projectPath:   projectPath,
		localRepoPath: getLocalRepositoryPath(),
	}
}

// POM represents a simplified Maven POM structure
type POM struct {
	XMLName      xml.Name     `xml:"project"`
	Parent       Parent       `xml:"parent"`
	GroupID      string       `xml:"groupId"`
	ArtifactID   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Dependencies []Dependency `xml:"dependencies>dependency"`
	Properties   Properties   `xml:"properties"`
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

	return deps, nil
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

// getDependencyTreeFromMaven uses mvn dependency:tree to get full dependency graph
func (mp *MavenParser) getDependencyTreeFromMaven() (*models.DependencyTree, error) {
	// Securely execute the Maven command without a shell
	// mp.projectPath is used as Dir, which is safe, and arguments are passed cleanly
	cmd := exec.Command("mvn", "dependency:tree", "-DoutputType=text")
	cmd.Dir = filepath.Clean(mp.projectPath)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("mvn command failed: %w, output: %s", err, string(output))
	}

	return mp.parseMavenTreeOutput(string(output))
}

// parseMavenTreeOutput parses the output of mvn dependency:tree
func (mp *MavenParser) parseMavenTreeOutput(output string) (*models.DependencyTree, error) {
	tree := &models.DependencyTree{
		Dependencies: make([]*models.Dependency, 0),
	}

	// Regex to match dependency lines like:
	// [INFO] +- org.springframework.boot:spring-boot-starter-web:jar:2.5.0:compile
	depRegex := regexp.MustCompile(`[\+\-\\\|]\s+([^:]+):([^:]+):([^:]+):([^:]+):([^\s]+)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		
		matches := depRegex.FindStringSubmatch(line)
		if len(matches) == 6 {
			dep := &models.Dependency{
				GroupID:    matches[1],
				ArtifactID: matches[2],
				Version:    matches[4],
				Scope:      matches[5],
			}
			
			// Try to locate the JAR file in local Maven repository
			dep.JARPath = mp.findJARInLocalRepo(dep)
			
			tree.Dependencies = append(tree.Dependencies, dep)
		}
	}

	return tree, nil
}

// parseDependenciesFromPOM fallback method to parse dependencies from POM only
func (mp *MavenParser) parseDependenciesFromPOM(pom *POM) (*models.DependencyTree, error) {
	tree := &models.DependencyTree{
		Dependencies: make([]*models.Dependency, 0),
	}

	for _, dep := range pom.Dependencies {
		modelDep := &models.Dependency{
			GroupID:    resolveValue(dep.GroupID, pom),
			ArtifactID: resolveValue(dep.ArtifactID, pom),
			Version:    resolveValue(dep.Version, pom),
			Scope:      resolveValue(dep.Scope, pom),
		}
		
		modelDep.JARPath = mp.findJARInLocalRepo(modelDep)
		tree.Dependencies = append(tree.Dependencies, modelDep)
	}

	return tree, nil
}

// findJARInLocalRepo attempts to locate the JAR file in the local Maven repository
func (mp *MavenParser) findJARInLocalRepo(dep *models.Dependency) string {
	if mp.localRepoPath == "" {
		return ""
	}

	// Convert groupId to path (e.g., org.springframework -> org/springframework)
	groupPath := strings.ReplaceAll(dep.GroupID, ".", string(filepath.Separator))
	
	jarPath := filepath.Join(
		mp.localRepoPath,
		groupPath,
		dep.ArtifactID,
		dep.Version,
		fmt.Sprintf("%s-%s.jar", dep.ArtifactID, dep.Version),
	)

	// Check if file exists
	if _, err := os.Stat(jarPath); err == nil {
		return jarPath
	}

	return ""
}

// getLocalRepositoryPath retrieves the Maven local repository path, respecting custom configurations.
func getLocalRepositoryPath() string {
	// 1. Check environment variable override
	if envPath := os.Getenv("MAVEN_REPO_LOCAL"); envPath != "" {
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
					return filepath.Clean(repoPath)
				}
			}
		}
	}

	// Default fallback
	if homeDir != "" {
		return filepath.Join(homeDir, ".m2", "repository")
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
