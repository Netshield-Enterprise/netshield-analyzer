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

// MavenParser handles parsing of Maven projects
type MavenParser struct {
	projectPath string
}

// NewMavenParser creates a new Maven parser
func NewMavenParser(projectPath string) *MavenParser {
	return &MavenParser{
		projectPath: projectPath,
	}
}

// POM represents a simplified Maven POM structure
type POM struct {
	XMLName      xml.Name     `xml:"project"`
	GroupID      string       `xml:"groupId"`
	ArtifactID   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Dependencies []Dependency `xml:"dependencies>dependency"`
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
	cmd := exec.Command("mvn", "dependency:tree", "-DoutputType=text")
	cmd.Dir = mp.projectPath
	
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
			GroupID:    dep.GroupID,
			ArtifactID: dep.ArtifactID,
			Version:    dep.Version,
			Scope:      dep.Scope,
		}
		
		modelDep.JARPath = mp.findJARInLocalRepo(modelDep)
		tree.Dependencies = append(tree.Dependencies, modelDep)
	}

	return tree, nil
}

// findJARInLocalRepo attempts to locate the JAR file in the local Maven repository
func (mp *MavenParser) findJARInLocalRepo(dep *models.Dependency) string {
	// Default Maven local repository location
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	// Convert groupId to path (e.g., org.springframework -> org/springframework)
	groupPath := strings.ReplaceAll(dep.GroupID, ".", string(filepath.Separator))
	
	jarPath := filepath.Join(
		homeDir,
		".m2",
		"repository",
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
