// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

func TestMavenParser_ParsePOM(t *testing.T) {
	tmpDir := t.TempDir()
	pomPath := filepath.Join(tmpDir, "pom.xml")

	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>`

	if err := os.WriteFile(pomPath, []byte(pomContent), 0644); err != nil {
		t.Fatalf("Failed to create test POM: %v", err)
	}

	parser := NewMavenParser(tmpDir)
	pom, err := parser.parsePOM(pomPath)
	if err != nil {
		t.Fatalf("Failed to parse POM: %v", err)
	}

	if pom.GroupID != "com.example" {
		t.Errorf("Expected groupId 'com.example', got '%s'", pom.GroupID)
	}

	if pom.ArtifactID != "test-app" {
		t.Errorf("Expected artifactId 'test-app', got '%s'", pom.ArtifactID)
	}

	if len(pom.Dependencies) != 1 {
		t.Errorf("Expected 1 dependency, got %d", len(pom.Dependencies))
	}

	if len(pom.Dependencies) > 0 {
		dep := pom.Dependencies[0]
		if dep.GroupID != "junit" {
			t.Errorf("Expected dependency groupId 'junit', got '%s'", dep.GroupID)
		}
	}
}

func TestMavenParser_FindJARInLocalRepo(t *testing.T) {
	parser := NewMavenParser(".")

	dep := &models.Dependency{
		GroupID:    "junit",
		ArtifactID: "junit",
		Version:    "4.13.2",
	}

	jarPath := parser.findJARInLocalRepo(dep)

	if jarPath != "" {
		if !filepath.IsAbs(jarPath) {
			t.Errorf("Expected absolute path, got '%s'", jarPath)
		}
	}
}

func TestMavenParser_PropertiesAndVersionFallback(t *testing.T) {
	tmpDir := t.TempDir()
	pomPath := filepath.Join(tmpDir, "pom.xml")

	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>com.example.parent</groupId>
        <artifactId>my-parent</artifactId>
        <version>2.0.0</version>
    </parent>
    <artifactId>test-app</artifactId>
    <properties>
        <jackson.version>2.13.0</jackson.version>
        <nested.version>${jackson.version}-patch</nested.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>${jackson.version}</version>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>sibling</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>nested-test</artifactId>
            <version>${nested.version}</version>
        </dependency>
    </dependencies>
</project>`

	if err := os.WriteFile(pomPath, []byte(pomContent), 0644); err != nil {
		t.Fatalf("Failed to create test POM: %v", err)
	}

	parser := NewMavenParser(tmpDir)
	pom, err := parser.parsePOM(pomPath)
	if err != nil {
		t.Fatalf("Failed to parse POM: %v", err)
	}

	if pom.GetEffectiveGroupID() != "com.example.parent" {
		t.Errorf("Expected groupId 'com.example.parent', got '%s'", pom.GetEffectiveGroupID())
	}

	if pom.GetEffectiveVersion() != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got '%s'", pom.GetEffectiveVersion())
	}

	deps, err := parser.parseDependenciesFromPOM(pom)
	if err != nil {
		t.Fatalf("Failed to parse dependencies from POM: %v", err)
	}

	if len(deps.Dependencies) != 3 {
		t.Fatalf("Expected 3 dependencies, got %d", len(deps.Dependencies))
	}

	// 1. Check jackson-databind
	if deps.Dependencies[0].Version != "2.13.0" {
		t.Errorf("Expected jackson-databind version '2.13.0', got '%s'", deps.Dependencies[0].Version)
	}

	// 2. Check sibling (${project.version} -> parent version)
	if deps.Dependencies[1].Version != "2.0.0" {
		t.Errorf("Expected sibling version '2.0.0', got '%s'", deps.Dependencies[1].Version)
	}

	// 3. Check nested-test (${nested.version} -> ${jackson.version}-patch -> 2.13.0-patch)
	if deps.Dependencies[2].Version != "2.13.0-patch" {
		t.Errorf("Expected nested-test version '2.13.0-patch', got '%s'", deps.Dependencies[2].Version)
	}
}

func TestMavenParser_LocalRepoEnvOverride(t *testing.T) {
	customPath := "/tmp/custom-m2-repo-test"
	t.Setenv("MAVEN_REPO_LOCAL", customPath)

	repoPath := getLocalRepositoryPath()
	if repoPath != customPath {
		t.Errorf("Expected local repo path '%s', got '%s'", customPath, repoPath)
	}
}
