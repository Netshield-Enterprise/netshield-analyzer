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
