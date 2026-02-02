package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Netshield-Enterprise/netshield-analyzer/internal/bytecode"
	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// Builder constructs call graphs from application code and dependencies
type Builder struct {
	projectPath string
	appPackages []string // Application package prefixes
}

// NewBuilder creates a new call graph builder
func NewBuilder(projectPath string) *Builder {
	return &Builder{
		projectPath: projectPath,
		appPackages: make([]string, 0),
	}
}

// SetApplicationPackages sets the package prefixes for application code
func (b *Builder) SetApplicationPackages(packages []string) {
	b.appPackages = packages
}

// BuildCallGraph builds a complete call graph from application and dependencies
func (b *Builder) BuildCallGraph(dependencies []*models.Dependency) (*models.CallGraph, error) {
	cg := models.NewCallGraph()

	// First, analyze application code
	appJARs, err := b.findApplicationJARs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to find application JARs: %v\n", err)
	}

	for _, jarPath := range appJARs {
		analyzer := bytecode.NewJARAnalyzer(jarPath)
		classes, err := analyzer.AnalyzeJAR()
		if err != nil {
			continue
		}

		b.addClassesToCallGraph(cg, classes, false)
	}

	// Then, analyze dependencies
	for _, dep := range dependencies {
		if dep.JARPath == "" {
			continue
		}

		analyzer := bytecode.NewJARAnalyzer(dep.JARPath)
		classes, err := analyzer.AnalyzeJAR()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to analyze JAR %s: %v\n", dep.JARPath, err)
			continue
		}

		b.addClassesToCallGraph(cg, classes, true)
	}

	return cg, nil
}

// addClassesToCallGraph adds classes and their methods to the call graph
func (b *Builder) addClassesToCallGraph(cg *models.CallGraph, classes []*bytecode.ClassFile, isExternal bool) {
	for _, class := range classes {
		// Determine if this is application code or external
		isAppCode := !isExternal && b.isApplicationClass(class.ClassName)

		for _, method := range class.Methods {
			methodID := models.GetMethodID(class.ClassName, method.Name, method.Descriptor)

			// Add method node
			node := &models.MethodNode{
				ClassName:  class.ClassName,
				MethodName: method.Name,
				Signature:  method.Descriptor,
				IsExternal: !isAppCode,
				Package:    b.extractPackage(class.ClassName),
			}

			cg.AddNode(methodID, node)

			// Add edges for method calls
			for _, call := range method.Calls {
				calleeID := models.GetMethodID(call.ClassName, call.MethodName, call.Descriptor)
				cg.AddEdge(methodID, calleeID)
			}
		}
	}
}

// findApplicationJARs finds compiled JAR files in the project
func (b *Builder) findApplicationJARs() ([]string, error) {
	jars := make([]string, 0)

	// Look in target directory for Maven projects
	targetDir := filepath.Join(b.projectPath, "target")
	if _, err := os.Stat(targetDir); err == nil {
		filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, ".jar") {
				// Skip test JARs and sources JARs
				if !strings.Contains(path, "tests") && !strings.Contains(path, "sources") {
					jars = append(jars, path)
				}
			}
			return nil
		})
	}

	// Look in build directory for Gradle projects
	buildDir := filepath.Join(b.projectPath, "build", "libs")
	if _, err := os.Stat(buildDir); err == nil {
		filepath.Walk(buildDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, ".jar") {
				jars = append(jars, path)
			}
			return nil
		})
	}

	return jars, nil
}

// isApplicationClass determines if a class is part of the application code
func (b *Builder) isApplicationClass(className string) bool {
	// Convert class name from internal format (com/example/App) to package format (com.example)
	packageName := strings.ReplaceAll(className, "/", ".")

	for _, appPkg := range b.appPackages {
		if strings.HasPrefix(packageName, appPkg) {
			return true
		}
	}

	return false
}

// extractPackage extracts package name from class name
func (b *Builder) extractPackage(className string) string {
	lastSlash := strings.LastIndex(className, "/")
	if lastSlash == -1 {
		return ""
	}
	return strings.ReplaceAll(className[:lastSlash], "/", ".")
}

// FindReachableMethods performs a reachability analysis from entry points
func (b *Builder) FindReachableMethods(cg *models.CallGraph, entryPoints []string) map[string]bool {
	reachable := make(map[string]bool)
	visited := make(map[string]bool)

	// If no entry points specified, find common entry points
	if len(entryPoints) == 0 {
		entryPoints = b.findCommonEntryPoints(cg)
	}

	// DFS from each entry point
	for _, entry := range entryPoints {
		b.dfsReachability(cg, entry, reachable, visited)
	}

	return reachable
}

// dfsReachability performs depth-first search to find reachable methods
func (b *Builder) dfsReachability(cg *models.CallGraph, methodID string, reachable, visited map[string]bool) {
	if visited[methodID] {
		return
	}

	visited[methodID] = true
	reachable[methodID] = true

	// Follow all outgoing edges
	for _, edge := range cg.Edges {
		if edge.From == methodID {
			b.dfsReachability(cg, edge.To, reachable, visited)
		}
	}
}

// findCommonEntryPoints finds common entry points in the call graph
func (b *Builder) findCommonEntryPoints(cg *models.CallGraph) []string {
	entryPoints := make([]string, 0)

	for id, node := range cg.Nodes {
		// Look for main methods
		if node.MethodName == "main" && node.Signature == "([Ljava/lang/String;)V" {
			entryPoints = append(entryPoints, id)
		}

		// Look for Spring Boot application classes
		if strings.Contains(node.ClassName, "Application") && node.MethodName == "main" {
			entryPoints = append(entryPoints, id)
		}

		// Look for servlet methods
		if node.MethodName == "doGet" || node.MethodName == "doPost" || node.MethodName == "service" {
			entryPoints = append(entryPoints, id)
		}

		// Look for Spring controller methods (heuristic: public methods in classes with "Controller")
		if strings.Contains(node.ClassName, "Controller") && node.MethodName != "<init>" {
			entryPoints = append(entryPoints, id)
		}
	}

	return entryPoints
}
