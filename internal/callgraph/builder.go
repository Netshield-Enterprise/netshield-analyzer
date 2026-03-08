package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Netshield-Enterprise/netshield-analyzer/internal/bytecode"
	"github.com/Netshield-Enterprise/netshield-analyzer/pkg/models"
)

// Builder constructs call graphs from application code and dependencies
type Builder struct {
	projectPath    string
	appPackages    []string // Application package prefixes
	classHierarchy map[string][]string
	classRegistry  map[string]*bytecode.ClassFile
	isExternalMap  map[string]bool
}

// NewBuilder creates a new call graph builder
func NewBuilder(projectPath string) *Builder {
	return &Builder{
		projectPath:    projectPath,
		appPackages:    make([]string, 0),
		classHierarchy: make(map[string][]string),
		classRegistry:  make(map[string]*bytecode.ClassFile),
		isExternalMap:  make(map[string]bool),
	}
}

// SetApplicationPackages sets the package prefixes for application code
func (b *Builder) SetApplicationPackages(packages []string) {
	b.appPackages = packages
}

// BuildCallGraph builds a complete call graph from application and dependencies
func (b *Builder) BuildCallGraph(dependencies []*models.Dependency) (*models.CallGraph, error) {
	cg := models.NewCallGraph()

	// First, analyze application code (sequential — usually just 1-2 JARs)
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

		b.registerClasses(classes, false)
	}

	// Then, analyze dependencies in parallel
	type jarResult struct {
		classes []*bytecode.ClassFile
		err     error
		jarPath string
	}

	const maxWorkers = 10
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	resultsCh := make(chan jarResult, len(dependencies))

	for _, dep := range dependencies {
		if dep.JARPath == "" {
			continue
		}

		wg.Add(1)
		go func(jarPath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			analyzer := bytecode.NewJARAnalyzer(jarPath)
			classes, err := analyzer.AnalyzeJAR()
			resultsCh <- jarResult{classes: classes, err: err, jarPath: jarPath}
		}(dep.JARPath)
	}

	// Close results channel when all workers finish
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Register classes serially (class registry is not concurrent-safe)
	for res := range resultsCh {
		if res.err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to analyze JAR %s: %v\n", res.jarPath, res.err)
			continue
		}
		b.registerClasses(res.classes, true)
	}

	// Now build call graph nodes and edges
	b.buildGraphNodesAndEdges(cg)

	return cg, nil
}

// registerClasses records classes and their hierarchy
func (b *Builder) registerClasses(classes []*bytecode.ClassFile, isExternal bool) {
	for _, class := range classes {
		b.classRegistry[class.ClassName] = class
		isAppCode := !isExternal && b.isApplicationClass(class.ClassName)
		b.isExternalMap[class.ClassName] = !isAppCode

		// Register subclasses and implementors
		if class.SuperClass != "" && class.SuperClass != "java/lang/Object" {
			b.classHierarchy[class.SuperClass] = append(b.classHierarchy[class.SuperClass], class.ClassName)
		}
		for _, iface := range class.Interfaces {
			b.classHierarchy[iface] = append(b.classHierarchy[iface], class.ClassName)
		}
	}
}

// buildGraphNodesAndEdges adds all nodes and resolves all edges including virtual dispatch
func (b *Builder) buildGraphNodesAndEdges(cg *models.CallGraph) {
	reflectionAnalyzer := bytecode.NewReflectionAnalyzer()

	// First pass: Add all nodes
	for _, class := range b.classRegistry {
		isExt := b.isExternalMap[class.ClassName]

		for _, method := range class.Methods {
			methodID := models.GetMethodID(class.ClassName, method.Name, method.Descriptor)

			// Analyze method for edge cases
			isReflective := reflectionAnalyzer.IsReflective(method.Calls)
			isLambda := strings.HasPrefix(method.Name, "lambda$")
			hasDynamic := false
			for _, call := range method.Calls {
				if call.Opcode == 0xBA {
					hasDynamic = true
					break
				}
			}

			node := &models.MethodNode{
				ClassName:  class.ClassName,
				MethodName: method.Name,
				Signature:  method.Descriptor,
				IsExternal: isExt,
				Package:    b.extractPackage(class.ClassName),
				Interfaces: class.Interfaces,

				IsReflective: isReflective,
				IsLambda:     isLambda,
				IsDynamic:    hasDynamic,
			}

			cg.AddNode(methodID, node)
		}
	}

	// Second pass: Add all edges
	for _, class := range b.classRegistry {
		for _, method := range class.Methods {
			methodID := models.GetMethodID(class.ClassName, method.Name, method.Descriptor)

			for _, call := range method.Calls {
				calleeID := models.GetMethodID(call.ClassName, call.MethodName, call.Descriptor)
				callType := getCallTypeFromOpcode(call.Opcode)
				
				// Always add the direct edge (to abstract method/interface method)
				cg.AddEdge(methodID, calleeID, callType)

				// For virtual dispatch, add edges to known implementors
				if callType == models.CallTypeVirtual || callType == models.CallTypeInterface {
					b.addVirtualEdges(cg, methodID, call.ClassName, call.MethodName, call.Descriptor)
				}
			}
		}
	}
}

// addVirtualEdges recursively finds implementors and adds edges to overridden methods
func (b *Builder) addVirtualEdges(cg *models.CallGraph, callerID, targetClass, methodName, descriptor string) {
	visited := make(map[string]bool)
	var queue []string
	queue = append(queue, targetClass)

	for len(queue) > 0 {
		currentClass := queue[0]
		queue = queue[1:]

		if visited[currentClass] {
			continue
		}
		visited[currentClass] = true

		// Check if this class defines the method
		if classData, ok := b.classRegistry[currentClass]; ok {
			for _, m := range classData.Methods {
				if m.Name == methodName && m.Descriptor == descriptor {
					// Add virtual edge if it's not the original abstract call
					if currentClass != targetClass {
						virtualID := models.GetMethodID(currentClass, methodName, descriptor)
						cg.AddEdge(callerID, virtualID, models.CallTypeVirtual)
					}
					break
				}
			}
		}

		// Enqueue subclasses / implementors
		if subclasses, exists := b.classHierarchy[currentClass]; exists {
			queue = append(queue, subclasses...)
		}
	}
}

// addClassesToCallGraph was replaced by multi-pass buildGraphNodesAndEdges

// getCallTypeFromOpcode converts JVM bytecode opcode to CallType
func getCallTypeFromOpcode(opcode byte) models.CallType {
	switch opcode {
	case 0xB8: // invokestatic
		return models.CallTypeStatic
	case 0xB6: // invokevirtual
		return models.CallTypeVirtual
	case 0xB9: // invokeinterface
		return models.CallTypeInterface
	case 0xB7: // invokespecial (constructors, super, private)
		return models.CallTypeSpecial
	case 0xBA: // invokedynamic (lambdas, method references)
		return models.CallTypeDynamic
	default:
		return models.CallTypeUnknown
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
// Uses adjacency list for O(V+E) traversal instead of scanning all edges
func (b *Builder) dfsReachability(cg *models.CallGraph, methodID string, reachable, visited map[string]bool) {
	stack := []string{methodID}

	for len(stack) > 0 {
		// Pop
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if visited[current] {
			continue
		}
		visited[current] = true
		reachable[current] = true

		// Follow outgoing edges via adjacency list
		for _, neighbor := range cg.AdjList[current] {
			if !visited[neighbor] {
				stack = append(stack, neighbor)
			}
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
		if strings.Contains(node.ClassName, "Controller") && node.MethodName != "<init>" && node.MethodName != "<clinit>" {
			entryPoints = append(entryPoints, id)
		}

		// Look for JAX-RS / Jakarta REST Endpoints
		if strings.Contains(node.ClassName, "Resource") || strings.Contains(node.ClassName, "Endpoint") {
			if node.MethodName != "<init>" && node.MethodName != "<clinit>" {
				entryPoints = append(entryPoints, id)
			}
		}

		// Look for Message Driven Beans / Kafka Listeners
		if strings.Contains(node.MethodName, "onMessage") || strings.Contains(node.MethodName, "consume") {
			if node.MethodName != "<init>" && node.MethodName != "<clinit>" {
				entryPoints = append(entryPoints, id)
			}
		}
	}

	return entryPoints
}
