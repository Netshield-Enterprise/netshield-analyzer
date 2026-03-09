// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

package bytecode

import "strings"

// ReflectionPattern represents a detected reflection usage
type ReflectionPattern struct {
	Type       string     // "ClassLoading", "MethodInvocation", "FieldAccess", "ConstructorCall"
	Method     MethodCall // The reflective call
	Target     string     // Inferred target class/method if analyzable
	Confidence string     // "high", "medium", "low" - how confident we are in the target
}

// ReflectionAnalyzer detects reflection usage patterns
type ReflectionAnalyzer struct{}

// NewReflectionAnalyzer creates a new reflection analyzer
func NewReflectionAnalyzer() *ReflectionAnalyzer {
	return &ReflectionAnalyzer{}
}

// AnalyzePatterns identifies reflection usage in method calls
func (ra *ReflectionAnalyzer) AnalyzePatterns(calls []MethodCall) []ReflectionPattern {
	patterns := []ReflectionPattern{}

	for _, call := range calls {
		pattern := ra.detectReflectionPattern(call)
		if pattern != nil {
			patterns = append(patterns, *pattern)
		}
	}

	return patterns
}

// detectReflectionPattern checks if a method call is a reflection API call
func (ra *ReflectionAnalyzer) detectReflectionPattern(call MethodCall) *ReflectionPattern {
	className := call.ClassName
	methodName := call.MethodName

	// Class.forName()
	if className == "java/lang/Class" && methodName == "forName" {
		return &ReflectionPattern{
			Type:       "ClassLoading",
			Method:     call,
			Target:     "", // Would need constant analysis to determine
			Confidence: "low",
		}
	}

	// Method.invoke()
	if className == "java/lang/reflect/Method" && methodName == "invoke" {
		return &ReflectionPattern{
			Type:       "MethodInvocation",
			Method:     call,
			Target:     "",
			Confidence: "low",
		}
	}

	// Constructor.newInstance()
	if className == "java/lang/reflect/Constructor" && methodName == "newInstance" {
		return &ReflectionPattern{
			Type:       "ConstructorCall",
			Method:     call,
			Target:     "",
			Confidence: "low",
		}
	}

	// Field.get() / Field.set()
	if className == "java/lang/reflect/Field" && (methodName == "get" || methodName == "set") {
		return &ReflectionPattern{
			Type:       "FieldAccess",
			Method:     call,
			Target:     "",
			Confidence: "low",
		}
	}

	return nil
}

// IsReflective checks if a method uses reflection based on its calls
func (ra *ReflectionAnalyzer) IsReflective(calls []MethodCall) bool {
	for _, call := range calls {
		if strings.HasPrefix(call.ClassName, "java/lang/reflect/") {
			return true
		}
		if call.ClassName == "java/lang/Class" &&
			(call.MethodName == "forName" || call.MethodName == "getDeclaredMethod") {
			return true
		}
	}
	return false
}
