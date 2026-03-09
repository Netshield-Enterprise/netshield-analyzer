// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

package bytecode

import "testing"

func TestReflectionAnalyzer_DetectClassForName(t *testing.T) {
	analyzer := NewReflectionAnalyzer()

	calls := []MethodCall{
		{
			ClassName:  "java/lang/Class",
			MethodName: "forName",
			Descriptor: "(Ljava/lang/String;)Ljava/lang/Class;",
			Opcode:     0xB8, // invokestatic
		},
	}

	patterns := analyzer.AnalyzePatterns(calls)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern, got %d", len(patterns))
	}

	pattern := patterns[0]
	if pattern.Type != "ClassLoading" {
		t.Errorf("Expected type 'ClassLoading', got '%s'", pattern.Type)
	}
}

func TestReflectionAnalyzer_DetectMethodInvoke(t *testing.T) {
	analyzer := NewReflectionAnalyzer()

	calls := []MethodCall{
		{
			ClassName:  "java/lang/reflect/Method",
			MethodName: "invoke",
			Descriptor: "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
			Opcode:     0xB6, // invokevirtual
		},
	}

	patterns := analyzer.AnalyzePatterns(calls)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern, got %d", len(patterns))
	}

	pattern := patterns[0]
	if pattern.Type != "MethodInvocation" {
		t.Errorf("Expected type 'MethodInvocation', got '%s'", pattern.Type)
	}
}

func TestReflectionAnalyzer_IsReflective(t *testing.T) {
	analyzer := NewReflectionAnalyzer()

	// Reflective calls
	reflectiveCalls := []MethodCall{
		{
			ClassName:  "java/lang/Class",
			MethodName: "forName",
			Descriptor: "(Ljava/lang/String;)Ljava/lang/Class;",
		},
	}

	if !analyzer.IsReflective(reflectiveCalls) {
		t.Error("Expected IsReflective to return true for Class.forName")
	}

	// Non-reflective calls
	normalCalls := []MethodCall{
		{
			ClassName:  "java/lang/String",
			MethodName: "toString",
			Descriptor: "()Ljava/lang/String;",
		},
	}

	if analyzer.IsReflective(normalCalls) {
		t.Error("Expected IsReflective to return false for normal method calls")
	}
}

func TestReflectionAnalyzer_DetectConstructorNewInstance(t *testing.T) {
	analyzer := NewReflectionAnalyzer()

	calls := []MethodCall{
		{
			ClassName:  "java/lang/reflect/Constructor",
			MethodName: "newInstance",
			Descriptor: "([Ljava/lang/Object;)Ljava/lang/Object;",
			Opcode:     0xB6,
		},
	}

	patterns := analyzer.AnalyzePatterns(calls)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern, got %d", len(patterns))
	}

	if patterns[0].Type != "ConstructorCall" {
		t.Errorf("Expected type 'ConstructorCall', got '%s'", patterns[0].Type)
	}
}

func TestReflectionAnalyzer_DetectFieldAccess(t *testing.T) {
	analyzer := NewReflectionAnalyzer()

	getCalls := []MethodCall{
		{
			ClassName:  "java/lang/reflect/Field",
			MethodName: "get",
			Descriptor: "(Ljava/lang/Object;)Ljava/lang/Object;",
			Opcode:     0xB6,
		},
	}

	patterns := analyzer.AnalyzePatterns(getCalls)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern for Field.get, got %d", len(patterns))
	}

	if patterns[0].Type != "FieldAccess" {
		t.Errorf("Expected type 'FieldAccess', got '%s'", patterns[0].Type)
	}

	// Test Field.set
	setCalls := []MethodCall{
		{
			ClassName:  "java/lang/reflect/Field",
			MethodName: "set",
			Descriptor: "(Ljava/lang/Object;Ljava/lang/Object;)V",
			Opcode:     0xB6,
		},
	}

	patterns = analyzer.AnalyzePatterns(setCalls)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern for Field.set, got %d", len(patterns))
	}
}
