package models

import "testing"

func TestCallGraph_AddNode(t *testing.T) {
	cg := NewCallGraph()

	node := &MethodNode{
		ClassName:  "com/example/App",
		MethodName: "main",
		Signature:  "([Ljava/lang/String;)V",
		IsExternal: false,
	}

	id := GetMethodID(node.ClassName, node.MethodName, node.Signature)
	cg.AddNode(id, node)

	if len(cg.Nodes) != 1 {
		t.Errorf("Expected 1 node, got %d", len(cg.Nodes))
	}

	retrieved := cg.Nodes[id]
	if retrieved == nil {
		t.Fatal("Node not found in graph")
	}

	if retrieved.ClassName != node.ClassName {
		t.Errorf("Expected className '%s', got '%s'", node.ClassName, retrieved.ClassName)
	}
}

func TestCallGraph_AddEdge(t *testing.T) {
	cg := NewCallGraph()

	cg.AddEdge("method1", "method2")

	if len(cg.Edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(cg.Edges))
	}

	edge := cg.Edges[0]
	if edge.From != "method1" || edge.To != "method2" {
		t.Errorf("Edge mismatch: expected method1->method2, got %s->%s", edge.From, edge.To)
	}
}

func TestGetMethodID(t *testing.T) {
	id := GetMethodID("com/example/App", "main", "([Ljava/lang/String;)V")
	expected := "com/example/App.main([Ljava/lang/String;)V"

	if id != expected {
		t.Errorf("Expected method ID '%s', got '%s'", expected, id)
	}
}
