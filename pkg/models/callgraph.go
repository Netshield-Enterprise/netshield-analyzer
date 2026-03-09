// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

package models

type CallGraph struct {
	Nodes   map[string]*MethodNode `json:"nodes"`
	Edges   []*CallEdge            `json:"edges"`
	AdjList map[string][]string    `json:"-"` // adjacency list for O(V+E) DFS
}

type MethodNode struct {
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	Signature  string `json:"signature"`
	IsExternal bool   `json:"is_external"`
	Package    string `json:"package"`

	// Edge case metadata for improved analysis
	IsReflective   bool     `json:"is_reflective,omitempty"`   // Method uses reflection (Class.forName, Method.invoke)
	IsLambda       bool     `json:"is_lambda,omitempty"`       // Lambda synthetic method
	IsDynamic      bool     `json:"is_dynamic,omitempty"`      // Uses invokedynamic
	Interfaces     []string `json:"interfaces,omitempty"`      // Implemented interfaces
	VirtualTargets []string `json:"virtual_targets,omitempty"` // Possible virtual dispatch targets
}

type CallEdge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Type CallType `json:"type"` // Type of call (static, virtual, interface, dynamic, reflective)
}

// CallType represents the type of method invocation
type CallType string

const (
	CallTypeStatic     CallType = "static"     // invokestatic
	CallTypeVirtual    CallType = "virtual"    // invokevirtual
	CallTypeInterface  CallType = "interface"  // invokeinterface
	CallTypeSpecial    CallType = "special"    // invokespecial (constructors, super)
	CallTypeDynamic    CallType = "dynamic"    // invokedynamic (lambdas)
	CallTypeReflective CallType = "reflective" // Reflection-based call
	CallTypeUnknown    CallType = "unknown"    // Unable to determine
)

func NewCallGraph() *CallGraph {
	return &CallGraph{
		Nodes:   make(map[string]*MethodNode),
		Edges:   make([]*CallEdge, 0),
		AdjList: make(map[string][]string),
	}
}

func (cg *CallGraph) AddNode(id string, node *MethodNode) {
	cg.Nodes[id] = node
}

func (cg *CallGraph) AddEdge(from, to string, callType CallType) {
	cg.Edges = append(cg.Edges, &CallEdge{
		From: from,
		To:   to,
		Type: callType,
	})
	cg.AdjList[from] = append(cg.AdjList[from], to)
}

func GetMethodID(className, methodName, signature string) string {
	return className + "." + methodName + signature
}
