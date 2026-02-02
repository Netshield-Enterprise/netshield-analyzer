package models

type CallGraph struct {
	Nodes map[string]*MethodNode `json:"nodes"`
	Edges []*CallEdge            `json:"edges"`
}

type MethodNode struct {
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	Signature  string `json:"signature"`
	IsExternal bool   `json:"is_external"`
	Package    string `json:"package"`
}

type CallEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func NewCallGraph() *CallGraph {
	return &CallGraph{
		Nodes: make(map[string]*MethodNode),
		Edges: make([]*CallEdge, 0),
	}
}

func (cg *CallGraph) AddNode(id string, node *MethodNode) {
	cg.Nodes[id] = node
}

func (cg *CallGraph) AddEdge(from, to string) {
	cg.Edges = append(cg.Edges, &CallEdge{From: from, To: to})
}

func GetMethodID(className, methodName, signature string) string {
	return className + "." + methodName + signature
}
