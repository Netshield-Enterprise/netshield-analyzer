package models

type Dependency struct {
	GroupID    string `json:"group_id"`
	ArtifactID string `json:"artifact_id"`
	Version    string `json:"version"`
	Scope      string `json:"scope"`
	JARPath    string `json:"jar_path"`
}

type DependencyTree struct {
	Root         *Dependency   `json:"root"`
	Dependencies []*Dependency `json:"dependencies"`
}
