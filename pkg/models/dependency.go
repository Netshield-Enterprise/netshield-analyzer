// Copyright (c) 2026 NetShield
//
// This file is part of NetShield Analyzer.
//
// NetShield Analyzer is licensed under the GNU Affero General Public
// License v3.0. See the LICENSE file for details.

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
