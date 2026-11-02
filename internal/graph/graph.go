// Package graph is the unified application security graph. It stores assets,
// endpoints, parameters, routes, functions, sources, sinks, dependencies and
// findings as typed nodes connected by typed edges, persisted in SQLite.
//
// The graph is what lets findings be explained (render the source-to-sink
// path), deduplicated (one finding per sink+parameter+control rather than per
// payload), and prioritized (only test sinks reachable from exposed endpoints).
package graph

import (
	"time"
)

// NodeKind enumerates the typed nodes in the security graph.
type NodeKind string

const (
	NodeAsset      NodeKind = "asset"
	NodeEndpoint   NodeKind = "endpoint"
	NodeParameter  NodeKind = "parameter"
	NodeRoute      NodeKind = "route"
	NodeFunction   NodeKind = "function"
	NodeSource     NodeKind = "source"
	NodeSink       NodeKind = "sink"
	NodeSanitizer  NodeKind = "sanitizer"
	NodeDependency NodeKind = "dependency"
	NodeComponent  NodeKind = "component"
	NodePrincipal  NodeKind = "principal"
	NodeFinding    NodeKind = "finding"
)

// EdgeKind enumerates the typed relationships.
type EdgeKind string

const (
	EdgeHosts       EdgeKind = "HOSTS"
	EdgeExposes     EdgeKind = "EXPOSES"
	EdgeAccepts     EdgeKind = "ACCEPTS"
	EdgeHandledBy   EdgeKind = "HANDLED_BY"
	EdgeCalls       EdgeKind = "CALLS"
	EdgeFlowsTo     EdgeKind = "FLOWS_TO"
	EdgeSanitizedBy EdgeKind = "SANITIZED_BY"
	EdgeDependsOn   EdgeKind = "DEPENDS_ON"
	EdgeAffects     EdgeKind = "AFFECTS"
	EdgeObservedAt  EdgeKind = "OBSERVED_AT"
	EdgeCorroborates EdgeKind = "CORROBORATES"
	EdgeContradicts EdgeKind = "CONTRADICTS"
)

// Node is one typed vertex. Attrs holds kind-specific properties (method,
// path, purl, file:line, etc.). Keys are stable, deterministic identifiers.
type Node struct {
	ID    string            `json:"id"`
	Kind  NodeKind          `json:"kind"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Edge is a directed, typed relationship between two nodes.
type Edge struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	Kind EdgeKind  `json:"kind"`
	At   time.Time `json:"at,omitempty"`
}

// Path is one route through the graph, used to render a finding's explanation.
type Path struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
