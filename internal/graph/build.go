package graph

import (
	"fmt"
	"net/url"

	"github.com/bugbountytool/rce-finder/internal/inventory"
)

// BuildFromInventory populates the graph from explicit targets and imported
// endpoints. It performs no network I/O: every node derives from already
// supplied, in-scope metadata. Imported endpoints never create new targets;
// they are attached under an existing asset only when in scope.
func BuildFromInventory(s *Store, targetRaw string, endpoints []inventory.Endpoint) error {
	u, err := url.Parse(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target %q: %w", targetRaw, err)
	}
	asset, err := s.AddNode(Node{Kind: NodeAsset, Name: u.Scheme + "://" + u.Host, Attrs: map[string]string{
		"scheme": u.Scheme, "host": u.Host,
	}})
	if err != nil {
		return err
	}
	for _, ep := range endpoints {
		en, err := s.AddNode(Node{Kind: NodeEndpoint, Name: ep.Path, Attrs: map[string]string{
			"method": ep.Method, "source": ep.Source, "asset": asset.ID,
		}})
		if err != nil {
			return err
		}
		if err := s.AddEdge(Edge{From: asset.ID, To: en.ID, Kind: EdgeExposes}); err != nil {
			return err
		}
	}
	return nil
}

// AddFlow records a source-to-sink path in the graph, creating the source,
// intermediate function, and sink nodes plus FLOWS_TO edges.
func AddFlow(s *Store, sourceName string, functions []string, sinkName string) (sourceID, sinkID string, err error) {
	src, err := s.AddNode(Node{Kind: NodeSource, Name: sourceName})
	if err != nil {
		return "", "", err
	}
	prev := src.ID
	for _, fn := range functions {
		f, err := s.AddNode(Node{Kind: NodeFunction, Name: fn})
		if err != nil {
			return "", "", err
		}
		if err := s.AddEdge(Edge{From: prev, To: f.ID, Kind: EdgeFlowsTo}); err != nil {
			return "", "", err
		}
		prev = f.ID
	}
	sink, err := s.AddNode(Node{Kind: NodeSink, Name: sinkName})
	if err != nil {
		return "", "", err
	}
	if err := s.AddEdge(Edge{From: prev, To: sink.ID, Kind: EdgeFlowsTo}); err != nil {
		return "", "", err
	}
	return src.ID, sink.ID, nil
}
