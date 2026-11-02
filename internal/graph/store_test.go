package graph

import (
	"testing"
)

func TestNodeIDIsDeterministicAndKindScoped(t *testing.T) {
	a := NodeID(NodeEndpoint, "/users", map[string]string{"method": "GET"})
	b := NodeID(NodeEndpoint, "/users", map[string]string{"method": "GET"})
	c := NodeID(NodeEndpoint, "/users", map[string]string{"method": "POST"})
	if a != b {
		t.Fatal("same node produced different IDs")
	}
	if a == c {
		t.Fatal("different attrs produced same ID")
	}
	if NodeID(NodeSink, "/users", map[string]string{"method": "GET"}) == a {
		t.Fatal("kind not scoped into ID")
	}
}

func TestStoreAddAndQueryNodes(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ep, err := s.AddNode(Node{Kind: NodeEndpoint, Name: "/users", Attrs: map[string]string{"method": "GET"}})
	if err != nil {
		t.Fatal(err)
	}
	if ep.ID == "" {
		t.Fatal("no ID assigned")
	}
	got, ok, err := s.Node(ep.ID)
	if err != nil || !ok {
		t.Fatalf("node not found: %v ok=%v", err, ok)
	}
	if got.Name != "/users" || got.Attrs["method"] != "GET" {
		t.Fatalf("node = %+v", got)
	}
	// idempotent re-add
	if _, err := s.AddNode(Node{Kind: NodeEndpoint, Name: "/users", Attrs: map[string]string{"method": "GET"}}); err != nil {
		t.Fatal(err)
	}
	eps, _ := s.NodesByKind(NodeEndpoint)
	if len(eps) != 1 {
		t.Fatalf("endpoint count = %d", len(eps))
	}
}

func TestStoreEdgesAndNeighbors(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	asset, _ := s.AddNode(Node{Kind: NodeAsset, Name: "https://example.test"})
	ep, _ := s.AddNode(Node{Kind: NodeEndpoint, Name: "/users"})
	param, _ := s.AddNode(Node{Kind: NodeParameter, Name: "id"})
	if err := s.AddEdge(Edge{From: asset.ID, To: ep.ID, Kind: EdgeExposes}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEdge(Edge{From: ep.ID, To: param.ID, Kind: EdgeAccepts}); err != nil {
		t.Fatal(err)
	}
	// duplicate edge is a no-op
	if err := s.AddEdge(Edge{From: asset.ID, To: ep.ID, Kind: EdgeExposes}); err != nil {
		t.Fatal(err)
	}
	nb, err := s.Neighbors(asset.ID, EdgeExposes)
	if err != nil || len(nb) != 1 || nb[0].Name != "/users" {
		t.Fatalf("neighbors = %+v err=%v", nb, err)
	}
	counts, _ := s.Counts()
	if counts[NodeAsset] != 1 || counts[NodeEndpoint] != 1 || counts[NodeParameter] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
}

func TestPathsToSink(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	src, _ := s.AddNode(Node{Kind: NodeSource, Name: "req.query"})
	fn, _ := s.AddNode(Node{Kind: NodeFunction, Name: "handle"})
	sink, _ := s.AddNode(Node{Kind: NodeSink, Name: "exec"})
	s.AddEdge(Edge{From: src.ID, To: fn.ID, Kind: EdgeFlowsTo})
	s.AddEdge(Edge{From: fn.ID, To: sink.ID, Kind: EdgeFlowsTo})
	paths, err := s.PathsToSink(src.ID, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %d, want 1", len(paths))
	}
	// unreachable source has no path
	orphan, _ := s.AddNode(Node{Kind: NodeSource, Name: "orphan"})
	paths, _ = s.PathsToSink(orphan.ID, 8)
	if len(paths) != 0 {
		t.Fatalf("orphan paths = %d, want 0", len(paths))
	}
}

func TestCycleDoesNotHang(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	a, _ := s.AddNode(Node{Kind: NodeFunction, Name: "a"})
	b, _ := s.AddNode(Node{Kind: NodeFunction, Name: "b"})
	sink, _ := s.AddNode(Node{Kind: NodeSink, Name: "exec"})
	s.AddEdge(Edge{From: a.ID, To: b.ID, Kind: EdgeCalls})
	s.AddEdge(Edge{From: b.ID, To: a.ID, Kind: EdgeCalls}) // cycle
	s.AddEdge(Edge{From: b.ID, To: sink.ID, Kind: EdgeFlowsTo})
	paths, err := s.PathsToSink(a.ID, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("cyclic graph paths = %d, want 1", len(paths))
	}
}
