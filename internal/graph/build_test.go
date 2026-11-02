package graph

import (
	"testing"

	"github.com/bugbountytool/rce-finder/internal/inventory"
)

func TestBuildFromInventory(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	eps := []inventory.Endpoint{
		{Method: "GET", Path: "/users", Source: "openapi"},
		{Method: "POST", Path: "/users", Source: "openapi"},
	}
	if err := BuildFromInventory(s, "https://example.test", eps); err != nil {
		t.Fatal(err)
	}
	counts, _ := s.Counts()
	if counts[NodeAsset] != 1 || counts[NodeEndpoint] != 2 {
		t.Fatalf("counts = %+v", counts)
	}
	assets, _ := s.NodesByKind(NodeAsset)
	nb, _ := s.Neighbors(assets[0].ID, EdgeExposes)
	if len(nb) != 2 {
		t.Fatalf("exposed endpoints = %d", len(nb))
	}
}

func TestAddFlowAndPathResolution(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	srcID, _, err := AddFlow(s, "req.query.q", []string{"controller", "service"}, "os/exec")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := s.PathsToSink(srcID, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths = %d", len(paths))
	}
	names := []string{}
	for _, n := range paths[0].Nodes {
		names = append(names, n.Name)
	}
	want := []string{"req.query.q", "controller", "service", "os/exec"}
	if len(names) != len(want) {
		t.Fatalf("path nodes = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("path[%d] = %s want %s", i, names[i], want[i])
		}
	}
}
