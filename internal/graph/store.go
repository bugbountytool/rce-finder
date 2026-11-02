package graph

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Store is a SQLite-backed security graph. A single file (or :memory:) holds
// typed nodes and edges. All writes are atomic per call.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS nodes (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	name TEXT NOT NULL,
	attrs TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS edges (
	from_id TEXT NOT NULL,
	to_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	PRIMARY KEY (from_id, to_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id);
CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_id);
`

// Open opens (creating if needed) a graph store at path. Use ":memory:" for
// an ephemeral store. The connection is bounded to one writer.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating graph schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// AddNode inserts or updates a node. The ID is derived if empty.
func (s *Store) AddNode(n Node) (Node, error) {
	if n.ID == "" {
		n.ID = NodeID(n.Kind, n.Name, n.Attrs)
	}
	if n.Kind == "" || n.Name == "" {
		return n, fmt.Errorf("node requires kind and name")
	}
	attrs := n.Attrs
	if attrs == nil {
		attrs = map[string]string{}
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return n, err
	}
	_, err = s.db.Exec(`INSERT INTO nodes(id,kind,name,attrs) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, attrs=excluded.attrs`,
		n.ID, string(n.Kind), n.Name, string(data))
	return n, err
}

// AddEdge inserts a typed edge, creating endpoint nodes if they exist.
func (s *Store) AddEdge(e Edge) error {
	if e.From == "" || e.To == "" || e.Kind == "" {
		return fmt.Errorf("edge requires from, to and kind")
	}
	_, err := s.db.Exec(`INSERT INTO edges(from_id,to_id,kind) VALUES(?,?,?)
		ON CONFLICT(from_id,to_id,kind) DO NOTHING`, e.From, e.To, string(e.Kind))
	return err
}

// Node retrieves a node by ID.
func (s *Store) Node(id string) (Node, bool, error) {
	row := s.db.QueryRow(`SELECT id,kind,name,attrs FROM nodes WHERE id=?`, id)
	return scanNode(row)
}

func scanNode(row *sql.Row) (Node, bool, error) {
	var n Node
	var kind, attrs string
	err := row.Scan(&n.ID, &kind, &n.Name, &attrs)
	if err == sql.ErrNoRows {
		return n, false, nil
	}
	if err != nil {
		return n, false, err
	}
	n.Kind = NodeKind(kind)
	_ = json.Unmarshal([]byte(attrs), &n.Attrs)
	return n, true, nil
}

// NodesByKind lists all nodes of a kind, ordered by name for determinism.
func (s *Store) NodesByKind(kind NodeKind) ([]Node, error) {
	rows, err := s.db.Query(`SELECT id,kind,name,attrs FROM nodes WHERE kind=? ORDER BY name`, string(kind))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var k, attrs string
		if err := rows.Scan(&n.ID, &k, &n.Name, &attrs); err != nil {
			return nil, err
		}
		n.Kind = NodeKind(k)
		_ = json.Unmarshal([]byte(attrs), &n.Attrs)
		out = append(out, n)
	}
	return out, rows.Err()
}

// Neighbors returns nodes reachable from id by the given edge kind.
func (s *Store) Neighbors(id string, kind EdgeKind) ([]Node, error) {
	rows, err := s.db.Query(`SELECT n.id,n.kind,n.name,n.attrs FROM edges e
		JOIN nodes n ON n.id=e.to_id WHERE e.from_id=? AND e.kind=? ORDER BY n.name`, id, string(kind))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var k, attrs string
		if err := rows.Scan(&n.ID, &k, &n.Name, &attrs); err != nil {
			return nil, err
		}
		n.Kind = NodeKind(k)
		_ = json.Unmarshal([]byte(attrs), &n.Attrs)
		out = append(out, n)
	}
	return out, rows.Err()
}

// PathsToSink returns all simple paths from a source node to any sink node,
// bounded by maxDepth, using a recursive traversal. Used to render and to
// assess reachability of a dangerous sink from an exposed entry point.
func (s *Store) PathsToSink(sourceID string, maxDepth int) ([]Path, error) {
	if maxDepth <= 0 {
		maxDepth = 8
	}
	rows, err := s.db.Query(`
		WITH RECURSIVE walk(id, path, depth) AS (
			SELECT ?, ?, 0
			UNION
			SELECT e.to_id, walk.path || ',' || e.to_id, walk.depth+1
			FROM walk JOIN edges e ON e.from_id = walk.id
			WHERE walk.depth < ? AND INSTR(walk.path, e.to_id) = 0
		)
		SELECT w.path FROM walk w JOIN nodes n ON n.id = w.id
		WHERE n.kind = ? AND w.id != ?`, sourceID, sourceID, maxDepth, string(NodeSink), sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var csvs []string
	for rows.Next() {
		var csv string
		if err := rows.Scan(&csv); err != nil {
			return nil, err
		}
		csvs = append(csvs, csv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close() // release the single connection before resolving nodes
	var paths []Path
	for _, csv := range csvs {
		ids := strings.Split(csv, ",")
		p := Path{}
		for _, id := range ids {
			n, ok, err := s.Node(id)
			if err != nil {
				return nil, err
			}
			if ok {
				p.Nodes = append(p.Nodes, n)
			}
		}
		for i := 0; i+1 < len(p.Nodes); i++ {
			p.Edges = append(p.Edges, Edge{From: p.Nodes[i].ID, To: p.Nodes[i+1].ID, Kind: EdgeFlowsTo})
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// Counts returns node counts by kind, for reporting and tests.
func (s *Store) Counts() (map[NodeKind]int, error) {
	rows, err := s.db.Query(`SELECT kind, COUNT(*) FROM nodes GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[NodeKind]int{}
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[NodeKind(k)] = c
	}
	return out, rows.Err()
}
