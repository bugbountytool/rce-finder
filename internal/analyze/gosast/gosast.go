// Package gosast is a native Go static analyzer. It loads packages with full
// type information, builds an SSA representation, and identifies untrusted
// sources (net/http request accessors), dangerous sinks (os/exec, template,
// database), and whether data flows from a source to a sink.
//
// It is intentionally scoped: this is a heuristic analyzer, not a sound
// whole-program prover. Reflection and some interface dispatch are invisible.
// Findings carry a complete-flow flag only when a def-use chain from a source
// to a sink is actually established; otherwise they are pattern-level.
package gosast

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/bugbountytool/rce-finder/internal/model"
)

// Rule declares a set of sources and sinks to trace for one vulnerability class.
type Rule struct {
	ID      string
	Class   string
	CWE     string
	Sources []Matcher // untrusted entry points
	Sinks   []Matcher // dangerous operations
}

// Matcher matches a call by package path and function/method name.
type Matcher struct {
	Pkg      string // import path, e.g. "net/http" or "os/exec"
	Func     string // function or method name, e.g. "Command"
	RecvType string // optional receiver type for methods
}

// Finding is one static analysis result before verification.
type Finding struct {
	RuleID      string
	Class       string
	CWE         string
	Source      model.Location
	SourceName  string
	Sink        model.Location
	SinkName    string
	Complete    bool // a def-use chain source->sink was established
	Description string
}

// DefaultRules returns the built-in RCE/injection rule set for Go services.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID: "go-command-injection", Class: "command-injection", CWE: "CWE-78",
			Sources: []Matcher{
				{Pkg: "net/http", Func: "FormValue"},
				{Pkg: "net/http", Func: "Get", RecvType: "url.Values"},
			},
			Sinks: []Matcher{
				{Pkg: "os/exec", Func: "Command"},
				{Pkg: "os/exec", Func: "CommandContext"},
			},
		},
		{
			ID: "go-sql-injection", Class: "sql-injection", CWE: "CWE-89",
			Sources: []Matcher{{Pkg: "net/http", Func: "FormValue"}},
			Sinks:   []Matcher{{Pkg: "database/sql", Func: "Query"}, {Pkg: "database/sql", Func: "Exec"}},
		},
	}
}

// Analyzer runs rules over a loaded module.
type Analyzer struct {
	Rules []Rule
	Dir   string // module/package directory to analyze
}

// New returns an analyzer with the default rules rooted at dir.
func New(dir string) *Analyzer {
	return &Analyzer{Rules: DefaultRules(), Dir: dir}
}

// Analyze loads the packages at the analyzer's Dir and applies every rule,
// returning static findings. No code is executed; only type/SSA analysis runs.
func (a *Analyzer) Analyze() ([]Finding, error) {
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  a.Dir,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		// continue: partial type info is still useful
	}
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	var findings []Finding
	for _, rule := range a.Rules {
		for _, sp := range ssaPkgs {
			if sp == nil {
				continue
			}
			findings = append(findings, a.applyRule(prog, sp, rule)...)
		}
	}
	return findings, nil
}

func (a *Analyzer) applyRule(prog *ssa.Program, sp *ssa.Package, rule Rule) []Finding {
	var out []Finding
	for _, mem := range sp.Members {
		fn, ok := mem.(*ssa.Function)
		if !ok || fn.Blocks == nil {
			continue
		}
		out = append(out, a.analyzeFunction(fn, rule)...)
	}
	return out
}

// analyzeFunction finds sink calls in a function and checks whether any
// argument is reachable (via SSA def-use) from a source call in the same
// function. This is intraprocedural; cross-function flow needs the call graph.
func (a *Analyzer) analyzeFunction(fn *ssa.Function, rule Rule) []Finding {
	var sourceVals []ssa.Value
	var sourceLoc model.Location
	var sourceName string

	// First pass: collect source values in this function.
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			if m := matchCall(call, rule.Sources); m != nil {
				if v := call.Value(); v != nil {
					sourceVals = append(sourceVals, v)
					sourceLoc = location(fn.Prog.Fset, call.Pos())
					sourceName = m.Func
				}
			}
		}
	}

	var out []Finding
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			m := matchCall(call, rule.Sinks)
			if m == nil {
				continue
			}
			sinkLoc := location(fn.Prog.Fset, call.Pos())
			complete := false
			// Check whether any sink operand is reachable from a source value.
			for _, arg := range call.Common().Args {
				for _, sv := range sourceVals {
					if reachable(arg, sv, 0) {
						complete = true
						break
					}
				}
			}
			f := Finding{
				RuleID: rule.ID, Class: rule.Class, CWE: rule.CWE,
				Source: sourceLoc, SourceName: sourceName,
				Sink: sinkLoc, SinkName: m.Func,
				Complete: complete,
			}
			if complete {
				f.Description = fmt.Sprintf("%s flows from %s to %s", rule.Class, sourceName, m.Func)
			} else {
				f.Description = fmt.Sprintf("dangerous sink %s present; no source flow established in this function", m.Func)
			}
			out = append(out, f)
		}
	}
	return out
}

// reachable reports whether target is derived from src within a bounded
// def-use walk. It handles phi nodes, conversions, calls, and the varargs
// memory pattern (a value Stored into an Alloc'd array element that is then
// Sliced and passed to a variadic sink like exec.Command).
func reachable(target, src ssa.Value, depth int) bool {
	if depth > 16 || target == nil || src == nil {
		return false
	}
	if target == src {
		return true
	}
	switch v := target.(type) {
	case *ssa.Phi:
		for _, e := range v.Edges {
			if reachable(e, src, depth+1) {
				return true
			}
		}
	case *ssa.Slice:
		// slice of an array/alloc: trace values stored into it.
		if alloc, ok := v.X.(*ssa.Alloc); ok {
			if storedIntoReaches(alloc, src, depth+1) {
				return true
			}
		}
		return reachable(v.X, src, depth+1)
	case *ssa.Call:
		for _, arg := range v.Call.Args {
			if reachable(arg, src, depth+1) {
				return true
			}
		}
	}
	// Generic operand walk for conversions and other wrappers.
	if un, ok := target.(interface{ Operands([]ssa.Value) []ssa.Value }); ok {
		for _, op := range un.Operands(nil) {
			if op != nil && reachable(op, src, depth+1) {
				return true
			}
		}
	}
	return false
}

// storedIntoReaches reports whether any value Stored into the Alloc (through
// an IndexAddr/FieldAddr) is reachable from src. This covers the varargs
// pattern where exec.Command("sh", slice...) receives a slice built by storing
// source values into a stack-allocated array.
func storedIntoReaches(alloc *ssa.Alloc, src ssa.Value, depth int) bool {
	if depth > 16 {
		return false
	}
	refs := alloc.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		idx, ok := ref.(*ssa.IndexAddr)
		if !ok {
			continue
		}
		// Find stores to this element address.
		irefs := idx.Referrers()
		if irefs == nil {
			continue
		}
		for _, iref := range *irefs {
			if store, ok := iref.(*ssa.Store); ok {
				if reachable(store.Val, src, depth+1) {
					return true
				}
			}
		}
	}
	return false
}

// matchCall returns the matcher if the call matches any in the set.
func matchCall(call ssa.CallInstruction, set []Matcher) *Matcher {
	common := call.Common()
	if common == nil {
		return nil
	}
	var pkgPath, funcName, recvType string
	if common.IsInvoke() {
		return nil
	}
	callee := common.StaticCallee()
	if callee != nil {
		funcName = callee.Name()
		if callee.Pkg != nil {
			pkgPath = callee.Pkg.Pkg.Path()
		}
		if sig, ok := callee.Type().(*types.Signature); ok && sig.Recv() != nil {
			recvType = sig.Recv().Type().String()
		}
	}
	for i := range set {
		m := &set[i]
		if m.Func != funcName {
			continue
		}
		if m.Pkg != "" && pkgPath != m.Pkg && !strings.HasSuffix(pkgPath, "/"+m.Pkg) {
			continue
		}
		if m.RecvType != "" && !strings.Contains(recvType, m.RecvType) {
			continue
		}
		return m
	}
	return nil
}

func location(fset *token.FileSet, pos token.Pos) model.Location {
	p := fset.Position(pos)
	return model.Location{File: p.Filename, Line: p.Line, Column: p.Column}
}
