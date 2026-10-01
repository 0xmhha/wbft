package event

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestNodeKinds checks that every Kind constant of this package is a node
// kind, so a kind added later cannot be emitted by an application.
func TestNodeKinds(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "event.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "Kind" {
				continue
			}
			for _, val := range v.Values {
				lit := val.(*ast.BasicLit)
				k := Kind(lit.Value[1 : len(lit.Value)-1])
				if !IsNodeKind(k) {
					t.Errorf("kind %s is not a node kind", k)
				}
				n++
			}
		}
	}
	if n != len(nodeKinds) {
		t.Fatalf("%d Kind constants, %d node kinds", n, len(nodeKinds))
	}
}
