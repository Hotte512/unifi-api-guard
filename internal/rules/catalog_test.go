package rules

import (
	"strings"
	"testing"
)

func TestCatalogEntriesValid(t *testing.T) {
	if len(Catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for _, e := range Catalog {
		if e.Group == "" || e.Name == "" || len(e.Methods) == 0 {
			t.Errorf("incomplete entry %q", e.Path)
		}
		if seen[e.Path] {
			t.Errorf("duplicate path %q", e.Path)
		}
		seen[e.Path] = true
		if err := Validate([]Rule{{Methods: e.Methods, Path: e.Path}}); err != nil {
			t.Errorf("path %q: %v", e.Path, err)
		}
		for _, m := range e.Methods {
			if m != strings.ToUpper(m) {
				t.Errorf("path %q: method %q not uppercase", e.Path, m)
			}
		}
	}
}

func TestTemplatesUseCatalogPaths(t *testing.T) {
	for _, tpl := range Templates {
		for _, r := range tpl.Rules([]string{"example.com"}) {
			if strings.Contains(r.Path, "**") {
				continue
			}
			if _, ok := EndpointByPath(r.Path); !ok {
				t.Errorf("template %s: path %q not in catalog", tpl.ID, r.Path)
			}
		}
	}
}
