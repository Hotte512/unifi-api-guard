package rules

import "testing"

func TestCleanPath(t *testing.T) {
	for _, bad := range []string{"", "/", "sites/../x", "sites//x", "sites/./x", "sites/a%2Fb", `sites\x`,
		"sites/s1/devices/..;/wifi", "sites/s1/devices/.;/x", "sites/s1/devices/..;x/y", "sites/s1;x/devices",
		"sites/s1/devices/a:b", "sites/s1/dev ices", "sites/s1/d\u00e9vices"} {
		if _, err := CleanPath(bad); err == nil {
			t.Errorf("CleanPath(%q) should fail", bad)
		}
	}
	if _, err := CleanPath("sites/0a1b2c3d-4e5f-6789-abcd-ef0123456789/devices/x_y.z~1"); err != nil {
		t.Errorf("uuid and unreserved characters must be allowed: %v", err)
	}
	segs, err := CleanPath("/sites/abc/dns/policies/")
	if err != nil || len(segs) != 4 {
		t.Fatalf("got %v %v", segs, err)
	}
}

func TestMatch(t *testing.T) {
	rs, _ := TemplateByID("dns-records")
	r := rs.Rules([]string{"*.example.com"})
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "sites", true},
		{"POST", "sites", false},
		{"GET", "sites/s1/dns/policies", true},
		{"POST", "sites/s1/dns/policies", true},
		{"DELETE", "sites/s1/dns/policies", false},
		{"PUT", "sites/s1/dns/policies/p1", true},
		{"DELETE", "sites/s1/dns/policies/p1", true},
		{"GET", "sites/s1/dns/policies/p1/x", false},
		{"GET", "sites/s1/firewall/policies", false},
		{"DELETE", "sites/s1/devices/d1", false},
	}
	for _, c := range cases {
		segs, _ := CleanPath(c.path)
		if got := Match(r, c.method, segs) != nil; got != c.want {
			t.Errorf("%s %s: got %v want %v", c.method, c.path, got, c.want)
		}
	}

	ro, _ := TemplateByID("read-only")
	segs, _ := CleanPath("sites/s1/firewall/policies")
	if Match(ro.Rules(nil), "GET", segs) == nil || Match(ro.Rules(nil), "POST", segs) != nil {
		t.Error("read-only template")
	}
}

func TestFilter(t *testing.T) {
	f := &Filter{Field: "domain", Patterns: []string{"*.example.com", "example.org"}}
	for v, want := range map[string]bool{
		"a.example.com":    true,
		"A.B.Example.COM.": true,
		"example.com":      false,
		"badexample.com":   false,
		".example.com":     false,
		"example.org":      true,
		"a.example.org":    false,
		"":                 false,
	} {
		if got := f.Allows(v); got != want {
			t.Errorf("Allows(%q) = %v, want %v", v, got, want)
		}
	}
	if f.AllowsObject(map[string]any{"domain": 5}) || f.AllowsObject(map[string]any{}) {
		t.Error("objects without a string field must not be allowed")
	}
}

func TestValidate(t *testing.T) {
	bad := [][]Rule{
		{{Methods: nil, Path: "sites"}},
		{{Methods: []string{"get"}, Path: "sites"}},
		{{Methods: []string{"GET"}, Path: "/sites"}},
		{{Methods: []string{"GET"}, Path: "**/x"}},
		{{Methods: []string{"GET"}, Path: "sites/../x"}},
		{{Methods: []string{"GET"}, Path: "sites", Filter: &Filter{Field: "domain"}}},
		{{Methods: []string{"GET"}, Path: "sites", Filter: &Filter{Field: "domain", Patterns: []string{"a*.example.com"}}}},
	}
	for i, rs := range bad {
		if Validate(rs) == nil {
			t.Errorf("case %d should be invalid", i)
		}
	}
	for _, tpl := range Templates {
		if err := Validate(tpl.Rules([]string{"*.example.com"})); err != nil {
			t.Errorf("template %s: %v", tpl.ID, err)
		}
	}
}
