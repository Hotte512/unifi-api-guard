// Package rules decides which requests a client key may send to the UniFi API.
//
// Everything is denied unless a rule allows it. A rule allows a set of HTTP methods on a path pattern and can
// restrict the objects it touches by a field of the object (e.g. only dns policies whose "domain" is below
// example.com).
package rules

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Rule allows Methods on Path. Path is relative to /proxy/network/integration/v1 and uses "/" separated segments:
// "*" matches exactly one segment, a trailing "**" matches any number of segments (also none).
type Rule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	// Filter restricts the objects the rule covers, nil = no restriction
	Filter *Filter `json:"filter,omitempty"`
}

// Filter restricts objects by a string field, e.g. Field "domain" with Patterns ["example.com", "*.example.com"].
//
// Pattern syntax: "example.com" matches only example.com, "*.example.com" matches every subdomain of example.com
// (not example.com itself), "*" matches everything.
type Filter struct {
	Field    string   `json:"field"`
	Patterns []string `json:"patterns"`
}

var validMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// Validate checks a rule set, so a typo can not silently allow more than intended.
func Validate(rs []Rule) error {
	for i, r := range rs {
		if len(r.Methods) == 0 {
			return fmt.Errorf("rule %d: no methods", i+1)
		}
		for _, m := range r.Methods {
			if !slices.Contains(validMethods, m) {
				return fmt.Errorf("rule %d: unknown method %q", i+1, m)
			}
		}
		if r.Path == "" || strings.HasPrefix(r.Path, "/") || strings.HasSuffix(r.Path, "/") {
			return fmt.Errorf("rule %d: path must be relative, e.g. sites/*/dns/policies", i+1)
		}
		segs := strings.Split(r.Path, "/")
		for j, s := range segs {
			if s == "" || s == "." || s == ".." {
				return fmt.Errorf("rule %d: invalid path segment %q", i+1, s)
			}
			if s == "**" && j != len(segs)-1 {
				return fmt.Errorf("rule %d: ** is only allowed at the end", i+1)
			}
		}
		if r.Filter != nil {
			if r.Filter.Field == "" {
				return fmt.Errorf("rule %d: filter needs a field", i+1)
			}
			if len(r.Filter.Patterns) == 0 {
				return fmt.Errorf("rule %d: filter needs at least one pattern", i+1)
			}
			for _, p := range r.Filter.Patterns {
				if p == "" || strings.Contains(strings.TrimPrefix(p, "*."), "*") && p != "*" {
					return fmt.Errorf("rule %d: invalid filter pattern %q", i+1, p)
				}
			}
		}
	}
	return nil
}

// ErrInvalidPath is returned for paths that could be used to escape the api prefix.
var ErrInvalidPath = errors.New("invalid path")

// CleanPath splits an api path (without query) into segments and rejects empty, "." and ".." segments as well as
// encoded slashes, so a request can never match a pattern it does not literally fit.
func CleanPath(p string) ([]string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil, ErrInvalidPath
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "%\\") {
			return nil, ErrInvalidPath
		}
	}
	return segs, nil
}

func matchPath(pattern string, segs []string) bool {
	ps := strings.Split(pattern, "/")
	for i, p := range ps {
		if p == "**" {
			return true
		}
		if i >= len(segs) || (p != "*" && p != segs[i]) {
			return false
		}
	}
	return len(ps) == len(segs)
}

// Match returns the first rule that allows method on the path segments, nil if none does.
func Match(rs []Rule, method string, segs []string) *Rule {
	for i := range rs {
		if slices.Contains(rs[i].Methods, method) && matchPath(rs[i].Path, segs) {
			return &rs[i]
		}
	}
	return nil
}

// Allows reports whether value matches one of the filter patterns (case-insensitive, trailing dot ignored).
func (f *Filter) Allows(value string) bool {
	v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if v == "" {
		return false
	}
	for _, p := range f.Patterns {
		p = strings.TrimSuffix(strings.ToLower(p), ".")
		switch {
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			if strings.HasSuffix(v, p[1:]) && len(v) > len(p)-1 {
				return true
			}
		case v == p:
			return true
		}
	}
	return false
}

// AllowsObject checks the filter field of a decoded json object. Objects without the field are not allowed.
func (f *Filter) AllowsObject(obj map[string]any) bool {
	s, ok := obj[f.Field].(string)
	return ok && f.Allows(s)
}
