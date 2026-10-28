package admin

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hotte512/unifi-api-guard/internal/proxy"
	"github.com/Hotte512/unifi-api-guard/internal/rules"
	"github.com/Hotte512/unifi-api-guard/internal/store"
)

const testCSRF = "test-csrf-token"

// newTestServer returns a server with a password, a logged in session and one client.
func newTestServer(t *testing.T, version string) (*Server, store.Client) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "config.json"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPassword("a-long-password"); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Audit: proxy.NewAudit(10), Version: version,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.sessions["test-session"] = session{csrf: testCSRF, expires: time.Now().Add(time.Hour)}
	c, _, err := st.CreateClient(store.Client{Name: "app", Enabled: true, AllowedIPs: []string{"192.168.1.10"},
		Rules: []rules.Rule{{Methods: []string{"GET"}, Path: "sites"}}, RatePerMinute: 60})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func (s *Server) testRequest(method, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.RemoteAddr = "127.0.0.1:1234"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// baseForm has the client fields and an empty rule form.
func baseForm() url.Values {
	return url.Values{"csrf": {testCSRF}, "name": {"app"}, "enabled": {"on"}, "allowed_ips": {"192.168.1.10"},
		"rate": {"60"}, "rule_count": {"0"}}
}

var (
	tagRe    = regexp.MustCompile(`(?s)<(input|textarea|select)\b([^>]*)>`)
	attrRe   = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:="([^"]*)")?`)
	optionRe = regexp.MustCompile(`<option\b([^>]*)>`)
)

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(s, -1) {
		m[a[1]] = html.UnescapeString(a[2])
	}
	return m
}

// formValues extracts what a browser would submit for the form with the given action.
func formValues(t *testing.T, page, action string) url.Values {
	t.Helper()
	start := strings.Index(page, `action="`+action+`"`)
	if start < 0 {
		t.Fatalf("form %s not found", action)
	}
	page = page[start:]
	page = page[:strings.Index(page, "</form>")]
	v := url.Values{}
	for _, m := range tagRe.FindAllStringSubmatchIndex(page, -1) {
		tag, a := page[m[2]:m[3]], attrs(page[m[4]:m[5]])
		name, hasName := a["name"]
		if !hasName {
			continue
		}
		rest := page[m[1]:]
		switch tag {
		case "input":
			switch a["type"] {
			case "checkbox", "radio":
				if _, ok := a["checked"]; ok {
					val, ok := a["value"]
					if !ok {
						val = "on"
					}
					v.Add(name, val)
				}
			case "button", "submit":
			default:
				v.Add(name, a["value"])
			}
		case "textarea":
			v.Add(name, html.UnescapeString(rest[:strings.Index(rest, "</textarea>")]))
		case "select":
			inner := rest[:strings.Index(rest, "</select>")]
			for _, o := range optionRe.FindAllStringSubmatch(inner, -1) {
				oa := attrs(o[1])
				if _, ok := oa["selected"]; ok {
					v.Add(name, oa["value"])
				}
			}
		}
	}
	return v
}

func TestParseRuleForm(t *testing.T) {
	form := url.Values{"rule_count": {"6"},
		// order of the checkboxes in the request does not matter
		"rule.0.endpoint": {"custom"}, "rule.0.path": {"sites/*/dns/policies"},
		"rule.0.methods": {"POST", "GET"}, "rule.0.filter_field": {"domain"},
		"rule.0.patterns": {"*.example.com\r\n\r\n  example.com \r\n"},
		// completely empty card
		"rule.1.endpoint": {""}, "rule.1.path": {""}, "rule.1.patterns": {"\r\n"},
		// removed card, even though it is invalid
		"rule.2.endpoint": {"custom"}, "rule.2.path": {"/bad"}, "rule.2.methods": {"GET"}, "rule.2.delete": {"on"},
		"rule.3.endpoint": {"custom"}, "rule.3.path": {"info"}, "rule.3.methods": {"GET"},
		// custom chosen but nothing else: ignored
		"rule.4.endpoint": {"custom"},
		"rule.5.endpoint": {"custom"}, "rule.5.path": {"sites/*/devices/**"}, "rule.5.methods": {"DELETE", "GET", "PATCH"},
		// beyond rule_count: ignored
		"rule.6.endpoint": {"custom"}, "rule.6.path": {"**"}, "rule.6.methods": {"DELETE"},
	}
	cards, rs, err := parseRuleForm(form)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 6 {
		t.Errorf("cards = %d, want 6", len(cards))
	}
	want := []rules.Rule{
		{Methods: []string{"GET", "POST"}, Path: "sites/*/dns/policies",
			Filter: &rules.Filter{Field: "domain", Patterns: []string{"*.example.com", "example.com"}}},
		{Methods: []string{"GET"}, Path: "info"},
		{Methods: []string{"GET", "PATCH", "DELETE"}, Path: "sites/*/devices/**"},
	}
	if !reflect.DeepEqual(rs, want) {
		t.Errorf("rules = %+v, want %+v", rs, want)
	}

	// the path input only counts with "Eigener Pfad" (it is hidden otherwise), unknown endpoints are rejected
	for _, f := range []url.Values{
		{"rule_count": {"1"}, "rule.0.endpoint": {""}, "rule.0.path": {"info"}, "rule.0.methods": {"GET"}},
		{"rule_count": {"1"}, "rule.0.endpoint": {"**"}, "rule.0.methods": {"GET"}},
	} {
		if _, rs, err := parseRuleForm(f); err == nil {
			t.Errorf("%v: accepted %+v", f, rs)
		}
	}

	// an empty form is an empty rule set, not nil
	_, rs, err = parseRuleForm(url.Values{"rule_count": {"2"}})
	if err != nil || rs == nil || len(rs) != 0 {
		t.Errorf("empty form: %v %v", rs, err)
	}

	if len(rules.Catalog) > 0 {
		e := rules.Catalog[0]
		// the path input is ignored when a catalog endpoint is chosen
		_, rs, err := parseRuleForm(url.Values{"rule_count": {"1"}, "rule.0.endpoint": {e.Path},
			"rule.0.path": {"**"}, "rule.0.methods": {e.Methods[0]}})
		if err != nil || len(rs) != 1 || rs[0].Path != e.Path {
			t.Errorf("catalog endpoint: %+v %v", rs, err)
		}
	}
}

func TestParseRuleFormErrors(t *testing.T) {
	for name, form := range map[string]url.Values{
		"missing count":   {},
		"invalid count":   {"rule_count": {"x"}},
		"negative count":  {"rule_count": {"-1"}},
		"too many":        {"rule_count": {strconv.Itoa(maxFormRules + 1)}},
		"absolute path":   {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"/sites"}, "rule.0.methods": {"GET"}},
		"dot segment":     {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites/../x"}, "rule.0.methods": {"GET"}},
		"inner **":        {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"**/x"}, "rule.0.methods": {"GET"}},
		"no methods":      {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites"}},
		"unknown method":  {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites"}, "rule.0.methods": {"TRACE"}},
		"no path":         {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.methods": {"GET"}},
		"field only":      {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites"}, "rule.0.methods": {"GET"}, "rule.0.filter_field": {"domain"}},
		"patterns only":   {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites"}, "rule.0.methods": {"GET"}, "rule.0.patterns": {"*.example.com"}},
		"invalid pattern": {"rule_count": {"1"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites"}, "rule.0.methods": {"GET"}, "rule.0.filter_field": {"domain"}, "rule.0.patterns": {"a*.example.com"}},
		"second invalid": {"rule_count": {"2"}, "rule.0.endpoint": {"custom"}, "rule.0.path": {"sites"}, "rule.0.methods": {"GET"},
			"rule.1.endpoint": {"custom"}, "rule.1.path": {"sites/"}, "rule.1.methods": {"GET"}},
	} {
		if _, rs, err := parseRuleForm(form); err == nil || rs != nil {
			t.Errorf("%s: want an error and no rules, got %v %v", name, rs, err)
		}
	}
	_, _, err := parseRuleForm(url.Values{"rule_count": {"2"}, "rule.1.endpoint": {"custom"}, "rule.1.path": {"/x"},
		"rule.1.methods": {"GET"}})
	if err == nil || !strings.HasPrefix(err.Error(), "Regel 2: ") {
		t.Errorf("error must name the card: %v", err)
	}
}

func TestUpdateClientForm(t *testing.T) {
	s, c := newTestServer(t, "dev")
	form := baseForm()
	form.Set("rule_count", "3")
	form.Set("rule.0.endpoint", "custom")
	form.Set("rule.0.path", "sites")
	form["rule.0.methods"] = []string{"GET"}
	form.Set("rule.1.endpoint", "custom")
	form.Set("rule.1.path", "sites/*/dns/policies/*")
	form["rule.1.methods"] = []string{"GET", "PUT"}
	form.Set("rule.1.filter_field", "domain")
	form.Set("rule.1.patterns", "*.example.com")
	w := s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Gespeichert.") {
		t.Fatalf("save failed: %d %s", w.Code, w.Body.String())
	}
	got, _ := s.Store.Client(c.ID)
	want := []rules.Rule{{Methods: []string{"GET"}, Path: "sites"},
		{Methods: []string{"GET", "PUT"}, Path: "sites/*/dns/policies/*",
			Filter: &rules.Filter{Field: "domain", Patterns: []string{"*.example.com"}}}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("rules = %+v", got.Rules)
	}

	// an invalid rule saves nothing, also not the other fields, and shows the input again
	form.Set("name", "renamed")
	form.Set("rule.2.endpoint", "custom")
	form.Set("rule.2.path", "/proxy/../secret")
	form["rule.2.methods"] = []string{"DELETE"}
	w = s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	body := w.Body.String()
	if !strings.Contains(body, `class="msg error">Regel 3: `) {
		t.Errorf("error not shown: %s", body)
	}
	if !strings.Contains(body, `value="/proxy/../secret"`) || !strings.Contains(body, `value="renamed"`) {
		t.Error("submitted input must be shown again")
	}
	if after, _ := s.Store.Client(c.ID); !reflect.DeepEqual(after, got) {
		t.Errorf("nothing may be saved on error: %+v", after)
	}

	// too many rules
	form = baseForm()
	form.Set("rule_count", "100000")
	w = s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	if !strings.Contains(w.Body.String(), "Zu viele Regeln") {
		t.Error("too many rules must be rejected")
	}
	// a request without the rule form must not wipe the rules
	form = baseForm()
	form.Del("rule_count")
	s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	// unknown mode
	form = baseForm()
	form.Set("rules_mode", "yaml")
	s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	if after, _ := s.Store.Client(c.ID); !reflect.DeepEqual(after, got) {
		t.Errorf("nothing may be saved: %+v", after)
	}
}

func TestUpdateClientNeedsCSRF(t *testing.T) {
	s, c := newTestServer(t, "dev")
	form := baseForm()
	form.Del("csrf")
	form.Set("rule_count", "1")
	form.Set("rule.0.endpoint", "custom")
	form.Set("rule.0.path", "**")
	form["rule.0.methods"] = []string{"DELETE"}
	for _, token := range []string{"", "wrong"} {
		if token != "" {
			form.Set("csrf", token)
		}
		if w := s.testRequest(http.MethodPost, "/clients/"+c.ID, form); w.Code != http.StatusForbidden {
			t.Errorf("csrf %q: status %d", token, w.Code)
		}
	}
	if after, _ := s.Store.Client(c.ID); !reflect.DeepEqual(after, c) {
		t.Error("rules changed without csrf token")
	}
}

func TestRuleFormRoundTrip(t *testing.T) {
	s, c := newTestServer(t, "dev")
	rs := []rules.Rule{
		{Methods: []string{"GET"}, Path: "sites"},
		{Methods: []string{"GET", "POST"}, Path: "sites/*/dns/policies",
			Filter: &rules.Filter{Field: "domain", Patterns: []string{"*.example.com", "example.com"}}},
		{Methods: []string{"GET", "PUT", "PATCH", "DELETE"}, Path: "sites/*/dns/policies/*",
			Filter: &rules.Filter{Field: "domain", Patterns: []string{"*"}}},
		{Methods: []string{"GET"}, Path: "**"},
		{Methods: []string{"POST"}, Path: `odd/"<name>"&x`},
	}
	if len(rules.Catalog) > 0 {
		e := rules.Catalog[0]
		r := rules.Rule{Methods: e.Methods[:1], Path: e.Path}
		if len(e.FilterFields) > 0 {
			r.Filter = &rules.Filter{Field: e.FilterFields[0], Patterns: []string{"*.example.com"}}
		}
		rs = append(rs, r)
	}
	c.Rules = rs
	if err := s.Store.UpdateClient(c); err != nil {
		t.Fatal(err)
	}
	c, _ = s.Store.Client(c.ID)

	page := s.testRequest(http.MethodGet, "/clients/"+c.ID, nil).Body.String()
	if n := strings.Count(page, "data-rule>"); n != len(rs)+extraRuleCards {
		t.Errorf("cards = %d, want %d", n, len(rs)+extraRuleCards)
	}
	if !strings.Contains(page, `<option value="custom" selected>Eigener Pfad</option>`) {
		t.Error("a path outside the catalog must be shown as custom path")
	}
	form := formValues(t, page, "/clients/"+c.ID)
	if form.Get("rules_mode") != "form" || form.Get("csrf") != testCSRF {
		t.Fatalf("unexpected form: %v", form)
	}
	if w := s.testRequest(http.MethodPost, "/clients/"+c.ID, form); !strings.Contains(w.Body.String(), "Gespeichert.") {
		t.Fatalf("save failed: %s", w.Body.String())
	}
	after, _ := s.Store.Client(c.ID)
	if !reflect.DeepEqual(after, c) {
		t.Errorf("round trip changed the client:\n got %+v\nwant %+v", after.Rules, c.Rules)
	}

	// removing the second rule keeps the order of the others
	form.Set("rule.1.delete", "on")
	s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	after, _ = s.Store.Client(c.ID)
	if want := append(rs[:1:1], rs[2:]...); !reflect.DeepEqual(after.Rules, want) {
		t.Errorf("after delete: %+v", after.Rules)
	}
}

func TestUpdateClientJSONMode(t *testing.T) {
	s, c := newTestServer(t, "dev")
	form := baseForm()
	form.Del("rule_count")
	form.Set("rules_mode", "json")
	form.Set("rules", `[{"methods":["GET"],"path":"sites/*/clients"}]`)
	if w := s.testRequest(http.MethodPost, "/clients/"+c.ID, form); !strings.Contains(w.Body.String(), "Gespeichert.") {
		t.Fatalf("json save failed: %s", w.Body.String())
	}
	got, _ := s.Store.Client(c.ID)
	if want := []rules.Rule{{Methods: []string{"GET"}, Path: "sites/*/clients"}}; !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("rules = %+v", got.Rules)
	}

	// the form fields are ignored in json mode
	form.Set("rule_count", "1")
	form.Set("rule.0.endpoint", "custom")
	form.Set("rule.0.path", "**")
	form["rule.0.methods"] = []string{"DELETE"}
	form.Set("rules", `[]`)
	s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	if got, _ := s.Store.Client(c.ID); len(got.Rules) != 0 {
		t.Errorf("json mode must use the json rules: %+v", got.Rules)
	}

	before, _ := s.Store.Client(c.ID)
	for _, raw := range []string{`[{"methods":["GET"],"path":"sites","extra":1}]`, `[{"methods":["GET"],"path":"/x"}]`, `nope`} {
		form.Set("rules", raw)
		body := s.testRequest(http.MethodPost, "/clients/"+c.ID, form).Body.String()
		if !strings.Contains(body, `class="msg error"`) || !strings.Contains(body, html.EscapeString(raw)) {
			t.Errorf("%s: error and raw input must be shown", raw)
		}
		if !strings.Contains(body, `value="json" checked`) {
			t.Errorf("%s: json mode must stay selected", raw)
		}
		if after, _ := s.Store.Client(c.ID); !reflect.DeepEqual(after, before) {
			t.Errorf("%s: nothing may be saved", raw)
		}
	}
}

func TestFooterVersion(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	r.RemoteAddr = "127.0.0.1:1234"

	s, _ := newTestServer(t, "v1.2.3")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	body := w.Body.String()
	if !strings.Contains(body, `<a href="https://github.com/Hotte512/unifi-api-guard/releases/tag/v1.2.3">v1.2.3</a>`) ||
		!strings.Contains(body, `<a href="https://github.com/Hotte512/unifi-api-guard">GitHub</a>`) {
		t.Errorf("footer missing on login page: %s", body)
	}

	s, _ = newTestServer(t, "dev")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if body := w.Body.String(); !strings.Contains(body, "UniFi API Guard dev") || strings.Contains(body, "/releases/tag/") {
		t.Errorf("dev build must not link a release: %s", body)
	}

	for v, want := range map[string]bool{"v1.0.0": true, "v2": true, "dev": false, "": false, "v": false, "version": false, "1.0": false} {
		if isReleaseTag(v) != want {
			t.Errorf("isReleaseTag(%q) = %v", v, !want)
		}
	}
}

func TestClientCreatedPointsToForm(t *testing.T) {
	s, _ := newTestServer(t, "dev")
	form := url.Values{"csrf": {testCSRF}, "name": {"custom app"}, "template": {"custom"},
		"allowed_ips": {"192.168.1.11"}, "rate": {"0"}}
	body := s.testRequest(http.MethodPost, "/clients", form).Body.String()
	if !strings.Contains(body, "Regeln im Formular hinzufügen") {
		t.Errorf("custom template must point to the rule form: %s", body)
	}
}

// withCatalog replaces the endpoint catalog for one test.
func withCatalog(t *testing.T, c []rules.Endpoint) {
	t.Helper()
	old := rules.Catalog
	rules.Catalog = c
	t.Cleanup(func() { rules.Catalog = old })
}

func TestRuleFormCatalog(t *testing.T) {
	withCatalog(t, []rules.Endpoint{
		{Group: "DNS", Name: "DNS-Policies", Path: "sites/*/dns/policies", Methods: []string{"GET", "POST"},
			FilterFields: []string{"domain"}},
		{Group: "Sites", Name: "Sites", Path: "sites", Methods: []string{"GET"}},
		{Group: "DNS", Name: "DNS-Policy", Path: "sites/*/dns/policies/*", Methods: []string{"GET", "PUT", "DELETE"},
			FilterFields: []string{"domain", "name"}},
	})
	if g := catalogGroups(); len(g) != 2 || g[0].Name != "DNS" || len(g[0].Endpoints) != 2 {
		t.Errorf("groups = %+v", g)
	}
	if f := catalogFilterFields(); !reflect.DeepEqual(f, []string{"domain", "name"}) {
		t.Errorf("filter fields = %v", f)
	}
	s, c := newTestServer(t, "dev")
	c.Rules = []rules.Rule{{Methods: []string{"GET", "POST"}, Path: "sites/*/dns/policies",
		Filter: &rules.Filter{Field: "domain", Patterns: []string{"*.example.com"}}}}
	if err := s.Store.UpdateClient(c); err != nil {
		t.Fatal(err)
	}
	c, _ = s.Store.Client(c.ID)
	page := s.testRequest(http.MethodGet, "/clients/"+c.ID, nil).Body.String()
	for _, want := range []string{`<optgroup label="DNS">`,
		`<option value="sites/*/dns/policies" data-methods="GET POST" selected>DNS-Policies – sites/*/dns/policies</option>`,
		`<option value="domain"></option>`} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %s", want)
		}
	}
	form := formValues(t, page, "/clients/"+c.ID)
	if form.Get("rule.0.endpoint") != "sites/*/dns/policies" {
		t.Errorf("catalog endpoint not selected: %v", form)
	}
	s.testRequest(http.MethodPost, "/clients/"+c.ID, form)
	if after, _ := s.Store.Client(c.ID); !reflect.DeepEqual(after, c) {
		t.Errorf("round trip changed the rules: %+v", after.Rules)
	}
}
