package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hotte512/unifi-api-guard/internal/rules"
	"github.com/Hotte512/unifi-api-guard/internal/store"
)

const upstreamKey = "UPSTREAM-SECRET-KEY"

// fakeUnifi serves dns policies like the integration api, with paging
type fakeUnifi struct {
	mu       sync.Mutex
	policies map[string]map[string]any
	nextID   int
	calls    []string
}

func newFake() *fakeUnifi {
	f := &fakeUnifi{policies: map[string]map[string]any{}}
	for i := range 230 {
		f.add(fmt.Sprintf("host%d.other.example", i))
	}
	f.add("a.example.com")
	f.add("b.example.com")
	return f
}

func (f *fakeUnifi) add(domain string) string {
	f.nextID++
	id := "p" + strconv.Itoa(f.nextID)
	f.policies[id] = map[string]any{"id": id, "type": "A_RECORD", "domain": domain, "ipv4Address": "192.168.1.10"}
	return id
}

func (f *fakeUnifi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-API-KEY") != upstreamKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	rest := strings.TrimPrefix(r.URL.Path, Prefix)
	switch {
	case rest == "sites":
		json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "s1"}}, "totalCount": 1})
	case rest == "sites/s1/dns/policies" && r.Method == http.MethodGet:
		ids := make([]string, 0, len(f.policies))
		for i := 1; i <= f.nextID; i++ {
			if _, ok := f.policies["p"+strconv.Itoa(i)]; ok {
				ids = append(ids, "p"+strconv.Itoa(i))
			}
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			limit = 25
		}
		data := []any{}
		for _, id := range ids[min(offset, len(ids)):min(offset+limit, len(ids))] {
			data = append(data, f.policies[id])
		}
		json.NewEncoder(w).Encode(map[string]any{"offset": offset, "limit": limit, "count": len(data),
			"totalCount": len(ids), "data": data})
	case rest == "sites/s1/dns/policies" && r.Method == http.MethodPost:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		id := f.add(body["domain"].(string))
		json.NewEncoder(w).Encode(f.policies[id])
	case strings.HasPrefix(rest, "sites/s1/dns/policies/"):
		id := strings.TrimPrefix(rest, "sites/s1/dns/policies/")
		p, ok := f.policies[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(p)
		case http.MethodPut:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			body["id"] = id
			f.policies[id] = body
			json.NewEncoder(w).Encode(body)
		case http.MethodDelete:
			delete(f.policies, id)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type env struct {
	t     *testing.T
	fake  *fakeUnifi
	guard *httptest.Server
	key   string
	store *store.Store
}

func setup(t *testing.T, allowedIPs []string) *env {
	t.Helper()
	fake := newFake()
	up := httptest.NewServer(fake)
	t.Cleanup(up.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "config.json"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUpstream(store.Upstream{URL: up.URL}, upstreamKey); err != nil {
		t.Fatal(err)
	}
	tpl, _ := rules.TemplateByID("dns-records")
	_, key, err := st.CreateClient(store.Client{Name: "npmplus", Enabled: true, AllowedIPs: allowedIPs,
		Rules: tpl.Rules([]string{"*.example.com"})})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Store: st, Audit: NewAudit(100), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	guard := httptest.NewServer(h)
	t.Cleanup(guard.Close)
	return &env{t: t, fake: fake, guard: guard, key: key, store: st}
}

func (e *env) do(method, path, key, body string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.guard.URL+path, rd)
	if key != "" {
		req.Header.Set("X-API-KEY", key)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

const policies = Prefix + "sites/s1/dns/policies"

func TestAuth(t *testing.T) {
	e := setup(t, []string{"127.0.0.1"})
	if s, _ := e.do("GET", Prefix+"sites", "", ""); s != 401 {
		t.Errorf("no key: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites", "uag_wrong", ""); s != 401 {
		t.Errorf("wrong key: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites", upstreamKey, ""); s != 401 {
		t.Errorf("upstream key must not work at the guard: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites", e.key, ""); s != 200 {
		t.Errorf("valid key: %d", s)
	}
	if s, _ := e.do("GET", "/api/system", e.key, ""); s != 404 {
		t.Errorf("outside prefix: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites/s1/firewall/policies", e.key, ""); s != 403 {
		t.Errorf("firewall: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites/s1/dns/../../x", e.key, ""); s != 400 && s != 403 && s != 404 {
		t.Errorf("dot segments: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites/s1/dns/..;/..;/x", e.key, ""); s != 400 {
		t.Errorf("path parameter traversal: %d", s)
	}
	if s, _ := e.do("GET", Prefix+"sites%2Fs1", e.key, ""); s != 400 {
		t.Errorf("encoded slash: %d", s)
	}
}

func TestIPWhitelist(t *testing.T) {
	e := setup(t, []string{"192.168.1.0/24"})
	if s, _ := e.do("GET", Prefix+"sites", e.key, ""); s != 403 {
		t.Errorf("foreign ip: %d", s)
	}
	e2 := setup(t, nil)
	if s, _ := e2.do("GET", Prefix+"sites", e2.key, ""); s != 403 {
		t.Errorf("empty whitelist must deny: %d", s)
	}
}

func TestFilteredList(t *testing.T) {
	e := setup(t, []string{"127.0.0.1/32"})
	s, body := e.do("GET", policies+"?offset=0&limit=200", e.key, "")
	if s != 200 {
		t.Fatalf("list: %d", s)
	}
	if body["totalCount"].(float64) != 2 || len(body["data"].([]any)) != 2 {
		t.Fatalf("expected only the 2 example.com records, got %v", body)
	}
	_, body = e.do("GET", policies+"?offset=1&limit=1", e.key, "")
	data := body["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["domain"] != "b.example.com" {
		t.Errorf("paging: %v", body)
	}
}

func TestWrites(t *testing.T) {
	e := setup(t, []string{"127.0.0.1"})
	if s, _ := e.do("POST", policies, e.key, `{"type":"A_RECORD","domain":"c.example.com","ipv4Address":"192.168.1.20"}`); s != 200 {
		t.Errorf("create allowed domain: %d", s)
	}
	if s, _ := e.do("POST", policies, e.key, `{"type":"A_RECORD","domain":"evil.example.org","ipv4Address":"192.168.1.20"}`); s != 403 {
		t.Errorf("create foreign domain: %d", s)
	}
	if s, _ := e.do("POST", policies, e.key, `not json`); s != 403 {
		t.Errorf("invalid body: %d", s)
	}
	// p1 is host0.other.example
	if s, _ := e.do("DELETE", policies+"/p1", e.key, ""); s != 404 {
		t.Errorf("delete foreign record must look like not found: %d", s)
	}
	if s, _ := e.do("PUT", policies+"/p1", e.key, `{"type":"A_RECORD","domain":"x.example.com","ipv4Address":"192.168.1.20"}`); s != 404 {
		t.Errorf("take over foreign record: %d", s)
	}
	if s, _ := e.do("GET", policies+"/p1", e.key, ""); s != 404 {
		t.Errorf("read foreign record: %d", s)
	}
	own := "p231" // a.example.com
	if s, _ := e.do("PUT", policies+"/"+own, e.key, `{"type":"A_RECORD","domain":"evil.example.org","ipv4Address":"192.168.1.20"}`); s != 403 {
		t.Errorf("move own record to foreign domain: %d", s)
	}
	if s, _ := e.do("PUT", policies+"/"+own, e.key, `{"type":"A_RECORD","domain":"a.example.com","ipv4Address":"192.168.1.30"}`); s != 200 {
		t.Errorf("update own record: %d", s)
	}
	if s, _ := e.do("DELETE", policies+"/"+own, e.key, ""); s != 200 {
		t.Errorf("delete own record: %d", s)
	}
	if _, ok := e.fake.policies["p1"]; !ok {
		t.Error("foreign record was deleted")
	}
}

func TestDisabledAndRateLimit(t *testing.T) {
	e := setup(t, []string{"127.0.0.1"})
	c := e.store.Clients()[0]
	c.RatePerMinute = 2
	if err := e.store.UpdateClient(c); err != nil {
		t.Fatal(err)
	}
	e.do("GET", Prefix+"sites", e.key, "")
	e.do("GET", Prefix+"sites", e.key, "")
	if s, _ := e.do("GET", Prefix+"sites", e.key, ""); s != 429 {
		t.Errorf("rate limit: %d", s)
	}
	c.Enabled = false
	e.store.UpdateClient(c)
	if s, _ := e.do("GET", Prefix+"sites", e.key, ""); s != 403 {
		t.Errorf("disabled: %d", s)
	}
}

func TestClientIP(t *testing.T) {
	trusted, _ := ParsePrefixes([]string{"10.0.0.1"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.5:1234"
	r.Header.Set("X-Forwarded-For", "192.168.1.99")
	if ip := ClientIP(r, trusted); ip != netip.MustParseAddr("192.168.1.5") {
		t.Errorf("untrusted peer must not use X-Forwarded-For: %v", ip)
	}
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 192.168.1.99")
	if ip := ClientIP(r, trusted); ip != netip.MustParseAddr("192.168.1.99") {
		t.Errorf("trusted proxy: %v", ip)
	}
}

func TestLimiter(t *testing.T) {
	var l limiter
	now := time.Now()
	for range 3 {
		if !l.allow("a", 3, now) {
			t.Fatal("should allow")
		}
	}
	if l.allow("a", 3, now) {
		t.Fatal("should deny")
	}
	if !l.allow("a", 3, now.Add(30*time.Second)) {
		t.Fatal("should refill")
	}
}
