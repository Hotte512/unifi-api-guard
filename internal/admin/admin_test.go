package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Hotte512/unifi-api-guard/internal/proxy"
	"github.com/Hotte512/unifi-api-guard/internal/store"
)

func TestSetupRemovesTokenFile(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "config.json"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "setup-token")
	if err := os.WriteFile(tokenFile, []byte("the-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: st, Audit: proxy.NewAudit(10), SetupToken: "the-token", TokenFile: tokenFile,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	post := func(token string) *httptest.ResponseRecorder {
		form := url.Values{"token": {token}, "password": {"a-long-password"}, "password2": {"a-long-password"}}
		r := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}

	if w := post("wrong"); st.HasPassword() || !strings.Contains(w.Body.String(), "setup-token") {
		t.Fatal("a wrong token must not set the password and the error must name the token file")
	}
	if _, err := os.Stat(tokenFile); err != nil {
		t.Fatal("token file must stay until the setup succeeded")
	}
	if w := post("the-token"); w.Code != http.StatusSeeOther || !st.HasPassword() {
		t.Fatalf("setup failed: %d", w.Code)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Error("token file must be removed after the setup")
	}
	if w := post("the-token"); w.Header().Get("Location") != "/login" {
		t.Error("the token must not work a second time")
	}
}

func postForm(s *Server, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:1234"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func sessionCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestLoginLockoutParallel(t *testing.T) {
	s, _ := newTestServer(t, "dev")
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	checked := 0
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := postForm(s, "/login", url.Values{"password": {"a-wrong-password"}}, nil)
			if strings.Contains(w.Body.String(), "Falsches Passwort") {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if checked > maxLoginFails {
		t.Errorf("%d parallel wrong logins reached the password check, at most %d may", checked, maxLoginFails)
	}
	if w := postForm(s, "/login", url.Values{"password": {"a-long-password"}}, nil); sessionCookieOf(w) != nil {
		t.Error("the right password must be refused while the ip is locked")
	}
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	s, _ := newTestServer(t, "dev")
	login := func(pw string) *http.Cookie {
		return sessionCookieOf(postForm(s, "/login", url.Values{"password": {pw}}, nil))
	}
	stolen, own := login("a-long-password"), login("a-long-password")
	if stolen == nil || own == nil {
		t.Fatal("login failed")
	}
	s.mu.Lock()
	csrf := s.sessions[own.Value].csrf
	s.mu.Unlock()
	w := postForm(s, "/password", url.Values{"csrf": {csrf}, "current": {"a-long-password"},
		"password": {"the-new-password"}, "password2": {"the-new-password"}}, own)
	fresh := sessionCookieOf(w)
	if w.Code != http.StatusSeeOther || fresh == nil {
		t.Fatalf("password change: %d", w.Code)
	}
	get := func(c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	for name, c := range map[string]*http.Cookie{"other": stolen, "old own": own} {
		if w := get(c); w.Header().Get("Location") != "/login" {
			t.Errorf("%s session must end after the password change, got %d", name, w.Code)
		}
	}
	if w := get(fresh); w.Code != http.StatusOK {
		t.Errorf("the new session must work, got %d", w.Code)
	}
}
