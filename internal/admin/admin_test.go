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
