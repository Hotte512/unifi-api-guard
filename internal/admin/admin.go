// Package admin is the small web ui to set the gateway and manage client keys. It runs on its own port, which should
// only be reachable from the admin network.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hotte512/unifi-api-guard/internal/proxy"
	"github.com/Hotte512/unifi-api-guard/internal/rules"
	"github.com/Hotte512/unifi-api-guard/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	repoURL        = "https://github.com/Hotte512/unifi-api-guard"
	sessionCookie  = "uag_session"
	sessionTTL     = 12 * time.Hour
	maxLoginFails  = 5
	loginBlockTime = 5 * time.Minute
)

// Server is the admin http handler.
type Server struct {
	Store          *store.Store
	Proxy          *proxy.Handler
	Audit          *proxy.Audit
	Allowed        []netip.Prefix
	TrustedProxies []netip.Prefix
	SecureCookie   bool
	// SetupToken allows to set the first password, empty once a password exists
	SetupToken string
	// TokenFile holds the setup token as well and is removed after the setup
	TokenFile string
	// Version is shown in the footer, e.g. "v1.2.0" or "dev"
	Version string
	Log     *slog.Logger

	pages map[string]*template.Template
	mux   *http.ServeMux

	mu       sync.Mutex
	sessions map[string]session
	fails    map[string]loginFails
}

type session struct {
	csrf    string
	expires time.Time
}

type loginFails struct {
	count int
	until time.Time
}

func token() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Init parses the templates and builds the routes.
func (s *Server) Init() error {
	funcs := template.FuncMap{
		"join": strings.Join,
		"json": func(v any) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
		"time": func(t time.Time) string { return t.Local().Format("02.01.2006 15:04:05") },
	}
	s.pages = map[string]*template.Template{}
	for _, p := range []string{"login", "setup", "index", "client_new", "client_created", "client_edit", "password"} {
		t, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return err
		}
		s.pages[p] = t
	}
	s.sessions = map[string]session{}
	s.fails = map[string]loginFails{}

	static, _ := fs.Sub(assets, "static")
	m := http.NewServeMux()
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.login)
	m.HandleFunc("GET /setup", s.setupPage)
	m.HandleFunc("POST /setup", s.setup)
	m.HandleFunc("POST /logout", s.auth(s.logout))
	m.HandleFunc("GET /{$}", s.auth(s.index))
	m.HandleFunc("POST /upstream", s.auth(s.saveUpstream))
	m.HandleFunc("POST /upstream/fingerprint", s.auth(s.fingerprint))
	m.HandleFunc("POST /upstream/test", s.auth(s.testUpstream))
	m.HandleFunc("GET /clients/new", s.auth(s.newClientPage))
	m.HandleFunc("POST /clients", s.auth(s.createClient))
	m.HandleFunc("GET /clients/{id}", s.auth(s.editClientPage))
	m.HandleFunc("POST /clients/{id}", s.auth(s.updateClient))
	m.HandleFunc("POST /clients/{id}/delete", s.auth(s.deleteClient))
	m.HandleFunc("GET /password", s.auth(s.passwordPage))
	m.HandleFunc("POST /password", s.auth(s.changePassword))
	s.mux = m
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin: with no-referrer browsers send "Origin: null" on form posts
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	ip := proxy.ClientIP(r, s.TrustedProxies)
	if len(s.Allowed) > 0 {
		ok := false
		for _, p := range s.Allowed {
			if p.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	if r.Method == http.MethodPost {
		// forms are only accepted from the ui itself
		if o := r.Header.Get("Origin"); o != "" {
			if u, err := url.Parse(o); err != nil || u.Host != r.Host {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	}
	s.mux.ServeHTTP(w, r)
}

type ctxKey struct{}

// auth checks the session and, for POST, the csrf token
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Store.HasPassword() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(sessionCookie)
		var sess session
		ok := false
		if err == nil {
			s.mu.Lock()
			sess, ok = s.sessions[c.Value]
			if ok && time.Now().After(sess.expires) {
				delete(s.sessions, c.Value)
				ok = false
			}
			s.mu.Unlock()
		}
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost &&
			subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.csrf)) != 1 {
			http.Error(w, "invalid form token, please reload the page", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if sess, ok := r.Context().Value(ctxKey{}).(session); ok {
		data["CSRF"] = sess.csrf
		data["LoggedIn"] = true
	}
	data["Version"] = s.Version
	data["RepoURL"] = repoURL
	if isReleaseTag(s.Version) {
		data["ReleaseURL"] = repoURL + "/releases/tag/" + url.PathEscape(s.Version)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages[page].ExecuteTemplate(w, "layout", data); err != nil {
		s.Log.Error("template", "page", page, "error", err)
	}
}

// isReleaseTag reports whether v looks like a release tag such as v1.2.0.
func isReleaseTag(v string) bool {
	return len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9'
}

func (s *Server) newSession(w http.ResponseWriter) {
	id := token()
	s.mu.Lock()
	for k, v := range s.sessions {
		if time.Now().After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = session{csrf: token(), expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
}

// --- login / setup ---

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.Store.HasPassword() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", nil)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := proxy.ClientIP(r, s.TrustedProxies).String()
	// check and count the attempt in one step before the slow password check, so parallel requests cannot all
	// pass with the same counter
	s.mu.Lock()
	f := s.fails[ip]
	now := time.Now()
	if f.count >= maxLoginFails && now.Before(f.until) {
		s.mu.Unlock()
		s.render(w, r, "login", map[string]any{"Error": "Zu viele Fehlversuche, bitte später erneut versuchen."})
		return
	}
	if !now.Before(f.until) {
		f.count = 0
	}
	f.count++
	f.until = now.Add(loginBlockTime)
	s.fails[ip] = f
	s.mu.Unlock()
	if !s.Store.CheckPassword(r.PostFormValue("password")) {
		s.Log.Warn("admin login failed", "ip", ip)
		s.render(w, r, "login", map[string]any{"Error": "Falsches Passwort."})
		return
	}
	s.mu.Lock()
	delete(s.fails, ip)
	s.mu.Unlock()
	s.Log.Info("admin login", "ip", ip)
	s.newSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if s.Store.HasPassword() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", nil)
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if s.Store.HasPassword() || s.SetupToken == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.PostFormValue("token"))), []byte(s.SetupToken)) != 1 {
		s.render(w, r, "setup", map[string]any{"Error": "Einrichtungs-Token stimmt nicht (Datei setup-token im Datenverzeichnis oder Container-Log)."})
		return
	}
	if r.PostFormValue("password") != r.PostFormValue("password2") {
		s.render(w, r, "setup", map[string]any{"Error": "Die Passwörter stimmen nicht überein."})
		return
	}
	if err := s.Store.SetPassword(r.PostFormValue("password")); err != nil {
		s.render(w, r, "setup", map[string]any{"Error": err.Error()})
		return
	}
	s.SetupToken = ""
	if s.TokenFile != "" {
		os.Remove(s.TokenFile)
	}
	s.newSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("changed") == "1" {
		s.render(w, r, "password", map[string]any{"Message": "Passwort geändert, andere Sitzungen wurden abgemeldet."})
		return
	}
	s.render(w, r, "password", nil)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if !s.Store.CheckPassword(r.PostFormValue("current")) {
		s.render(w, r, "password", map[string]any{"Error": "Aktuelles Passwort ist falsch."})
		return
	}
	if r.PostFormValue("password") != r.PostFormValue("password2") {
		s.render(w, r, "password", map[string]any{"Error": "Die Passwörter stimmen nicht überein."})
		return
	}
	if err := s.Store.SetPassword(r.PostFormValue("password")); err != nil {
		s.render(w, r, "password", map[string]any{"Error": err.Error()})
		return
	}
	// end all sessions, a stolen session cookie must not survive the password change
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
	s.newSession(w)
	http.Redirect(w, r, "/password?changed=1", http.StatusSeeOther)
}

// --- dashboard / upstream ---

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	s.renderIndex(w, r, map[string]any{})
}

func (s *Server) renderIndex(w http.ResponseWriter, r *http.Request, data map[string]any) {
	up, key, err := s.Store.Upstream()
	if err != nil {
		data["Error"] = err.Error()
	}
	if _, ok := data["Upstream"]; !ok {
		data["Upstream"] = up
	}
	data["KeySet"] = key != ""
	data["Clients"] = s.Store.Clients()
	entries := s.Audit.Latest()
	if len(entries) > 100 {
		entries = entries[:100]
	}
	data["Audit"] = entries
	s.render(w, r, "index", data)
}

func upstreamFromForm(r *http.Request) store.Upstream {
	return store.Upstream{
		URL:       strings.TrimRight(strings.TrimSpace(r.PostFormValue("url")), "/"),
		VerifyTLS: r.PostFormValue("verify_tls") == "on",
		PinSHA256: strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("pin_sha256")), ":", "")),
	}
}

func validateUpstream(u store.Upstream) error {
	p, err := url.Parse(u.URL)
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || p.Path != "" || p.RawQuery != "" {
		return errors.New("Gateway-URL muss die Form https://192.168.1.1 haben (ohne Pfad).")
	}
	if _, err := proxy.TLSConfig(u); err != nil {
		return errors.New("Zertifikats-Fingerprint muss ein SHA-256-Hexwert sein.")
	}
	return nil
}

func (s *Server) saveUpstream(w http.ResponseWriter, r *http.Request) {
	u := upstreamFromForm(r)
	if err := validateUpstream(u); err != nil {
		s.renderIndex(w, r, map[string]any{"Error": err.Error(), "Upstream": u})
		return
	}
	if err := s.Store.SetUpstream(u, strings.TrimSpace(r.PostFormValue("api_key"))); err != nil {
		s.renderIndex(w, r, map[string]any{"Error": err.Error(), "Upstream": u})
		return
	}
	s.Log.Info("upstream changed", "url", u.URL)
	s.renderIndex(w, r, map[string]any{"Message": "Gateway gespeichert."})
}

func (s *Server) fingerprint(w http.ResponseWriter, r *http.Request) {
	up, _, _ := s.Store.Upstream()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	fp, err := proxy.Fingerprint(ctx, up.URL)
	if err != nil {
		s.renderIndex(w, r, map[string]any{"Error": "Zertifikat konnte nicht abgerufen werden: " + err.Error()})
		return
	}
	up.PinSHA256 = fp
	s.renderIndex(w, r, map[string]any{"Upstream": up,
		"Message": "Fingerprint abgerufen. Bitte mit dem Zertifikat des Gateways vergleichen und dann speichern."})
}

func (s *Server) testUpstream(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	n, err := s.Proxy.TestUpstream(ctx)
	if err != nil {
		s.renderIndex(w, r, map[string]any{"Error": "Verbindung fehlgeschlagen: " + err.Error()})
		return
	}
	s.renderIndex(w, r, map[string]any{"Message": "Verbindung ok, " + strconv.Itoa(n) + " Site(s) gefunden."})
}

// --- clients ---

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' })
}

func (s *Server) newClientPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "client_new", map[string]any{"Templates": rules.Templates,
		"SuggestedIP": proxy.ClientIP(r, s.TrustedProxies).String(), "Rate": 120})
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	form := map[string]any{"Templates": rules.Templates, "Name": r.PostFormValue("name"),
		"Template": r.PostFormValue("template"), "Domains": r.PostFormValue("domains"),
		"SuggestedIP": r.PostFormValue("allowed_ips"), "Rate": r.PostFormValue("rate")}
	fail := func(msg string) {
		form["Error"] = msg
		s.render(w, r, "client_new", form)
	}
	tpl, ok := rules.TemplateByID(r.PostFormValue("template"))
	if !ok {
		fail("Bitte eine Vorlage wählen.")
		return
	}
	domains := splitList(r.PostFormValue("domains"))
	if tpl.NeedsDomains && len(domains) == 0 {
		fail("Diese Vorlage braucht mindestens eine Domain, z. B. *.example.com")
		return
	}
	ips := splitList(r.PostFormValue("allowed_ips"))
	if len(ips) == 0 {
		fail("Mindestens eine erlaubte IP-Adresse angeben.")
		return
	}
	rate, _ := strconv.Atoi(r.PostFormValue("rate"))
	c, key, err := s.Store.CreateClient(store.Client{Name: r.PostFormValue("name"), Enabled: true, AllowedIPs: ips,
		Rules: tpl.Rules(domains), RatePerMinute: rate})
	if err != nil {
		fail(err.Error())
		return
	}
	s.Log.Info("client created", "client", c.Name, "id", c.ID)
	s.render(w, r, "client_created", map[string]any{"Client": c, "Key": key})
}

func (s *Server) editClientPage(w http.ResponseWriter, r *http.Request) {
	c, ok := s.Store.Client(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "client_edit", editData(c, c.Rules, nil))
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	stored, ok := s.Store.Client(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	c := stored
	c.Name = r.PostFormValue("name")
	c.Enabled = r.PostFormValue("enabled") == "on"
	c.AllowedIPs = splitList(r.PostFormValue("allowed_ips"))
	c.RatePerMinute, _ = strconv.Atoi(r.PostFormValue("rate"))
	mode := r.PostFormValue("rules_mode")
	if mode == "" {
		mode = "form"
	}
	var (
		rs    []rules.Rule
		cards []ruleCard
		err   error
	)
	switch mode {
	case "form":
		cards, rs, err = parseRuleForm(r.PostForm)
	case "json":
		rs, err = decodeJSONRules(r.PostFormValue("rules"))
	default:
		err = errors.New("Unbekannte Bearbeitungsart der Regeln.")
	}
	if err == nil {
		c.Rules = rs
		err = s.Store.UpdateClient(c)
	}
	if err != nil {
		// show the form again with the submitted input, the other editor shows the stored rules
		data := editData(c, stored.Rules, cards)
		if mode == "json" {
			data["RulesJSON"] = r.PostFormValue("rules")
			data["RulesMode"] = "json"
		}
		data["Error"] = err.Error()
		s.render(w, r, "client_edit", data)
		return
	}
	s.Log.Info("client changed", "client", c.Name, "id", c.ID)
	c, _ = s.Store.Client(c.ID)
	data := editData(c, c.Rules, nil)
	data["Message"] = "Gespeichert."
	s.render(w, r, "client_edit", data)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteClient(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Log.Info("client deleted", "id", id)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
