// unifi-api-guard sits between applications and the UniFi Network integration api and only lets through what the
// rules of the application's own key allow.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hotte512/unifi-api-guard/internal/admin"
	"github.com/Hotte512/unifi-api-guard/internal/proxy"
	"github.com/Hotte512/unifi-api-guard/internal/store"
)

var version = "dev"

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func prefixes(name, def string) ([]netip.Prefix, error) {
	list := strings.FieldsFunc(env(name, def), func(r rune) bool { return r == ',' || r == ' ' })
	p, err := proxy.ParsePrefixes(list)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return p, nil
}

func main() {
	health := flag.Bool("healthcheck", false, "check the proxy port and exit (for docker healthchecks)")
	flag.Parse()
	if *health {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func healthcheck() int {
	addr := env("GUARD_PROXY_ADDR", ":8080")
	scheme := "http"
	if os.Getenv("GUARD_TLS_CERT") != "" {
		return 0 // not worth a tls client here, the process is running
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	res, err := c.Get(scheme + "://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(log *slog.Logger) error {
	dataDir := env("GUARD_DATA_DIR", "/data")
	secret, err := store.LoadSecret(env("GUARD_SECRET_FILE", filepath.Join(dataDir, "secret.key")))
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: the data directory must belong to uid 65532, on the host run: "+
			"chown 65532:65532 <host directory of %s>", err, dataDir)
	}
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "config.json"), secret)
	if err != nil {
		return err
	}
	trusted, err := prefixes("GUARD_TRUSTED_PROXIES", "")
	if err != nil {
		return err
	}
	adminAllow, err := prefixes("GUARD_ADMIN_ALLOW",
		"127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7")
	if err != nil {
		return err
	}

	audit := proxy.NewAudit(1000)
	ph := &proxy.Handler{Store: st, Audit: audit, TrustedProxies: trusted, Log: log.With("part", "proxy")}
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	certFile, keyFile := os.Getenv("GUARD_TLS_CERT"), os.Getenv("GUARD_TLS_KEY")
	info, err := guardInfo(env("GUARD_ADMIN_ADDR", ":8081"), certFile != "", env("GUARD_ADMIN_URL", ""))
	if err != nil {
		return err
	}
	// lets clients like NPMplus link to the admin ui; no secrets, the same for everyone
	proxyMux.HandleFunc("GET /guard/v1/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(info)
	})
	proxyMux.Handle("/", ph)

	as := &admin.Server{Store: st, Proxy: ph, Audit: audit, Allowed: adminAllow, TrustedProxies: trusted,
		SecureCookie: certFile != "" || env("GUARD_COOKIE_SECURE", "") == "true", Version: version,
		Log: log.With("part", "admin")}
	// the token only allows to set the first password and is useless afterwards; it is also kept in a file, so it
	// can still be found when the log is gone
	as.TokenFile = filepath.Join(dataDir, "setup-token")
	if st.HasPassword() {
		os.Remove(as.TokenFile)
	} else {
		as.SetupToken = store.RandomPassword()
		if err := os.WriteFile(as.TokenFile, []byte(as.SetupToken+"\n"), 0o600); err != nil {
			return err
		}
		log.Warn("no admin password yet, open the admin ui and enter this setup token (also in "+as.TokenFile+")",
			"setup_token", as.SetupToken)
	}
	if err := as.Init(); err != nil {
		return err
	}

	servers := []*http.Server{
		newServer(env("GUARD_PROXY_ADDR", ":8080"), proxyMux),
		newServer(env("GUARD_ADMIN_ADDR", ":8081"), as),
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			log.Info("listening", "addr", s.Addr, "tls", certFile != "")
			var err error
			if certFile != "" {
				err = s.ListenAndServeTLS(certFile, keyFile)
			} else {
				err = s.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	log.Info("unifi-api-guard started", "version", version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(shutdown)
	}
	return nil
}

// guardInfo builds the response of /guard/v1/info
func guardInfo(adminAddr string, tls bool, adminURL string) ([]byte, error) {
	_, portStr, err := net.SplitHostPort(adminAddr)
	if err != nil {
		return nil, fmt.Errorf("GUARD_ADMIN_ADDR: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("GUARD_ADMIN_ADDR: invalid port %q", portStr)
	}
	if adminURL != "" {
		u, err := url.Parse(adminURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("GUARD_ADMIN_URL must be an http(s) url, got %q", adminURL)
		}
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return json.Marshal(map[string]any{
		"product": "unifi-api-guard", "version": version,
		"admin_port": port, "admin_scheme": scheme, "admin_url": adminURL,
	})
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}
