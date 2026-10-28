// Package proxy forwards allowed requests to the UniFi Network integration api.
//
// Clients use the same paths and the same X-API-KEY header as with the gateway, so an application only needs the
// guard url and its own key.
package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hotte512/unifi-api-guard/internal/rules"
	"github.com/Hotte512/unifi-api-guard/internal/store"
)

// Prefix of the UniFi Network integration api, the only part of the gateway the guard forwards to.
const Prefix = "/proxy/network/integration/v1/"

const (
	maxRequestBody  = 1 << 20
	maxResponseBody = 16 << 20
	upstreamTimeout = 15 * time.Second
	pageSize        = 200
	maxPages        = 100
)

// Handler is the http handler of the proxy port.
type Handler struct {
	Store          *store.Store
	Audit          *Audit
	TrustedProxies []netip.Prefix
	Log            *slog.Logger

	limiter   limiter
	clientsMu sync.Mutex
	clients   map[string]*http.Client
}

type apiError struct {
	StatusCode int    `json:"statusCode"`
	StatusName string `json:"statusName"`
	Message    string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	name := strings.ToUpper(strings.ReplaceAll(http.StatusText(status), " ", "_"))
	json.NewEncoder(w).Encode(apiError{StatusCode: status, StatusName: name, Message: msg})
}

// ClientIP is the address of the tcp peer, X-Forwarded-For is only used when the peer is a trusted proxy.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := ap.Addr().Unmap()
	if !inPrefixes(ip, trusted) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip
		}
		hop = hop.Unmap()
		if !inPrefixes(hop, trusted) {
			return hop
		}
		ip = hop
	}
	return ip
}

func inPrefixes(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParsePrefixes parses a list of ips/cidrs.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	norm, err := store.NormalizeIPs(list)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(norm))
	for _, v := range norm {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := ClientIP(r, h.TrustedProxies)
	entry := Entry{Time: start, IP: ip.String(), Method: r.Method, Path: r.URL.EscapedPath()}
	status, reason := h.serve(w, r, ip, &entry)
	entry.Status, entry.Reason = status, reason
	entry.Allowed = reason == ""
	entry.Duration = time.Since(start)
	h.Audit.Add(entry)
	h.Log.Info("request", "client", entry.Client, "ip", entry.IP, "method", entry.Method, "path", entry.Path,
		"status", status, "allowed", entry.Allowed, "reason", reason)
}

// serve returns the status and, for denied requests, the reason
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, ip netip.Addr, entry *Entry) (int, string) {
	deny := func(status int, msg string) (int, string) {
		writeError(w, status, msg)
		return status, msg
	}

	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, Prefix) {
		return deny(http.StatusNotFound, "only "+Prefix+"* is available")
	}
	key := r.Header.Get("X-API-KEY")
	if key == "" {
		return deny(http.StatusUnauthorized, "missing X-API-KEY")
	}
	client, ok := h.Store.ClientByKey(key)
	if !ok {
		return deny(http.StatusUnauthorized, "invalid api key")
	}
	entry.Client = client.Name
	if !client.Enabled {
		return deny(http.StatusForbidden, "api key is disabled")
	}
	allowed, _ := ParsePrefixes(client.AllowedIPs)
	if !ip.IsValid() || !inPrefixes(ip, allowed) {
		return deny(http.StatusForbidden, "ip address not allowed for this api key")
	}
	if !h.limiter.allow(client.ID, client.RatePerMinute, time.Now()) {
		return deny(http.StatusTooManyRequests, "rate limit exceeded")
	}
	segs, err := rules.CleanPath(strings.TrimPrefix(escaped, Prefix))
	if err != nil {
		return deny(http.StatusBadRequest, "invalid path")
	}
	rule := rules.Match(client.Rules, r.Method, segs)
	if rule == nil {
		return deny(http.StatusForbidden, "not allowed for this api key")
	}

	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
		if err != nil {
			return deny(http.StatusRequestEntityTooLarge, "request body too large")
		}
	}

	up, err := h.upstream()
	if err != nil {
		h.Log.Error("upstream not usable", "error", err)
		return deny(http.StatusBadGateway, "upstream is not configured")
	}
	path := strings.Join(segs, "/")
	ctx := r.Context()

	if f := rule.Filter; f != nil {
		switch r.Method {
		case http.MethodGet:
			return h.filteredGet(ctx, w, up, path, r.URL.Query(), f)
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			var obj map[string]any
			if json.Unmarshal(body, &obj) != nil || !f.AllowsObject(obj) {
				return deny(http.StatusForbidden, fmt.Sprintf("%s not allowed for this api key", f.Field))
			}
		}
		// changing or deleting an existing object: the stored object has to match as well
		if r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if code, reason := h.checkExisting(ctx, up, path, f); code != 0 {
				return deny(code, reason)
			}
		}
	}

	res, err := up.do(ctx, r.Method, path, r.URL.RawQuery, body)
	if err != nil {
		h.Log.Warn("upstream request failed", "error", err)
		return deny(http.StatusBadGateway, "upstream request failed")
	}
	writeResponse(w, res)
	return res.status, ""
}

// checkExisting loads the object at path and returns a status != 0 if it may not be touched
func (h *Handler) checkExisting(ctx context.Context, up *upstream, path string, f *rules.Filter) (int, string) {
	res, err := up.do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return http.StatusBadGateway, "upstream request failed"
	}
	if res.status == http.StatusNotFound {
		return http.StatusNotFound, "not found"
	}
	var obj map[string]any
	if res.status != http.StatusOK || json.Unmarshal(res.body, &obj) != nil {
		return http.StatusBadGateway, "could not check the existing object"
	}
	if !f.AllowsObject(obj) {
		// do not tell whether a foreign object exists
		return http.StatusNotFound, "not found"
	}
	return 0, ""
}

type page struct {
	Offset     int              `json:"offset"`
	Limit      int              `json:"limit"`
	Count      int              `json:"count"`
	TotalCount int              `json:"totalCount"`
	Data       []map[string]any `json:"data"`
}

// filteredGet returns only objects matching the filter. Lists are loaded completely, filtered and paginated again,
// so offset, limit and totalCount stay consistent for the client.
func (h *Handler) filteredGet(ctx context.Context, w http.ResponseWriter, up *upstream, path string, q url.Values,
	f *rules.Filter) (int, string) {
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = 25
	}
	offset = max(offset, 0)
	q.Del("offset")
	q.Del("limit")

	// the first request is sent without paging parameters, it may as well be a single object
	var all []map[string]any
	seen := 0
	for i := 0; i < maxPages; i++ {
		if i > 0 {
			q.Set("offset", strconv.Itoa(seen))
			q.Set("limit", strconv.Itoa(pageSize))
		}
		res, err := up.do(ctx, http.MethodGet, path, q.Encode(), nil)
		if err != nil {
			writeError(w, http.StatusBadGateway, "upstream request failed")
			return http.StatusBadGateway, "upstream request failed"
		}
		if res.status != http.StatusOK {
			writeResponse(w, res)
			return res.status, ""
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(res.body, &raw) != nil {
			writeError(w, http.StatusBadGateway, "unexpected upstream response")
			return http.StatusBadGateway, "unexpected upstream response"
		}
		if _, ok := raw["data"]; !ok {
			// a single object
			var obj map[string]any
			if json.Unmarshal(res.body, &obj) != nil || !f.AllowsObject(obj) {
				writeError(w, http.StatusNotFound, "not found")
				return http.StatusNotFound, "filtered"
			}
			writeResponse(w, res)
			return res.status, ""
		}
		var p page
		if json.Unmarshal(res.body, &p) != nil {
			writeError(w, http.StatusBadGateway, "unexpected upstream response")
			return http.StatusBadGateway, "unexpected upstream response"
		}
		for _, obj := range p.Data {
			if f.AllowsObject(obj) {
				all = append(all, obj)
			}
		}
		seen += len(p.Data)
		if len(p.Data) == 0 || seen >= p.TotalCount {
			break
		}
	}

	out := page{Offset: offset, Limit: limit, TotalCount: len(all), Data: []map[string]any{}}
	if offset < len(all) {
		out.Data = all[offset:min(offset+limit, len(all))]
	}
	out.Count = len(out.Data)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(out)
	return http.StatusOK, ""
}

func writeResponse(w http.ResponseWriter, res *response) {
	if res.contentType != "" {
		w.Header().Set("Content-Type", res.contentType)
	}
	w.WriteHeader(res.status)
	w.Write(res.body)
}

// --- upstream ---

type upstream struct {
	base   string
	apiKey string
	client *http.Client
}

type response struct {
	status      int
	contentType string
	body        []byte
}

func (u *upstream) do(ctx context.Context, method, path, rawQuery string, body []byte) (*response, error) {
	target := u.base + Prefix + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	var rd io.Reader
	if body != nil && method != http.MethodGet && method != http.MethodDelete {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", u.apiKey)
	req.Header.Set("Accept", "application/json")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := u.client.Do(req)
	if err != nil {
		// the error of the http client contains the url, never the headers
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBody {
		return nil, errors.New("upstream response too large")
	}
	return &response{status: res.StatusCode, contentType: res.Header.Get("Content-Type"), body: data}, nil
}

func (h *Handler) upstream() (*upstream, error) {
	cfg, key, err := h.Store.Upstream()
	if err != nil {
		return nil, err
	}
	if cfg.URL == "" || key == "" {
		return nil, errors.New("upstream url or api key missing")
	}
	client, err := h.httpClient(cfg)
	if err != nil {
		return nil, err
	}
	return &upstream{base: strings.TrimRight(cfg.URL, "/"), apiKey: key, client: client}, nil
}

// httpClient keeps one client (and its connection pool) per tls setting
func (h *Handler) httpClient(cfg store.Upstream) (*http.Client, error) {
	id := fmt.Sprintf("%t|%s", cfg.VerifyTLS, cfg.PinSHA256)
	h.clientsMu.Lock()
	defer h.clientsMu.Unlock()
	if c, ok := h.clients[id]; ok {
		return c, nil
	}
	tlsCfg, err := TLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	c := &http.Client{
		Timeout: upstreamTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
		// redirects could carry the api key to another host
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if h.clients == nil {
		h.clients = map[string]*http.Client{}
	}
	h.clients[id] = c
	return c, nil
}

// TLSConfig builds the tls settings for the gateway: pinned certificate, normal ca check, or no check at all.
func TLSConfig(cfg store.Upstream) (*tls.Config, error) {
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(cfg.PinSHA256), ":", ""))
	if pin != "" {
		want, err := hex.DecodeString(pin)
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("certificate fingerprint must be a sha256 hex value")
		}
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			// the pin replaces the ca check, self-signed gateway certificates are the normal case
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if !bytes.Equal(sum[:], want) {
					return errors.New("certificate fingerprint does not match")
				}
				return nil
			},
		}, nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !cfg.VerifyTLS}, nil
}

// Fingerprint connects to the gateway and returns the sha256 of its certificate (for pinning on first use).
func Fingerprint(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("url must start with https://")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

// --- rate limit ---

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// allow implements a token bucket per client, perMinute 0 = unlimited
func (l *limiter) allow(id string, perMinute int, now time.Time) bool {
	if perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	b, ok := l.buckets[id]
	if !ok {
		b = &bucket{tokens: float64(perMinute), last: now}
		l.buckets[id] = b
	}
	b.tokens = min(float64(perMinute), b.tokens+now.Sub(b.last).Minutes()*float64(perMinute))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// TestUpstream checks url and api key by listing the sites, returns the number of sites.
func (h *Handler) TestUpstream(ctx context.Context) (int, error) {
	up, err := h.upstream()
	if err != nil {
		return 0, err
	}
	res, err := up.do(ctx, http.MethodGet, "sites", "", nil)
	if err != nil {
		return 0, err
	}
	if res.status != http.StatusOK {
		return 0, fmt.Errorf("gateway answered %d", res.status)
	}
	var p page
	if err := json.Unmarshal(res.body, &p); err != nil {
		return 0, errors.New("unexpected response, is this a UniFi Network 9.4+ gateway?")
	}
	return len(p.Data), nil
}
