// Package store keeps the configuration in a single json file (mode 0600) and handles all secrets:
// the UniFi api key is encrypted with AES-GCM, client keys and the admin password are only stored as hashes.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hotte512/unifi-api-guard/internal/rules"
)

// Upstream is the UniFi gateway the guard talks to.
type Upstream struct {
	URL       string `json:"url"`
	APIKeyEnc string `json:"api_key_enc"`
	VerifyTLS bool   `json:"verify_tls"`
	// PinSHA256 is the hex sha256 of the gateway's leaf certificate, used instead of the CA check when set
	PinSHA256 string `json:"pin_sha256"`
}

// Client is a key handed out to one application.
type Client struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	KeyHash       string       `json:"key_hash"`
	KeyHint       string       `json:"key_hint"`
	Enabled       bool         `json:"enabled"`
	AllowedIPs    []string     `json:"allowed_ips"`
	Rules         []rules.Rule `json:"rules"`
	RatePerMinute int          `json:"rate_per_minute"`
	CreatedAt     time.Time    `json:"created_at"`
}

// Data is the content of the config file.
type Data struct {
	Upstream      Upstream `json:"upstream"`
	Clients       []Client `json:"clients"`
	AdminPassword string   `json:"admin_password"`
}

// Store is safe for concurrent use.
type Store struct {
	mu     sync.RWMutex
	path   string
	aead   cipher.AEAD
	data   Data
	byHash map[string]*Client
}

const keyPrefix = "uag_"

// Open loads (or creates) the config file. secret is the 32 byte key for the UniFi api key encryption.
func Open(path string, secret []byte) (*Store, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, aead: aead}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	s.index()
	return s, nil
}

// LoadSecret reads the encryption key from file, or creates one. The file holds 32 random bytes, hex encoded.
func LoadSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		rand.Read(key)
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s: expected 64 hex characters", path)
	}
	return key, nil
}

func (s *Store) index() {
	s.byHash = make(map[string]*Client, len(s.data.Clients))
	for i := range s.data.Clients {
		s.byHash[s.data.Clients[i].KeyHash] = &s.data.Clients[i]
	}
}

// save writes atomically, the caller holds the write lock.
func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	s.index()
	return nil
}

// --- upstream ---

// Upstream returns the gateway settings and the decrypted api key.
func (s *Store) Upstream() (Upstream, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u := s.data.Upstream
	if u.APIKeyEnc == "" {
		return u, "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(u.APIKeyEnc)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return u, "", errors.New("stored api key is damaged")
	}
	plain, err := s.aead.Open(nil, raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():], []byte("upstream"))
	if err != nil {
		return u, "", errors.New("stored api key can not be decrypted (secret changed?)")
	}
	return u, string(plain), nil
}

// SetUpstream saves the gateway settings, an empty apiKey keeps the stored one.
func (s *Store) SetUpstream(u Upstream, apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u.APIKeyEnc = s.data.Upstream.APIKeyEnc
	if apiKey != "" {
		nonce := make([]byte, s.aead.NonceSize())
		rand.Read(nonce)
		u.APIKeyEnc = base64.StdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, []byte(apiKey), []byte("upstream")))
	}
	s.data.Upstream = u
	return s.save()
}

// --- clients ---

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ClientByKey returns a copy of the client owning key.
func (s *Store) ClientByKey(key string) (Client, bool) {
	if !strings.HasPrefix(key, keyPrefix) {
		return Client{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.byHash[hashKey(key)]
	if !ok {
		return Client{}, false
	}
	return *c, true
}

// Clients returns copies of all clients.
func (s *Store) Clients() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.data.Clients)
}

// Client returns a copy of one client.
func (s *Store) Client(id string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.data.Clients {
		if c.ID == id {
			return c, true
		}
	}
	return Client{}, false
}

// NormalizeIPs parses ip addresses and cidr ranges, single addresses become /32 or /128.
func NormalizeIPs(in []string) ([]string, error) {
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("invalid ip or cidr %q", v)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String())
	}
	return out, nil
}

func validateClient(c *Client) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return errors.New("name is required")
	}
	ips, err := NormalizeIPs(c.AllowedIPs)
	if err != nil {
		return err
	}
	c.AllowedIPs = ips
	if c.RatePerMinute < 0 {
		return errors.New("rate limit must not be negative")
	}
	return rules.Validate(c.Rules)
}

// CreateClient stores a new client and returns its key. The key is not stored and can not be shown again.
func (s *Store) CreateClient(c Client) (Client, string, error) {
	if err := validateClient(&c); err != nil {
		return Client{}, "", err
	}
	key := keyPrefix + randomString(32)
	c.ID = randomString(9)
	c.KeyHash = hashKey(key)
	c.KeyHint = key[:len(keyPrefix)+4] + "…"
	c.CreatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Clients = append(s.data.Clients, c)
	if err := s.save(); err != nil {
		s.data.Clients = s.data.Clients[:len(s.data.Clients)-1]
		s.index()
		return Client{}, "", err
	}
	return c, key, nil
}

// UpdateClient changes name, state, ips, rules and rate limit. The key stays the same.
func (s *Store) UpdateClient(c Client) error {
	if err := validateClient(&c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Clients {
		if s.data.Clients[i].ID == c.ID {
			old := s.data.Clients[i]
			c.KeyHash, c.KeyHint, c.CreatedAt = old.KeyHash, old.KeyHint, old.CreatedAt
			s.data.Clients[i] = c
			if err := s.save(); err != nil {
				s.data.Clients[i] = old
				s.index()
				return err
			}
			return nil
		}
	}
	return errors.New("client not found")
}

// DeleteClient removes a client, its key stops working at once.
func (s *Store) DeleteClient(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := slices.Clone(s.data.Clients)
	s.data.Clients = slices.DeleteFunc(s.data.Clients, func(c Client) bool { return c.ID == id })
	if err := s.save(); err != nil {
		s.data.Clients = old
		s.index()
		return err
	}
	return nil
}

// --- admin password ---

const pbkdf2Iterations = 600_000

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// HasPassword reports whether an admin password is set.
func (s *Store) HasPassword() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.AdminPassword != ""
}

// SetPassword sets the admin password (at least 12 characters).
func (s *Store) SetPassword(pw string) error {
	if len(pw) < 12 {
		return errors.New("the password needs at least 12 characters")
	}
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.AdminPassword = h
	return s.save()
}

// CheckPassword compares in constant time.
func (s *Store) CheckPassword(pw string) bool {
	s.mu.RLock()
	stored := s.data.AdminPassword
	s.mu.RUnlock()
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err1 := strconv.Atoi(parts[1])
	salt, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err3 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// RandomPassword returns a password for the first start.
func RandomPassword() string { return randomString(18) }
