package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	secret, err := LoadSecret(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUpstream(Upstream{URL: "https://192.168.1.1"}, "TOP-SECRET-KEY"); err != nil {
		t.Fatal(err)
	}
	c, key, err := s.CreateClient(Client{Name: " test ", Enabled: true, AllowedIPs: []string{"192.168.1.5", "192.168.1.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "test" || c.AllowedIPs[0] != "192.168.1.5/32" {
		t.Errorf("normalisation: %+v", c)
	}
	if err := s.SetPassword("correct horse battery"); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	for _, secretValue := range []string{"TOP-SECRET-KEY", key, "correct horse"} {
		if strings.Contains(string(raw), secretValue) {
			t.Errorf("config file contains %q in plain text", secretValue)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("config file mode %v", fi.Mode().Perm())
	}

	// reopen
	s, err = Open(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, k, _ := s.Upstream(); k != "TOP-SECRET-KEY" {
		t.Errorf("upstream key round trip: %q", k)
	}
	if _, ok := s.ClientByKey(key); !ok {
		t.Error("client key not found after reopen")
	}
	if !s.CheckPassword("correct horse battery") || s.CheckPassword("wrong") {
		t.Error("password check")
	}
	// empty key keeps the stored one
	s.SetUpstream(Upstream{URL: "https://192.168.1.2"}, "")
	if u, k, _ := s.Upstream(); k != "TOP-SECRET-KEY" || u.URL != "https://192.168.1.2" {
		t.Error("empty key must keep the stored key")
	}
	if _, _, err := s.CreateClient(Client{Name: "x", AllowedIPs: []string{"not-an-ip"}}); err == nil {
		t.Error("invalid ip accepted")
	}
	if err := s.DeleteClient(c.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ClientByKey(key); ok {
		t.Error("deleted client still works")
	}

	other := make([]byte, 32)
	other[0] = 1
	s2, _ := Open(path, other)
	if _, _, err := s2.Upstream(); err == nil {
		t.Error("wrong secret must fail")
	}
}
