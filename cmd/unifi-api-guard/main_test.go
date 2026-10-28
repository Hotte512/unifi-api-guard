package main

import (
	"encoding/json"
	"testing"
)

func TestGuardInfo(t *testing.T) {
	raw, err := guardInfo(":8091", false, "")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["product"] != "unifi-api-guard" || got["admin_port"] != float64(8091) || got["admin_scheme"] != "http" {
		t.Errorf("unexpected info: %v", got)
	}
	if raw, _ := guardInfo("127.0.0.1:8443", true, "https://guard.example.com/"); !json.Valid(raw) {
		t.Error("tls variant")
	}
	for _, bad := range [][2]string{{"8091", ""}, {":x", ""}, {":8091", "ftp://example.com"}, {":8091", "nonsense"}} {
		if _, err := guardInfo(bad[0], false, bad[1]); err == nil {
			t.Errorf("guardInfo(%q, %q) should fail", bad[0], bad[1])
		}
	}
}
