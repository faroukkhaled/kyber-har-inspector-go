package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivacyAndSignals(t *testing.T) {
	var h HAR
	json.Unmarshal([]byte(sample), &h)
	r := analyze(h)
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(r.Findings))
	}
	b, _ := json.Marshal(r)
	for _, secret := range []string{"private-query", "private-path", "private-value", "username"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("Sensitive data leaked")
		}
	}
}
func TestInvalidURL(t *testing.T) {
	var h HAR
	json.Unmarshal([]byte(`{"log":{"entries":[{"request":{"url":"file:///etc/passwd"}}]}}`), &h)
	if analyze(h).InvalidURLs != 1 {
		t.Fatal("Invalid scheme accepted")
	}
}

const sample = `{"log":{"entries":[{"request":{"url":"http://username:password@example.test/private-path?token=private-query","headers":[{"name":"Authorization","value":"private-value"}]},"response":{"status":200,"headers":[]},"time":100}]}}`
