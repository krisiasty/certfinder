package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

func TestRunHelp(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if status := run(context.Background(), []string{"-h"}, &stdout, &stderr); status != 0 {
		t.Fatalf("help status = %d, want 0", status)
	}
	if !strings.Contains(stderr.String(), "Usage: certfinder [options] PATH") {
		t.Fatalf("help output = %q", stderr.String())
	}
}

func TestRunRequiresPath(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if status := run(context.Background(), nil, &stdout, &stderr); status != 2 {
		t.Fatalf("missing-path status = %d, want 2", status)
	}
}

func TestRunJSONWithNoCertificates(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	status := run(context.Background(), []string{"-json", t.TempDir()}, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("JSON status = %d, stderr = %q", status, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("empty JSON output = %q, want []", stdout.String())
	}
}

func TestRunRejectsConflictingExpirationFilters(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	status := run(context.Background(), []string{"-expired", "-expiration=30d", "."}, &stdout, &stderr)
	if status != 2 {
		t.Fatalf("conflicting-filter status = %d, want 2", status)
	}
	if !strings.Contains(stderr.String(), `level=ERROR msg="conflicting options"`) {
		t.Fatalf("conflicting-filter log = %q", stderr.String())
	}
}

func TestPrintCertificateIncludesIssuerAndValidity(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	printCertificate(&output, scanner.Certificate{
		Path:                  "/certificates/server.pem",
		Subject:               "CN=server.example",
		Issuer:                "CN=Example Test CA",
		SANs:                  []string{"DNS:server.example"},
		ExtendedKeyUsage:      []string{scanner.UsageServer},
		SHA1Fingerprint:       "112233",
		SHA256Fingerprint:     "aabbcc",
		SPKISHA256Fingerprint: "ddeeff",
		NotBefore:             time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("test", 3600)),
		NotAfter:              time.Date(2027, time.January, 2, 3, 4, 5, 0, time.FixedZone("test", 3600)),
	})

	wantParts := []string{
		"  Issuer: CN=Example Test CA\n",
		"  Extended key usage: server\n",
		"  SHA-1 fingerprint: 112233\n",
		"  SHA-256 fingerprint: aabbcc\n",
		"  SPKI SHA-256 fingerprint: ddeeff\n",
		"  Valid from: 2026-01-02T02:04:05Z\n",
		"  Valid to: 2027-01-02T02:04:05Z\n",
	}
	for _, want := range wantParts {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q does not contain %q", output.String(), want)
		}
	}
}

func TestParseExpiration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "0d", want: 0},
		{value: "30d", want: 30 * 24 * time.Hour},
		{value: "48h", want: 48 * time.Hour},
		{value: "90m", want: 90 * time.Minute},
	}
	for _, test := range tests {
		duration, present, err := parseExpiration(test.value)
		if err != nil {
			t.Fatalf("parseExpiration(%q): %v", test.value, err)
		}
		if !present || duration != test.want {
			t.Fatalf("parseExpiration(%q) = %v, %v; want %v, true", test.value, duration, present, test.want)
		}
	}
	if _, _, err := parseExpiration("tomorrow"); err == nil {
		t.Fatal("invalid expiration did not return an error")
	}
}

func TestNormalizeUsage(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"server":       scanner.UsageServer,
		"server-auth":  scanner.UsageServer,
		"CLIENT":       scanner.UsageClient,
		"email":        scanner.UsageEmailProtection,
		"ocsp-signing": scanner.UsageOCSPSigning,
	}
	for value, want := range tests {
		usage, err := normalizeUsage(value)
		if err != nil {
			t.Fatalf("normalizeUsage(%q): %v", value, err)
		}
		if usage != want {
			t.Fatalf("normalizeUsage(%q) = %q, want %q", value, usage, want)
		}
	}
	if _, err := normalizeUsage("web-browsing"); err == nil {
		t.Fatal("unsupported usage did not return an error")
	}
}

func TestCertificateFilters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	server := scanner.Certificate{
		ExtendedKeyUsage: []string{scanner.UsageServer},
		NotAfter:         now.Add(12 * time.Hour),
	}
	if !certificateMatches(server, scanner.UsageServer, 0, false, now) {
		t.Fatal("server certificate did not match the server usage filter")
	}
	if certificateMatches(server, scanner.UsageClient, 0, false, now) {
		t.Fatal("server certificate matched the client usage filter")
	}
	if !certificateMatches(server, "", 24*time.Hour, true, now) {
		t.Fatal("certificate expiring in 12 hours did not match a 24-hour window")
	}
	if certificateMatches(server, "", 6*time.Hour, true, now) {
		t.Fatal("certificate expiring in 12 hours matched a 6-hour window")
	}

	unrestricted := server
	unrestricted.ExtendedKeyUsage = nil
	unrestricted.ExtendedKeyUsageUnrestricted = true
	if !certificateMatches(unrestricted, scanner.UsageClient, 0, false, now) {
		t.Fatal("unrestricted certificate did not match the client usage filter")
	}

	expired := server
	expired.NotAfter = now.Add(-time.Second)
	if !certificateMatches(expired, "", 0, true, now) {
		t.Fatal("expired certificate did not match a zero-day expiration window")
	}
	if !certificateMatches(expired, "", 24*time.Hour, true, now) {
		t.Fatal("expired certificate did not match a future expiration window")
	}
}

func TestPrintJSON(t *testing.T) {
	t.Parallel()
	certificate := scanner.Certificate{
		Path:                         "/certificates/server.pem",
		Subject:                      "CN=server.example",
		Issuer:                       "CN=Example Test CA",
		SANs:                         []string{"DNS:server.example"},
		ExtendedKeyUsage:             []string{scanner.UsageServer},
		ExtendedKeyUsageUnrestricted: false,
		SHA1Fingerprint:              "112233",
		SHA256Fingerprint:            "aabbcc",
		SPKISHA256Fingerprint:        "ddeeff",
		NotBefore:                    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:                     time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	var output bytes.Buffer
	if err := printJSON(&output, []scanner.Certificate{certificate}); err != nil {
		t.Fatal(err)
	}
	wantParts := []string{
		`"path": "/certificates/server.pem"`,
		`"extended_key_usage": [`,
		`"fingerprints": {`,
		`"sha1": "112233"`,
		`"sha256": "aabbcc"`,
		`"spki_sha256": "ddeeff"`,
		`"valid_from": "2026-01-01T00:00:00Z"`,
		`"valid_to": "2027-01-01T00:00:00Z"`,
	}
	for _, want := range wantParts {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("JSON output %q does not contain %q", output.String(), want)
		}
	}
}
