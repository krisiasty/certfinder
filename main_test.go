package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
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

func TestRunVersion(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if status := run(context.Background(), []string{"--version"}, &stdout, &stderr); status != 0 {
		t.Fatalf("version status = %d, want 0; stderr = %q", status, stderr.String())
	}
	if want := "certfinder dev (commit unknown, built unknown)\n"; stdout.String() != want {
		t.Fatalf("version output = %q, want %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("version stderr = %q, want empty", stderr.String())
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

func TestRunDisplaysTraversalOptions(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{
		"-exclude=.git",
		"-exclude=cache",
		"-extensions=pem,CRT",
		"-follow-symlinks",
		"-ignore-errors",
		t.TempDir(),
	}, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("traversal-options status = %d; stderr = %q", status, stderr.String())
	}
	want := "Traversal: exclude=.git,cache extensions=.pem,.crt one-file-system=false follow-symlinks=true ignore-errors=true\n"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("startup output %q does not contain %q", stderr.String(), want)
	}
}

func TestRunIgnoreErrorsControlsExitStatus(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "missing.pem"), filepath.Join(root, "broken.pem")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	for _, test := range []struct {
		name       string
		arguments  []string
		wantStatus int
		ignored    bool
	}{
		{name: "failure", arguments: []string{"-follow-symlinks", root}, wantStatus: 1},
		{name: "ignored", arguments: []string{"-follow-symlinks", "-ignore-errors", root}, wantStatus: 0, ignored: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if status := run(context.Background(), test.arguments, &stdout, &stderr); status != test.wantStatus {
				t.Fatalf("status = %d, want %d; stderr = %q", status, test.wantStatus, stderr.String())
			}
			if !strings.Contains(stderr.String(), "1 error") {
				t.Fatalf("summary %q does not retain the error count", stderr.String())
			}
			wantIgnored := fmt.Sprintf("ignored=%t", test.ignored)
			if !strings.Contains(stderr.String(), wantIgnored) {
				t.Fatalf("warning %q does not contain %q", stderr.String(), wantIgnored)
			}
		})
	}
}

func TestRunRejectsInvalidTraversalFlags(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		{"-exclude=[", "."},
		{"-extensions=", "."},
		{"-extensions=path/cert", "."},
		{"-extensions=*.pem", "."},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if status := run(context.Background(), arguments, &stdout, &stderr); status != 2 {
			t.Fatalf("run(%v) status = %d, want 2", arguments, status)
		}
	}
}

func TestPrintCertificateIncludesIssuerAndValidity(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	err := printCertificateAt(&output, scanner.Certificate{
		Path:                  "/certificates/server.pem",
		Subject:               "CN=server.example",
		Issuer:                "CN=Example Test CA",
		SerialNumber:          "abc123",
		IsCA:                  false,
		SelfSigned:            false,
		SANs:                  []string{"DNS:server.example"},
		KeyUsage:              []string{"digital-signature", "key-encipherment"},
		ExtendedKeyUsage:      []string{scanner.UsageServer},
		PublicKeyAlgorithm:    "RSA",
		PublicKeyBits:         2048,
		SignatureAlgorithm:    "SHA256-RSA",
		SHA1Fingerprint:       "112233",
		SHA256Fingerprint:     "aabbcc",
		SPKISHA256Fingerprint: "ddeeff",
		NotBefore:             time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("test", 3600)),
		NotAfter:              time.Date(2027, time.January, 2, 3, 4, 5, 0, time.FixedZone("test", 3600)),
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	wantParts := []string{
		"  Issuer: CN=Example Test CA\n",
		"  Serial number: abc123\n",
		"  Certificate type: leaf\n",
		"  Self-signed: no\n",
		"  Key usage: digital-signature, key-encipherment\n",
		"  Extended key usage: server\n",
		"  Public key: RSA (2048 bits)\n",
		"  Signature algorithm: SHA256-RSA\n",
		"  SHA-1 fingerprint: 112233\n",
		"  SHA-256 fingerprint: aabbcc\n",
		"  SPKI SHA-256 fingerprint: ddeeff\n",
		"  Valid from: 2026-01-02T02:04:05Z\n",
		"  Valid to: 2027-01-02T02:04:05Z\n",
		"  Validity status: valid\n",
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
		SerialNumber:                 "abc123",
		IsCA:                         true,
		SelfSigned:                   true,
		SANs:                         []string{"DNS:server.example"},
		KeyUsage:                     []string{"certificate-signing", "crl-signing"},
		ExtendedKeyUsage:             []string{scanner.UsageServer},
		ExtendedKeyUsageUnrestricted: false,
		PublicKeyAlgorithm:           "ECDSA",
		PublicKeyCurve:               "P-256",
		SignatureAlgorithm:           "ECDSA-SHA256",
		SHA1Fingerprint:              "112233",
		SHA256Fingerprint:            "aabbcc",
		SPKISHA256Fingerprint:        "ddeeff",
		NotBefore:                    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:                     time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	var output bytes.Buffer
	if err := printJSONAt(
		&output,
		[]scanner.Certificate{certificate},
		time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatal(err)
	}
	wantParts := []string{
		`"path": "/certificates/server.pem"`,
		`"serial_number": "abc123"`,
		`"is_ca": true`,
		`"self_signed": true`,
		`"key_usage": [`,
		`"extended_key_usage": [`,
		`"public_key": {`,
		`"algorithm": "ECDSA"`,
		`"curve": "P-256"`,
		`"signature_algorithm": "ECDSA-SHA256"`,
		`"fingerprints": {`,
		`"sha1": "112233"`,
		`"sha256": "aabbcc"`,
		`"spki_sha256": "ddeeff"`,
		`"valid_from": "2026-01-01T00:00:00Z"`,
		`"valid_to": "2027-01-01T00:00:00Z"`,
		`"validity_status": "valid"`,
	}
	for _, want := range wantParts {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("JSON output %q does not contain %q", output.String(), want)
		}
	}
}
