package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
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

func TestRunJSONRemainsASortedArray(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Now()
	zPath := writeTestCertificate(t, directory, "z.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	aPath := writeTestCertificate(t, directory, "a.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-json", "-quiet", directory}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("JSON status = %d; stderr = %q", status, stderr.String())
	}
	var certificates []jsonCertificate
	if err := json.Unmarshal(stdout.Bytes(), &certificates); err != nil {
		t.Fatalf("JSON array is invalid: %v; output = %q", err, stdout.String())
	}
	if len(certificates) != 2 || certificates[0].Path != aPath || certificates[1].Path != zPath {
		t.Fatalf("JSON paths = %+v, want %s then %s", certificates, aPath, zPath)
	}
	if !strings.HasPrefix(stdout.String(), "[\n") {
		t.Fatalf("JSON output is not an indented array: %q", stdout.String())
	}
}

func TestRunJSONLinesEmitsOneCompactObjectPerCertificate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Now()
	wantPaths := map[string]bool{
		writeTestCertificate(t, directory, "first.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth):    true,
		writeTestCertificate(t, directory, "second.pem", now.Add(-time.Hour), now.Add(2*time.Hour), x509.ExtKeyUsageClientAuth): true,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-jsonl", directory}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("JSON Lines status = %d; stderr = %q", status, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != len(wantPaths) {
		t.Fatalf("JSON Lines output has %d lines, want %d: %q", len(lines), len(wantPaths), stdout.String())
	}
	for _, line := range lines {
		if strings.Contains(line, "\n") || !json.Valid([]byte(line)) {
			t.Fatalf("JSON Lines record is not compact valid JSON: %q", line)
		}
		var certificate jsonCertificate
		if err := json.Unmarshal([]byte(line), &certificate); err != nil {
			t.Fatal(err)
		}
		if !wantPaths[certificate.Path] {
			t.Errorf("unexpected JSON Lines certificate path %q", certificate.Path)
		}
		if certificate.Index == nil || *certificate.Index != 0 {
			t.Errorf("JSON Lines certificate index = %v, want 0", certificate.Index)
		}
		delete(wantPaths, certificate.Path)
	}
	if len(wantPaths) != 0 {
		t.Fatalf("JSON Lines output omitted paths %v", wantPaths)
	}
	if !strings.Contains(stderr.String(), "output=jsonl") {
		t.Fatalf("startup output %q does not identify JSON Lines mode", stderr.String())
	}
}

func TestRunJSONLinesWithNoCertificatesIsEmpty(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-jsonl", "-quiet", t.TempDir()}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("empty JSON Lines status = %d; stderr = %q", status, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("empty quiet JSON Lines output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunJSONLinesWriteFailureIsRuntimeError(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Now()
	writeTestCertificate(t, directory, "certificate.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-jsonl", "-quiet", directory}, errorWriter{}, &stderr)
	if status != exitRuntimeError {
		t.Fatalf("JSON Lines write-failure status = %d, want %d", status, exitRuntimeError)
	}
	if !strings.Contains(stderr.String(), `level=ERROR msg="write JSON Lines"`) {
		t.Fatalf("JSON Lines write-failure log = %q", stderr.String())
	}
}

func TestRunRejectsConflictingJSONModes(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-json", "-jsonl", t.TempDir()}, &stdout, &stderr)
	if status != exitUsageError {
		t.Fatalf("conflicting JSON status = %d, want %d", status, exitUsageError)
	}
	if !strings.Contains(stderr.String(), `options=json,jsonl`) {
		t.Fatalf("conflicting JSON log = %q", stderr.String())
	}
}

func TestRunRejectsConflictingIdentityModes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	tests := []struct {
		arguments []string
		options   string
	}{
		{arguments: []string{"-unique", "-duplicates", directory}, options: "unique,duplicates"},
		{arguments: []string{"-jsonl", "-unique", directory}, options: "jsonl,unique"},
		{arguments: []string{"-jsonl", "-duplicates", directory}, options: "jsonl,duplicates"},
	}
	for _, test := range tests {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if status := run(context.Background(), test.arguments, &stdout, &stderr); status != exitUsageError {
			t.Errorf("run(%v) status = %d, want %d", test.arguments, status, exitUsageError)
		}
		if !strings.Contains(stderr.String(), `options=`+test.options) {
			t.Errorf("run(%v) error = %q, want options=%s", test.arguments, stderr.String(), test.options)
		}
	}
}

func TestRunDuplicateModesGroupFilesAndBundleEntries(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	duplicatePath, bundlePath, singletonPath := writeDuplicateTestFixture(t, directory)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-duplicates", "-json", "-quiet", directory}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("duplicates status = %d; stderr = %q", status, stderr.String())
	}
	var duplicateGroups []jsonCertificateGroup
	if err := json.Unmarshal(stdout.Bytes(), &duplicateGroups); err != nil {
		t.Fatalf("decode duplicate groups: %v; output = %q", err, stdout.String())
	}
	if len(duplicateGroups) != 1 {
		t.Fatalf("duplicate groups = %+v, want one", duplicateGroups)
	}
	wantLocations := []certificateLocation{
		{Path: duplicatePath, Index: 0},
		{Path: bundlePath, Index: 0},
		{Path: bundlePath, Index: 1},
	}
	if len(duplicateGroups[0].Locations) != len(wantLocations) {
		t.Fatalf("locations = %+v, want %+v", duplicateGroups[0].Locations, wantLocations)
	}
	for index, location := range duplicateGroups[0].Locations {
		if location != wantLocations[index] {
			t.Errorf("location %d = %+v, want %+v", index, location, wantLocations[index])
		}
	}

	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{"-unique", "-json", "-quiet", directory}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("unique status = %d; stderr = %q", status, stderr.String())
	}
	var uniqueGroups []jsonCertificateGroup
	if err := json.Unmarshal(stdout.Bytes(), &uniqueGroups); err != nil {
		t.Fatalf("decode unique groups: %v; output = %q", err, stdout.String())
	}
	if len(uniqueGroups) != 2 {
		t.Fatalf("unique group count = %d, want 2", len(uniqueGroups))
	}
	if uniqueGroups[1].Locations[0].Path != singletonPath {
		t.Errorf("singleton group = %+v, want path %q", uniqueGroups[1], singletonPath)
	}

	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{"-json", "-quiet", directory}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("default JSON status = %d; stderr = %q", status, stderr.String())
	}
	var certificates []jsonCertificate
	if err := json.Unmarshal(stdout.Bytes(), &certificates); err != nil {
		t.Fatalf("decode default JSON: %v; output = %q", err, stdout.String())
	}
	if len(certificates) != 4 {
		t.Fatalf("default JSON certificate count = %d, want 4", len(certificates))
	}
	wantLocations = []certificateLocation{
		{Path: duplicatePath, Index: 0},
		{Path: bundlePath, Index: 0},
		{Path: bundlePath, Index: 1},
		{Path: singletonPath, Index: 0},
	}
	for index, certificate := range certificates {
		if certificate.Index == nil {
			t.Errorf("certificate %d has no JSON index", index)
			continue
		}
		location := certificateLocation{Path: certificate.Path, Index: *certificate.Index}
		if location != wantLocations[index] {
			t.Errorf("certificate location %d = %+v, want %+v", index, location, wantLocations[index])
		}
	}
}

func TestRunTextReportsCertificateIndices(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	duplicatePath, bundlePath, singletonPath := writeDuplicateTestFixture(t, directory)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := run(context.Background(), []string{"-quiet", directory}, &stdout, &stderr); status != exitSuccess {
		t.Fatalf("status = %d; stderr = %q", status, stderr.String())
	}
	for _, header := range []string{
		duplicatePath + " [index 0]\n",
		bundlePath + " [index 0]\n",
		bundlePath + " [index 1]\n",
		singletonPath + " [index 0]\n",
	} {
		if !strings.Contains(stdout.String(), header) {
			t.Errorf("text output %q does not contain %q", stdout.String(), header)
		}
	}
}

func TestRunDuplicateModesTextAndFiltering(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	duplicatePath, bundlePath, singletonPath := writeDuplicateTestFixture(t, directory)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-duplicates", "-quiet", directory}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("duplicates status = %d; stderr = %q", status, stderr.String())
	}
	for _, wanted := range []string{
		duplicatePath + " [index 0]",
		bundlePath + " [index 0]",
		bundlePath + " [index 1]",
	} {
		if !strings.Contains(stdout.String(), wanted) {
			t.Errorf("duplicate text %q does not contain %q", stdout.String(), wanted)
		}
	}
	if strings.Contains(stdout.String(), singletonPath) {
		t.Errorf("duplicate text %q contains singleton path %q", stdout.String(), singletonPath)
	}
	if count := strings.Count(stdout.String(), "  SHA-256 fingerprint:"); count != 1 {
		t.Errorf("duplicate text contains %d SHA-256 fingerprints, want 1: %q", count, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	status = run(
		context.Background(),
		[]string{"-unique", "-usage=client", "-json", "-quiet", directory},
		&stdout,
		&stderr,
	)
	if status != exitSuccess {
		t.Fatalf("filtered unique status = %d; stderr = %q", status, stderr.String())
	}
	var groups []jsonCertificateGroup
	if err := json.Unmarshal(stdout.Bytes(), &groups); err != nil {
		t.Fatalf("decode filtered groups: %v; output = %q", err, stdout.String())
	}
	if len(groups) != 1 || len(groups[0].Locations) != 1 || groups[0].Locations[0].Path != singletonPath {
		t.Fatalf("filtered groups = %+v, want only %q", groups, singletonPath)
	}
}

func TestRunSummaryIncludesCertificateIdentityCounts(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeDuplicateTestFixture(t, directory)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if status := run(context.Background(), []string{directory}, &stdout, &stderr); status != exitSuccess {
		t.Fatalf("status = %d; stderr = %q", status, stderr.String())
	}
	want := "4 certificates found; 4 certificates matched; 2 unique certificates; 2 duplicate occurrences;"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("summary %q does not contain %q", stderr.String(), want)
	}

	stdout.Reset()
	stderr.Reset()
	if status := run(context.Background(), []string{"-usage=client", directory}, &stdout, &stderr); status != exitSuccess {
		t.Fatalf("filtered status = %d; stderr = %q", status, stderr.String())
	}
	want = "4 certificates found; 1 certificate matched; 1 unique certificate; 0 duplicate occurrences;"
	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("filtered summary %q does not contain %q", stderr.String(), want)
	}
}

func TestRunQuietSuppressesProgressButPreservesErrors(t *testing.T) {
	t.Parallel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-quiet", t.TempDir()}, &stdout, &stderr)
	if status != exitSuccess || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("quiet scan status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	missing := filepath.Join(t.TempDir(), "missing")
	status = run(context.Background(), []string{"-quiet", missing}, &stdout, &stderr)
	if status != exitRuntimeError {
		t.Fatalf("quiet failed scan status = %d, want %d", status, exitRuntimeError)
	}
	if !strings.Contains(stderr.String(), `level=ERROR msg="scan failed"`) {
		t.Fatalf("quiet failed scan did not preserve its error: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "certfinder dev") || strings.Contains(stderr.String(), "Scan stopped") {
		t.Fatalf("quiet failed scan emitted progress: %q", stderr.String())
	}
}

func TestRunMonitoringExitStatuses(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name       string
		notAfter   time.Time
		usage      x509.ExtKeyUsage
		options    []string
		wantStatus int
	}{
		{
			name:       "expired shortcut finds expired",
			notAfter:   now.Add(-time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-fail-expired"},
			wantStatus: exitOperationalFinding,
		},
		{
			name:       "expired shortcut accepts valid",
			notAfter:   now.Add(24 * time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-fail-expired"},
			wantStatus: exitSuccess,
		},
		{
			name:       "expiration window finds soon expiration",
			notAfter:   now.Add(12 * time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-fail-expiring=24h"},
			wantStatus: exitOperationalFinding,
		},
		{
			name:       "expiration window accepts later expiration",
			notAfter:   now.Add(48 * time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-fail-expiring=24h"},
			wantStatus: exitSuccess,
		},
		{
			name:       "expiration window includes expired",
			notAfter:   now.Add(-time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-fail-expiring=24h"},
			wantStatus: exitOperationalFinding,
		},
		{
			name:       "usage filter narrows monitoring scope",
			notAfter:   now.Add(-time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-usage=client", "-fail-expired"},
			wantStatus: exitSuccess,
		},
		{
			name:       "expiration filter narrows monitoring scope",
			notAfter:   now.Add(48 * time.Hour),
			usage:      x509.ExtKeyUsageServerAuth,
			options:    []string{"-expiration=24h", "-fail-expiring=72h"},
			wantStatus: exitSuccess,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			writeTestCertificate(t, directory, "certificate.pem", now.Add(-24*time.Hour), test.notAfter, test.usage)
			arguments := append(append([]string{}, test.options...), "-quiet", directory)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			status := run(context.Background(), arguments, &stdout, &stderr)
			if status != test.wantStatus {
				t.Fatalf("status = %d, want %d; stdout=%q stderr=%q", status, test.wantStatus, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunRejectsInvalidMonitoringOptions(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for _, arguments := range [][]string{
		{"-fail-expired", "-fail-expiring=0d", directory},
		{"-fail-expiring=-1h", directory},
		{"-fail-expiring=tomorrow", directory},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if status := run(context.Background(), arguments, &stdout, &stderr); status != exitUsageError {
			t.Fatalf("run(%v) status = %d, want %d", arguments, status, exitUsageError)
		}
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

func TestRunRejectsInvalidHostnameFilters(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for _, value := range []string{"", "*.example.test", "https://example.test", "bad name", "[2001:db8::1"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		arguments := []string{"-hostname=" + value, directory}
		if status := run(context.Background(), arguments, &stdout, &stderr); status != exitUsageError {
			t.Errorf("-hostname=%q status = %d, want %d", value, status, exitUsageError)
		}
		if !strings.Contains(stderr.String(), "invalid value") {
			t.Errorf("-hostname=%q error = %q, want a useful invalid-value error", value, stderr.String())
		}
	}
}

func TestRunHostnameFilterReturnsSameSetInEveryOutputMode(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Now()
	wantPath := writeTestCertificateWithSANs(
		t, directory, "match.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth,
		[]string{"service.example.test"}, nil,
	)
	otherPath := writeTestCertificateWithSANs(
		t, directory, "other.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth,
		[]string{"other.example.test"}, nil,
	)

	tests := []struct {
		name    string
		options []string
	}{
		{name: "text"},
		{name: "JSON", options: []string{"-json"}},
		{name: "JSON Lines", options: []string{"-jsonl"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			arguments := append(append([]string{}, test.options...), "-quiet", "-hostname=service.example.test", directory)
			if status := run(context.Background(), arguments, &stdout, &stderr); status != exitSuccess {
				t.Fatalf("status = %d; stderr = %q", status, stderr.String())
			}
			if !strings.Contains(stdout.String(), wantPath) || strings.Contains(stdout.String(), otherPath) {
				t.Fatalf("output = %q, want only %q", stdout.String(), wantPath)
			}
		})
	}
}

func TestRunHostnameFilterAcceptsIPAddresses(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Now()
	wantPath := writeTestCertificateWithSANs(
		t, directory, "match.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth, nil,
		[]net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
	)
	writeTestCertificateWithSANs(
		t, directory, "other.pem", now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth, nil,
		[]net.IP{net.ParseIP("192.0.2.11"), net.ParseIP("2001:db8::11")},
	)

	for _, hostname := range []string{"192.0.2.10", "[2001:db8::10]"} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		arguments := []string{"-json", "-quiet", "-hostname=" + hostname, directory}
		if status := run(context.Background(), arguments, &stdout, &stderr); status != exitSuccess {
			t.Fatalf("-hostname=%q status = %d; stderr = %q", hostname, status, stderr.String())
		}
		var certificates []jsonCertificate
		if err := json.Unmarshal(stdout.Bytes(), &certificates); err != nil {
			t.Fatalf("decode -hostname=%q output: %v", hostname, err)
		}
		if len(certificates) != 1 || certificates[0].Path != wantPath {
			t.Errorf("-hostname=%q paths = %+v, want only %q", hostname, certificates, wantPath)
		}
	}
}

func TestRunHostnameFilterComposesWithOtherFilters(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	now := time.Now()
	dnsNames := []string{"service.example.test"}
	wantPath := writeTestCertificateWithSANs(
		t, directory, "match.pem", now.Add(-time.Hour), now.Add(12*time.Hour), x509.ExtKeyUsageServerAuth, dnsNames, nil,
	)
	writeTestCertificateWithSANs(
		t, directory, "client.pem", now.Add(-time.Hour), now.Add(12*time.Hour), x509.ExtKeyUsageClientAuth, dnsNames, nil,
	)
	writeTestCertificateWithSANs(
		t, directory, "later.pem", now.Add(-time.Hour), now.Add(48*time.Hour), x509.ExtKeyUsageServerAuth, dnsNames, nil,
	)
	expiredPath := writeTestCertificateWithSANs(
		t, directory, "expired.pem", now.Add(-48*time.Hour), now.Add(-time.Hour), x509.ExtKeyUsageServerAuth, dnsNames, nil,
	)
	writeTestCertificateWithSANs(
		t, directory, "other-name.pem", now.Add(-time.Hour), now.Add(12*time.Hour), x509.ExtKeyUsageServerAuth,
		[]string{"other.example.test"}, nil,
	)

	tests := []struct {
		name      string
		options   []string
		wantPaths []string
	}{
		{
			name:      "usage and expiration",
			options:   []string{"-usage=server", "-expiration=24h"},
			wantPaths: []string{expiredPath, wantPath},
		},
		{
			name:      "expired shortcut",
			options:   []string{"-expired"},
			wantPaths: []string{expiredPath},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			arguments := append([]string{"-json", "-quiet", "-hostname=service.example.test"}, test.options...)
			arguments = append(arguments, directory)
			if status := run(context.Background(), arguments, &stdout, &stderr); status != exitSuccess {
				t.Fatalf("status = %d; stderr = %q", status, stderr.String())
			}
			var certificates []jsonCertificate
			if err := json.Unmarshal(stdout.Bytes(), &certificates); err != nil {
				t.Fatalf("decode JSON: %v; output = %q", err, stdout.String())
			}
			if len(certificates) != len(test.wantPaths) {
				t.Fatalf("paths = %+v, want %v", certificates, test.wantPaths)
			}
			for index, certificate := range certificates {
				if certificate.Path != test.wantPaths[index] {
					t.Errorf("path %d = %q, want %q", index, certificate.Path, test.wantPaths[index])
				}
			}
		})
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

func TestRunRuntimeErrorsTakePrecedenceOverOperationalFindings(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	now := time.Now()
	writeTestCertificate(t, root, "expired.pem", now.Add(-24*time.Hour), now.Add(-time.Hour), x509.ExtKeyUsageServerAuth)
	if err := os.Symlink(filepath.Join(root, "missing.pem"), filepath.Join(root, "broken.pem")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	for _, test := range []struct {
		name       string
		options    []string
		wantStatus int
	}{
		{
			name:       "scan error",
			options:    []string{"-quiet", "-follow-symlinks", "-fail-expired"},
			wantStatus: exitRuntimeError,
		},
		{
			name:       "ignored scan error",
			options:    []string{"-quiet", "-follow-symlinks", "-ignore-errors", "-fail-expired"},
			wantStatus: exitOperationalFinding,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			arguments := append(append([]string{}, test.options...), root)
			if status := run(context.Background(), arguments, &stdout, &stderr); status != test.wantStatus {
				t.Fatalf("status = %d, want %d; stderr = %q", status, test.wantStatus, stderr.String())
			}
			if !strings.Contains(stderr.String(), `level=WARN msg="path scan failed"`) {
				t.Fatalf("quiet mode suppressed warning: %q", stderr.String())
			}
			if strings.Contains(stderr.String(), "certfinder dev") || strings.Contains(stderr.String(), "Scan complete") {
				t.Fatalf("quiet mode emitted progress: %q", stderr.String())
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
		Index:                 2,
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
		"/certificates/server.pem [index 2]\n",
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
	if !certificateMatches(server, scanner.UsageServer, "", 0, false, now) {
		t.Fatal("server certificate did not match the server usage filter")
	}
	if certificateMatches(server, scanner.UsageClient, "", 0, false, now) {
		t.Fatal("server certificate matched the client usage filter")
	}
	if !certificateMatches(server, "", "", 24*time.Hour, true, now) {
		t.Fatal("certificate expiring in 12 hours did not match a 24-hour window")
	}
	if certificateMatches(server, "", "", 6*time.Hour, true, now) {
		t.Fatal("certificate expiring in 12 hours matched a 6-hour window")
	}

	unrestricted := server
	unrestricted.ExtendedKeyUsage = nil
	unrestricted.ExtendedKeyUsageUnrestricted = true
	if !certificateMatches(unrestricted, scanner.UsageClient, "", 0, false, now) {
		t.Fatal("unrestricted certificate did not match the client usage filter")
	}

	expired := server
	expired.NotAfter = now.Add(-time.Second)
	if !certificateMatches(expired, "", "", 0, true, now) {
		t.Fatal("expired certificate did not match a zero-day expiration window")
	}
	if !certificateMatches(expired, "", "", 24*time.Hour, true, now) {
		t.Fatal("expired certificate did not match a future expiration window")
	}
}

func TestPrintJSON(t *testing.T) {
	t.Parallel()
	certificate := scanner.Certificate{
		Path:                         "/certificates/server.pem",
		Index:                        2,
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
		`"index": 2`,
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

func writeTestCertificate(
	t *testing.T,
	directory string,
	name string,
	notBefore time.Time,
	notAfter time.Time,
	usage x509.ExtKeyUsage,
) string {
	t.Helper()
	return writeTestCertificateWithSANs(t, directory, name, notBefore, notAfter, usage, nil, nil)
}

func writeTestCertificateWithSANs(
	t *testing.T,
	directory string,
	name string,
	notBefore time.Time,
	notAfter time.Time,
	usage x509.ExtKeyUsage,
	dnsNames []string,
	ipAddresses []net.IP,
) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificatePath := filepath.Join(directory, name)
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath
}

func writeDuplicateTestFixture(t *testing.T, directory string) (string, string, string) {
	t.Helper()
	now := time.Now()
	duplicatePath := writeTestCertificate(
		t,
		directory,
		"a-duplicate.pem",
		now.Add(-time.Hour),
		now.Add(time.Hour),
		x509.ExtKeyUsageServerAuth,
	)
	certificatePEM, err := os.ReadFile(duplicatePath) //nolint:gosec // The test path is confined to t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "b-bundle.pem")
	bundle := make([]byte, 0, len(certificatePEM)*2)
	bundle = append(bundle, certificatePEM...)
	bundle = append(bundle, certificatePEM...)
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil { //nolint:gosec // The test path is confined to t.TempDir.
		t.Fatal(err)
	}
	singletonPath := writeTestCertificate(
		t,
		directory,
		"c-singleton.pem",
		now.Add(-time.Hour),
		now.Add(time.Hour),
		x509.ExtKeyUsageClientAuth,
	)
	return duplicatePath, bundlePath, singletonPath
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
