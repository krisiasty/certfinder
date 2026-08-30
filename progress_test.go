package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

func TestProgressDisplayPrintsConfigurationProgressAndCertificate(t *testing.T) {
	t.Parallel()
	var progressOutput bytes.Buffer
	var certificateOutput bytes.Buffer
	display := newProgressDisplay(&progressOutput, &certificateOutput, true, false)
	display.Start(scanConfiguration{
		Path:              ".",
		Workers:           4,
		MaxBytes:          scanner.DefaultMaxBytes,
		Exclude:           []string{".git", "cache"},
		Extensions:        []string{".pem", ".crt"},
		OneFileSystem:     true,
		FollowSymlinks:    true,
		IgnoreErrors:      true,
		Usage:             scanner.UsageServer,
		Hostname:          "service.example.test",
		Expiration:        "30d",
		FailExpiring:      "14d",
		Verify:            true,
		Roots:             []string{"/etc/private-root.pem"},
		RootsOnly:         true,
		Archives:          true,
		ArchiveMaxBytes:   scanner.DefaultArchiveMaxBytes,
		ArchiveMaxEntries: scanner.DefaultArchiveMaxEntries,
		ArchiveMaxDepth:   scanner.DefaultArchiveMaxDepth,
		IdentityMode:      identityModeDuplicates,
		Output:            outputText,
	})
	display.Update(scanner.Progress{
		FilesDiscovered:          10,
		FilesScanned:             4,
		ArchiveEntriesDiscovered: 3,
		ArchiveEntriesScanned:    2,
		CertificatesFound:        1,
	})
	display.Certificate(scanner.Certificate{
		Path:      "/certificates/server.pem",
		Subject:   "CN=server.example",
		Issuer:    "CN=Example Test CA",
		NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	display.Update(scanner.Progress{
		FilesDiscovered:          10,
		FilesScanned:             10,
		FilesCapped:              3,
		ArchiveEntriesDiscovered: 3,
		ArchiveEntriesScanned:    3,
		ArchiveEntriesCapped:     1,
		CertificatesFound:        1,
		DiscoveryComplete:        true,
	})
	display.SetIdentitySummary(certificateIdentitySummary{Matched: 1, Unique: 1})
	display.Stop(true)
	if err := display.Err(); err != nil {
		t.Fatal(err)
	}

	progressParts := []string{
		"certfinder dev\n",
		"Scan path:",
		"Workers: 4\n",
		"Options: max-bytes=65536 usage=server hostname=service.example.test expiration=30d fail-expiring=14d " +
			"identity=duplicates output=text quiet=false\n",
		"Traversal: exclude=.git,cache extensions=.pem,.crt one-file-system=true follow-symlinks=true ignore-errors=true\n",
		"Verification: enabled=true roots=/etc/private-root.pem roots-only=true\n",
		"Archives: enabled=true max-bytes=67108864 max-entries=10000 max-depth=3\n",
		"Scanning: 4/10 files scanned; 6 pending; 2/3 archive entries scanned; 1 certificate found; discovering files...\n",
		"Scan complete: 10 files scanned, 3 stopped at max-bytes; 3 archive entries scanned, 1 stopped at max-bytes; " +
			"1 certificate found; 1 certificate matched; " +
			"1 unique certificate; 0 duplicate occurrences; 0 errors;",
	}
	for _, part := range progressParts {
		if !strings.Contains(progressOutput.String(), part) {
			t.Fatalf("progress output %q does not contain %q", progressOutput.String(), part)
		}
	}
	if !strings.Contains(certificateOutput.String(), "Subject: CN=server.example") {
		t.Fatalf("certificate output = %q", certificateOutput.String())
	}
}

func TestProgressDisplayQuietModeSuppressesProgressOnly(t *testing.T) {
	t.Parallel()
	var progressOutput bytes.Buffer
	var certificateOutput bytes.Buffer
	display := newProgressDisplay(&progressOutput, &certificateOutput, true, true)
	display.Start(scanConfiguration{Path: ".", Workers: 1, Quiet: true})
	display.Update(scanner.Progress{FilesDiscovered: 1, FilesScanned: 1, DiscoveryComplete: true})
	display.Certificate(scanner.Certificate{
		Path:      "/certificates/server.pem",
		Subject:   "CN=server.example",
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	})
	display.Stop(true)
	if err := display.Err(); err != nil {
		t.Fatal(err)
	}
	if progressOutput.Len() != 0 {
		t.Fatalf("quiet progress output = %q, want empty", progressOutput.String())
	}
	if !strings.Contains(certificateOutput.String(), "Subject: CN=server.example") {
		t.Fatalf("quiet certificate output = %q", certificateOutput.String())
	}
}

func TestProgressDisplayReportsEncryptedPKCS12Content(t *testing.T) {
	t.Parallel()
	var progressOutput bytes.Buffer
	var resultOutput bytes.Buffer
	display := newProgressDisplay(&progressOutput, &resultOutput, true, false)
	display.Start(scanConfiguration{Path: ".", Workers: 1})
	finding := scanner.PKCS12EncryptedContent{
		Path: "/certificates/service.p12", ContentIndex: 2, Algorithm: "PBES2",
		AlgorithmOID: "1.2.840.113549.1.5.13",
	}
	display.Update(scanner.Progress{
		FilesDiscovered: 1, FilesScanned: 1, PKCS12Encrypted: 1, DiscoveryComplete: true,
	})
	display.PKCS12Encrypted(finding)
	display.Stop(true)
	if err := display.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(progressOutput.String(), "1 encrypted PKCS#12 content;") {
		t.Fatalf("progress output = %q", progressOutput.String())
	}
	for _, wanted := range []string{
		"/certificates/service.p12 [PKCS#12 content 2]",
		"certificates are unreadable without a password",
		"PBE algorithm: PBES2 (1.2.840.113549.1.5.13)",
		"Bag count: unknown",
	} {
		if !strings.Contains(resultOutput.String(), wanted) {
			t.Errorf("result output %q does not contain %q", resultOutput.String(), wanted)
		}
	}
}
