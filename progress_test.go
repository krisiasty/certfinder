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
		Path:           ".",
		Workers:        4,
		MaxBytes:       scanner.DefaultMaxBytes,
		Exclude:        []string{".git", "cache"},
		Extensions:     []string{".pem", ".crt"},
		OneFileSystem:  true,
		FollowSymlinks: true,
		IgnoreErrors:   true,
		Usage:          scanner.UsageServer,
		Expiration:     "30d",
		FailExpiring:   "14d",
		Output:         outputText,
	})
	display.Update(scanner.Progress{
		FilesDiscovered:   10,
		FilesScanned:      4,
		CertificatesFound: 1,
	})
	display.Certificate(scanner.Certificate{
		Path:      "/certificates/server.pem",
		Subject:   "CN=server.example",
		Issuer:    "CN=Example Test CA",
		NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	display.Update(scanner.Progress{
		FilesDiscovered:   10,
		FilesScanned:      10,
		FilesCapped:       3,
		CertificatesFound: 1,
		DiscoveryComplete: true,
	})
	display.Stop(true)
	if err := display.Err(); err != nil {
		t.Fatal(err)
	}

	progressParts := []string{
		"certfinder dev\n",
		"Scan path:",
		"Workers: 4\n",
		"Options: max-bytes=65536 usage=server expiration=30d fail-expiring=14d output=text quiet=false\n",
		"Traversal: exclude=.git,cache extensions=.pem,.crt one-file-system=true follow-symlinks=true ignore-errors=true\n",
		"Scanning: 4/10 files scanned; 6 pending; 1 certificate found; discovering files...\n",
		"Scan complete: 10 files scanned, 3 stopped at max-bytes; 1 certificate found; 0 errors;",
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
